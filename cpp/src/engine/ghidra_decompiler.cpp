// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "ghidra_decompiler.h"
#include "ghidra_project.h"
#include "ghidra_cpp_init.h"
#include "libdecomp.hh"

#include <sstream>
#include <fstream>
#include <iostream>
#include <map>

namespace ghidra_standalone {

using namespace ghidra;

/// Copy-on-write LoadImage overlay that patches bytes without modifying the
/// underlying binary image.  Reads fall through to the original; only bytes
/// explicitly written via writeByte() are overridden.
class OverlayLoadImage : public LoadImage {
 public:
  explicit OverlayLoadImage(LoadImage* underlying)
      : LoadImage("overlay"), underlying_(underlying) {}

  void loadFill(uint1* ptr, int4 size, const Address& addr) override {
    underlying_->loadFill(ptr, size, addr);
    uint64_t start = addr.getOffset();
    for (int4 i = 0; i < size; i++) {
      auto it = patches_.find(start + static_cast<uint64_t>(i));
      if (it != patches_.end()) ptr[i] = it->second;
    }
  }

  string getArchType(void) const override { return underlying_->getArchType(); }
  void adjustVma(long adjust) override { underlying_->adjustVma(adjust); }

  void writeByte(uint64_t addr, uint8_t val) { patches_[addr] = val; }

  void writeBytes(uint64_t addr, const std::vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); i++)
      patches_[addr + i] = data[i];
  }

 private:
  LoadImage* underlying_;
  std::map<uint64_t, uint8_t> patches_;
};

struct Decompiler::Impl {
    Architecture *arch = nullptr;
    std::string lastError;
    bool usingEmbeddedSpecs = false;
    OverlayLoadImage *overlay = nullptr;  // owned by arch (replaces arch->loader)

    ~Impl() {
        if (arch != nullptr) {
            delete arch;
            arch = nullptr;
        }
    }

    /// Register C-standard type names as typedefs pointing to
    /// the Ghidra-native core types (e.g. "int" -> int4, etc.).
    /// This allows parse_type/parse_protopieces to accept C syntax.
    void registerCTypeAliases() {
        TypeFactory *tf = arch->types;
        struct Alias { const char *cname; const char *ghidra_name; };
        static const Alias aliases[] = {
            {"int",                "int4"},
            {"unsigned int",       "uint4"},
            {"short",              "int2"},
            {"unsigned short",     "uint2"},
            {"long",               "int4"},
            {"unsigned long",      "uint4"},
            {"long long",          "int8"},
            {"unsigned long long", "uint8"},
            {"signed char",        "int1"},
            {"unsigned char",      "uint1"},
        };
        for (const auto &a : aliases) {
            Datatype *base = tf->findByName(a.ghidra_name);
            if (base != nullptr && tf->findByName(a.cname) == nullptr) {
                tf->getTypedef(base, a.cname, 0, 0);
            }
        }
    }

    /// Fix the XML DOM so that every <scope> element contains a
    /// <symbollist> child.  The encoder conditionally omits <symbollist>
    /// when a scope has no named symbols, but the decoder unconditionally
    /// requires it—causing a DecoderError on load.  We recurse through
    /// the entire tree because function-local scopes can be nested
    /// arbitrarily deep inside <localdb>/<function>/<mapsym> elements.
    static void ensureSymbolLists(Element *el) {
        if (el->getName() == "scope") {
            bool hasSymbolList = false;
            const List &kids = el->getChildren();
            for (List::const_iterator it = kids.begin(); it != kids.end(); ++it) {
                if ((*it)->getName() == "symbollist") {
                    hasSymbolList = true;
                    break;
                }
            }
            if (!hasSymbolList) {
                Element *sl = new Element(el);
                sl->setName("symbollist");
                el->addChild(sl);
            }
        }
        // Recurse into children (use index loop because addChild may
        // have appended; we still want to visit original children only,
        // but the new <symbollist> has no children so it's safe either way).
        const List &kids = el->getChildren();
        for (size_t i = 0; i < kids.size(); i++)
            ensureSymbolLists(kids[i]);
    }

    /// Parse a C-style type string (e.g. "int", "char*", "uint4[10]")
    /// into a Ghidra Datatype. Returns nullptr and sets lastError on failure.
    Datatype *parseType(const std::string& type_str) {
        try {
            // The C grammar expects "type identifier" for doc_parameter_declaration.
            // Array brackets go after the identifier in C: "char x[64]", not "char[64] x".
            // Detect trailing [N] and move it after the placeholder name.
            std::string base = type_str;
            std::string arraySuffix;
            size_t bracket = type_str.find('[');
            if (bracket != std::string::npos) {
                base = type_str.substr(0, bracket);
                arraySuffix = type_str.substr(bracket);
                // Trim trailing whitespace from base
                while (!base.empty() && base.back() == ' ')
                    base.pop_back();
            }

            std::istringstream ss(base + " _p" + arraySuffix);
            string name;
            return parse_type(ss, name, arch);
        } catch (ParseError &err) {
            lastError = "Failed to parse type '" + type_str + "': " + err.explain;
            return nullptr;
        } catch (LowlevelError &err) {
            lastError = "Failed to parse type '" + type_str + "': " + err.explain;
            return nullptr;
        }
    }
};

Decompiler::Decompiler()
    : impl_(new Impl)
{
    impl_->usingEmbeddedSpecs = true;
    std::string spec_dir = ghidra_embedded::EmbeddedSpecManager::acquire();
    vector<string> extrapaths;
    startDecompilerLibrary(spec_dir.c_str(), extrapaths);
}

Decompiler::Decompiler(const std::string& ghidra_root)
    : impl_(new Impl)
{
    vector<string> extrapaths;
    startDecompilerLibrary(ghidra_root.c_str(), extrapaths);
}

Decompiler::~Decompiler()
{
    bool wasUsingEmbedded = impl_->usingEmbeddedSpecs;
    impl_.reset();
    shutdownDecompilerLibrary();
    if (wasUsingEmbedded) {
        ghidra_embedded::EmbeddedSpecManager::release();
    }
}

bool Decompiler::loadBinary(const std::string& filepath, const std::string& arch)
{
    if (impl_->arch != nullptr) {
        delete impl_->arch;
        impl_->arch = nullptr;
    }

    try {
        ArchitectureCapability *capa = ArchitectureCapability::findCapability(filepath);
        if (capa == nullptr) {
            impl_->lastError = "Unable to recognize image file: " + filepath;
            return false;
        }

        // Raw binary format requires an explicit architecture (e.g. "x86:LE:64:default")
        string target = arch;
        if (target.empty()) {
            if (capa->getName() == "raw") {
                impl_->lastError = "Raw binary requires an explicit architecture "
                    "(e.g. \"x86:LE:64:default\")";
                return false;
            }
            target = "default";
        }

        impl_->arch = capa->buildArchitecture(filepath, target, &std::cerr);

        DocumentStorage store;
        impl_->arch->init(store);
        impl_->registerCTypeAliases();

        // Read loader symbols if the format supports them (e.g. XML images)
        if (capa->getName() == "xml")
            impl_->arch->readLoaderSymbols("::");

    } catch (DecoderError &err) {
        impl_->lastError = err.explain;
        if (impl_->arch != nullptr) { delete impl_->arch; impl_->arch = nullptr; }
        return false;
    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        if (impl_->arch != nullptr) { delete impl_->arch; impl_->arch = nullptr; }
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        if (impl_->arch != nullptr) { delete impl_->arch; impl_->arch = nullptr; }
        return false;
    }

    impl_->lastError.clear();
    return true;
}

std::string Decompiler::decompileAt(uint64_t address)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return "";
    }

    try {
        AddrSpace *defaultSpace = impl_->arch->getDefaultCodeSpace();
        Address addr(defaultSpace, (uintb)address);

        // Create or find the function at this address
        string name;
        Scope *global = impl_->arch->symboltab->getGlobalScope();

        Funcdata *fd = global->queryFunction(addr);
        if (fd == nullptr) {
            impl_->arch->nameFunction(addr, name);
            fd = global->addFunction(addr, name)->getFunction();
        }

        // Follow control flow
        {
            Address baddr(defaultSpace, 0);
            Address eaddr(defaultSpace, defaultSpace->getHighest());
            fd->followFlow(baddr, eaddr);
        }

        // Run decompilation
        impl_->arch->allacts.getCurrent()->reset(*fd);
        int4 res = impl_->arch->allacts.getCurrent()->perform(*fd);
        if (res < 0) {
            impl_->lastError = "Decompilation did not complete";
            impl_->arch->clearAnalysis(fd);
            return "";
        }

        // Capture C output to string
        std::ostringstream oss;
        impl_->arch->print->setOutputStream(&oss);
        impl_->arch->print->docFunction(fd);

        // Clean up analysis for this function
        impl_->arch->clearAnalysis(fd);

        impl_->lastError.clear();
        return oss.str();

    } catch (RecovError &err) {
        impl_->lastError = err.explain;
        return "";
    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return "";
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return "";
    }
}

std::string Decompiler::getError() const
{
    return impl_->lastError;
}

// ---------------------------------------------------------------------------
// Type Creation
// ---------------------------------------------------------------------------

bool Decompiler::defineStruct(const std::string& name, const std::vector<FieldDef>& fields)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return false;
    }

    try {
        TypeFactory *types = impl_->arch->types;

        // If a type with this name already exists and is complete, destroy it
        // so we can recreate it (setFields only works on incomplete types).
        Datatype *existing = types->findByName(name);
        if (existing != nullptr && !existing->isIncomplete()) {
            types->destroyType(existing);
        }

        // Create an incomplete struct
        TypeStruct *st = types->getTypeStruct(name);

        // Build TypeField vector and compute total size
        vector<TypeField> fieldVec;
        int4 totalSize = 0;
        for (size_t i = 0; i < fields.size(); i++) {
            Datatype *ftype = impl_->parseType(fields[i].type_name);
            if (ftype == nullptr)
                return false;  // lastError already set by parseType
            fieldVec.push_back(TypeField((int4)i, fields[i].offset, fields[i].name, ftype));
            int4 fieldEnd = fields[i].offset + ftype->getSize();
            if (fieldEnd > totalSize)
                totalSize = fieldEnd;
        }

        // Complete the struct definition
        vector<TypeBitField> bitVec;
        types->assignRawFields(st, fieldVec, bitVec);

        impl_->lastError.clear();
        return true;

    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

bool Decompiler::defineEnum(const std::string& name, const std::vector<EnumValue>& values)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return false;
    }

    try {
        TypeFactory *types = impl_->arch->types;

        // If an enum with this name already exists and is complete, destroy it
        // so we can recreate it cleanly.
        Datatype *existing = types->findByName(name);
        if (existing != nullptr && !existing->isIncomplete()) {
            types->destroyType(existing);
        }

        // Create an incomplete enum
        TypeEnum *te = types->getTypeEnum(name);

        // Build the name map
        map<uintb, string> nmap;
        for (const auto &v : values) {
            nmap[(uintb)v.value] = v.name;
        }

        // Set the enum values
        types->setEnumValues(nmap, te);

        impl_->lastError.clear();
        return true;

    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

// ---------------------------------------------------------------------------
// Symbol Management
// ---------------------------------------------------------------------------

bool Decompiler::nameFunction(uint64_t address, const std::string& name)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return false;
    }

    try {
        AddrSpace *defaultSpace = impl_->arch->getDefaultCodeSpace();
        Address addr(defaultSpace, (uintb)address);

        Scope *global = impl_->arch->symboltab->getGlobalScope();
        FunctionSymbol *sym = global->addFunction(addr, name);
        global->setAttribute(sym, Varnode::namelock);

        impl_->lastError.clear();
        return true;

    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

bool Decompiler::nameGlobal(uint64_t address, const std::string& name, const std::string& type_name)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return false;
    }

    try {
        Datatype *dt = impl_->parseType(type_name);
        if (dt == nullptr)
            return false;

        AddrSpace *defaultSpace = impl_->arch->getDefaultCodeSpace();
        Address addr(defaultSpace, (uintb)address);

        Scope *global = impl_->arch->symboltab->getGlobalScope();
        uint4 flags = Varnode::namelock | Varnode::typelock;
        flags |= impl_->arch->symboltab->getProperty(addr);

        SymbolEntry *entry = global->addSymbol(name, dt, addr, Address());
        Symbol *sym = entry->getSymbol();
        global->setAttribute(sym, flags);

        impl_->lastError.clear();
        return true;

    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

bool Decompiler::renameSymbol(const std::string& old_name, const std::string& new_name)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return false;
    }

    try {
        Scope *global = impl_->arch->symboltab->getGlobalScope();
        vector<Symbol *> symList;
        global->queryByName(old_name, symList);

        if (symList.empty()) {
            impl_->lastError = "No symbol named: " + old_name;
            return false;
        }
        if (symList.size() > 1) {
            impl_->lastError = "More than one symbol named: " + old_name;
            return false;
        }

        Symbol *sym = symList[0];
        sym->getScope()->renameSymbol(sym, new_name);
        sym->getScope()->setAttribute(sym, Varnode::namelock | Varnode::typelock);

        impl_->lastError.clear();
        return true;

    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

bool Decompiler::retypeSymbol(const std::string& symbol_name, const std::string& type_name)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return false;
    }

    try {
        Datatype *ct = impl_->parseType(type_name);
        if (ct == nullptr)
            return false;

        Scope *global = impl_->arch->symboltab->getGlobalScope();
        vector<Symbol *> symList;
        global->queryByName(symbol_name, symList);

        if (symList.empty()) {
            impl_->lastError = "No symbol named: " + symbol_name;
            return false;
        }
        if (symList.size() > 1) {
            impl_->lastError = "More than one symbol named: " + symbol_name;
            return false;
        }

        Symbol *sym = symList[0];
        sym->getScope()->retypeSymbol(sym, ct);
        sym->getScope()->setAttribute(sym, Varnode::typelock);

        impl_->lastError.clear();
        return true;

    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

bool Decompiler::addGlobalRange(uint64_t address, uint64_t size)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return false;
    }

    try {
        AddrSpace *defaultSpace = impl_->arch->getDefaultCodeSpace();
        Scope *global = impl_->arch->symboltab->getGlobalScope();
        impl_->arch->symboltab->addRange(global, defaultSpace, (uintb)address, (uintb)(address + size - 1));

        impl_->lastError.clear();
        return true;

    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

// ---------------------------------------------------------------------------
// Function Prototypes
// ---------------------------------------------------------------------------

bool Decompiler::setPrototype(uint64_t address, const std::string& prototype)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return false;
    }

    try {
        // Parse the prototype string into PrototypePieces.
        // The C grammar requires a trailing semicolon for declarations.
        PrototypePieces pieces;
        std::istringstream ss(prototype + ";");
        parse_protopieces(pieces, ss, impl_->arch);

        // Ensure the function exists at this address
        AddrSpace *defaultSpace = impl_->arch->getDefaultCodeSpace();
        Address addr(defaultSpace, (uintb)address);

        Scope *global = impl_->arch->symboltab->getGlobalScope();
        Funcdata *fd = global->queryFunction(addr);
        if (fd == nullptr) {
            // Create the function if it doesn't exist yet
            FunctionSymbol *sym = global->addFunction(addr, pieces.name);
            fd = sym->getFunction();
        }

        // Apply the prototype
        fd->getFuncProto().setPieces(pieces);

        impl_->lastError.clear();
        return true;

    } catch (ParseError &err) {
        impl_->lastError = "Failed to parse prototype: " + err.explain;
        return false;
    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

// ---------------------------------------------------------------------------
// Project Loading
// ---------------------------------------------------------------------------

bool Decompiler::loadProject(const std::string& gpr_path, const std::string& binary_override)
{
    ghidra_db::GhidraProject proj;
    if (!proj.open(gpr_path)) {
        impl_->lastError = "Failed to open project: " + proj.getError();
        return false;
    }

    ghidra_db::ProjectData data = proj.extract();
    if (data.info.language_id.empty()) {
        impl_->lastError = "No language ID found in project. " + proj.getError();
        return false;
    }

    // Determine which binary to load
    std::string binary_path = binary_override.empty() ? data.info.exe_path : binary_override;
    if (binary_path.empty()) {
        impl_->lastError = "No executable path found in project (and no override provided)";
        return false;
    }

    if (!loadBinary(binary_path, data.info.language_id)) {
        return false; // lastError already set
    }

    // Apply function names from the project (skip empty names — auto-generated)
    int named = 0;
    for (auto& func : data.functions) {
        if (!func.name.empty() && nameFunction(func.address, func.name))
            ++named;
    }

    impl_->lastError.clear();
    return true;
}

// ---------------------------------------------------------------------------
// State Persistence
// ---------------------------------------------------------------------------

bool Decompiler::saveState(const std::string& filepath)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return false;
    }

    try {
        std::ofstream fs(filepath);
        if (!fs) {
            impl_->lastError = "Unable to open file for writing: " + filepath;
            return false;
        }

        XmlEncode encoder(fs);
        impl_->arch->encode(encoder);
        fs.close();

        impl_->lastError.clear();
        return true;

    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

bool Decompiler::loadState(const std::string& filepath)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded (load a binary first, then restore state)";
        return false;
    }

    try {
        DocumentStorage store;
        Document *doc = store.openDocument(filepath);
        store.registerTag(doc->getRoot());

        // The save file has an architecture-specific root element (e.g.
        // <raw_savefile>) wrapping a <save_state> child.  We need to find
        // and register the <save_state> element so getTag can locate it.
        Element *root = const_cast<Element *>(doc->getRoot());
        const List &children = root->getChildren();
        for (List::const_iterator it = children.begin(); it != children.end(); ++it) {
            if ((*it)->getName() == ELEM_SAVE_STATE.getName()) {
                store.registerTag(*it);
                break;
            }
        }

        // Fix up <scope> elements that are missing <symbollist> children.
        // The encoder conditionally omits empty symbol lists but the
        // decoder unconditionally requires them.
        Impl::ensureSymbolLists(root);

        // Selectively restore only types and symbols from the save file.
        // We cannot call Architecture::restoreXml() because it also decodes
        // context points and other elements that try to re-register address
        // spaces, causing "Space X was assigned as id duplicating" errors
        // on an already-initialized architecture.
        const Element *el = store.getTag(ELEM_SAVE_STATE.getName());
        if (el == nullptr)
            throw LowlevelError("Could not find save_state tag");

        XmlDecode decoder(impl_->arch, el);
        uint4 elemId = decoder.openElement(ELEM_SAVE_STATE);

        // Skip top-level attributes
        while (decoder.getNextAttributeId() != 0) {}

        // Selectively decode child elements
        for (;;) {
            uint4 subId = decoder.peekElement();
            if (subId == 0) break;

            if (subId == ELEM_TYPEGRP)
                impl_->arch->types->decode(decoder);
            else if (subId == ELEM_DB)
                impl_->arch->symboltab->decode(decoder);
            else
                decoder.skipElement();
        }

        decoder.closeElement(elemId);
        impl_->registerCTypeAliases();

        // Post-decode fixup for restored symbols.
        //
        // 1. The <functionshell> decoder reads 'name' from ATTRIB_NAME but
        //    never sets 'displayName' (no label attribute is encoded for
        //    shells), leaving it empty.  When getFunction() later creates
        //    Funcdata, it inherits the empty displayName.  The printer uses
        //    getDisplayName(), so the function name silently disappears from
        //    output.  Fix: renameSymbol(sym, name) sets both name and
        //    displayName.
        //
        // 2. The decoders do not always set namelock, causing function names
        //    to be discarded during decompilation.  Fix: force namelock on
        //    any symbol with a non-empty name.
        Scope *global = impl_->arch->symboltab->getGlobalScope();
        MapIterator mit = global->begin();
        MapIterator mend = global->end();
        while (mit != mend) {
            Symbol *sym = (*mit)->getSymbol();
            if (!sym->getName().empty() && sym->getDisplayName().empty())
                global->renameSymbol(sym, sym->getName());
            if (!sym->isNameLocked() && !sym->getName().empty())
                global->setAttribute(sym, Varnode::namelock);
            ++mit;
        }

        impl_->lastError.clear();
        return true;

    } catch (DecoderError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

// ---------------------------------------------------------------------------
// Output Control
// ---------------------------------------------------------------------------

bool Decompiler::setPrintLanguage(const std::string& language)
{
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return false;
    }

    try {
        impl_->arch->setPrintLanguage(language);

        impl_->lastError.clear();
        return true;

    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        return false;
    }
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

std::vector<FunctionInfo> Decompiler::listFunctions()
{
    std::vector<FunctionInfo> result;
    if (impl_->arch == nullptr) {
        impl_->lastError = "No binary loaded";
        return result;
    }

    try {
        Scope *global = impl_->arch->symboltab->getGlobalScope();
        MapIterator it = global->begin();
        MapIterator end = global->end();
        while (it != end) {
            const SymbolEntry *entry = *it;
            const Symbol *sym = entry->getSymbol();
            const FunctionSymbol *fsym = dynamic_cast<const FunctionSymbol *>(sym);
            if (fsym != nullptr) {
                FunctionInfo fi;
                fi.name = fsym->getName();
                fi.address = entry->getAddr().getOffset();
                fi.size = fsym->getBytesConsumed();
                result.push_back(std::move(fi));
            }
            ++it;
        }
        impl_->lastError.clear();
    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
    }

    return result;
}

// ---------------------------------------------------------------------------
// Memory Writes
// ---------------------------------------------------------------------------

void Decompiler::writeBytes(uint64_t address, const std::vector<uint8_t>& data)
{
    if (impl_->arch == nullptr || data.empty()) return;

    // Lazily install the overlay on first write
    if (impl_->overlay == nullptr) {
        impl_->overlay = new OverlayLoadImage(impl_->arch->loader);
        impl_->arch->loader = impl_->overlay;
    }

    impl_->overlay->writeBytes(address, data);
}

void* Decompiler::getArchitecturePointer()
{
    return static_cast<void*>(impl_->arch);
}

} // namespace ghidra_standalone
