// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "ghidra_decompiler.h"
#include "ghidra_project.h"
#include "ghidradb/memory_image.h"
#include "ghidra_cpp_init.h"
#include "libdecomp.hh"
#include "../print_stream_guard.hpp"
#include "../symbol_entry.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <sstream>
#include <fstream>
#include <iostream>
#include <map>
#include <new>

namespace ghidra_standalone {

using namespace ghidra;

/// Copy-on-write LoadImage overlay that patches bytes without modifying the
/// underlying binary image.  Reads fall through to the original; only bytes
/// explicitly written via writeByte() are overridden.
class OverlayLoadImage : public LoadImage {
 public:
  explicit OverlayLoadImage(LoadImage* underlying)
      : LoadImage("overlay"), underlying_(underlying) {}

  // Takes ownership of the underlying loader. Ghidra's contract is that
  // Architecture::loader is fully owned and freed by ~Architecture; once this
  // overlay is installed as arch->loader, deleting the overlay must also free the
  // original loader it wrapped, else it leaks.
  ~OverlayLoadImage() override { delete underlying_; }

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
    std::string bootstrapTempPath;        // scratch file used only to build a raw arch

    // Tear down the Architecture and null the cached overlay TOGETHER.
    // ~Architecture deletes arch->loader (== overlay once writeBytes installs it,
    // architecture.cc:215-216), so `overlay` dangles the instant `arch` is freed.
    // Every teardown path must go through here, or a later writeBytes() null-check
    // (overlay != nullptr) would deref freed memory (use-after-free).
    void destroyArch() {
        delete arch;
        arch = nullptr;
        overlay = nullptr;
        // The bootstrap loader (held open by arch until now) is gone; drop its
        // scratch file. Safe to remove after the arch — and thus the loader's
        // file handle — is destroyed (matters on Windows, which can't unlink an
        // open file).
        if (!bootstrapTempPath.empty()) {
            std::error_code ec;
            std::filesystem::remove(bootstrapTempPath, ec);
            bootstrapTempPath.clear();
        }
    }

    ~Impl() {
        destroyArch();
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

static void rebase_loader_vma(LoadImage* loader, uint64_t base);
static std::string write_scratch_image(const std::vector<uint8_t>& bytes);

enum class PeImageStatus {
    NotPe,
    Ready,
    Error,
};

static PeImageStatus prepare_pe_image(const std::string& filepath,
                                      std::vector<uint8_t>& mapped,
                                      uint64_t& image_base,
                                      std::string& error);

bool Decompiler::loadBinary(const std::string& filepath, const std::string& arch,
                            uint64_t base_address, const std::string& format)
{
    impl_->destroyArch();

    // Guard: a missing/unreadable binary makes RawBinaryArchitecture::buildLoader
    // throw, and its error path double-frees the RawLoadImage (SEGV during stack
    // unwind). Fail cleanly BEFORE building the architecture rather than crash.
    if (!std::ifstream(filepath, std::ios::binary).good()) {
        impl_->lastError = "Cannot open binary file: " + filepath;
        return false;
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

        const bool uses_raw_loader = capa->getName() == "raw";
        std::string load_path = filepath;
        uint64_t effective_base = base_address;

        // Windows and other BFD-free builds select RawLoadImage even for a PE.
        // A raw file-offset view is not a process image: section raw offsets and
        // RVAs commonly differ. Flatten a recognized PE into its in-memory RVA
        // layout before constructing the architecture. Project loading passes
        // format="raw" because its scratch image is already flattened.
        if (uses_raw_loader && format != "raw") {
            std::vector<uint8_t> mapped;
            uint64_t pe_image_base = 0;
            std::string map_error;
            PeImageStatus pe_status =
                prepare_pe_image(filepath, mapped, pe_image_base, map_error);
            if (pe_status == PeImageStatus::Error) {
                impl_->lastError = map_error;
                return false;
            }
            if (pe_status == PeImageStatus::Ready) {
                load_path = write_scratch_image(mapped);
                if (load_path.empty()) {
                    impl_->lastError =
                        "Failed to create scratch image for PE load";
                    return false;
                }
                impl_->bootstrapTempPath = load_path;
                if (effective_base == 0)
                    effective_base = pe_image_base;
            }
        }

        impl_->arch = capa->buildArchitecture(load_path, target, &std::cerr);

        DocumentStorage store;
        impl_->arch->init(store);
        impl_->registerCTypeAliases();

        // RawLoadImage has no format metadata from which to recover an image
        // base. Honor OpenProgramRequest.base_address so PE/Mach-O callers on
        // builds without BFD address the file at its real virtual addresses.
        // Structured loaders already map their own VMAs and must not be shifted.
        if (uses_raw_loader && effective_base != 0)
            rebase_loader_vma(impl_->arch->loader, effective_base);

        // Read loader symbols if the format supports them (e.g. XML images)
        if (capa->getName() == "xml")
            impl_->arch->readLoaderSymbols();

    } catch (DecoderError &err) {
        impl_->lastError = err.explain;
        impl_->destroyArch();
        return false;
    } catch (LowlevelError &err) {
        impl_->lastError = err.explain;
        impl_->destroyArch();
        return false;
    } catch (std::exception &err) {
        impl_->lastError = err.what();
        impl_->destroyArch();
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

        // Capture C output to string. The RAII guard resets the print stream off
        // `oss` before it is destroyed, so arch->print is never left dangling.
        std::ostringstream oss;
        {
          libghidra::detail::ScopedPrintStream print_guard(impl_->arch->print,
                                                           oss);
          impl_->arch->print->docFunction(fd);
        }

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

// Shift a raw loader's vma up to `base`. adjustVma is additive, so we apply it in
// <= 1 GiB steps: Ghidra's adjustVma parameter is `long`, which is 32-bit on
// Windows/LLP64, so a single 0x140000000 argument would truncate there. Each step
// fits a signed 32-bit `long`, and the increments accumulate to `base`.
static void rebase_loader_vma(LoadImage* loader, uint64_t base)
{
    const long kStep = 0x40000000L;  // 1 GiB, safely within int32
    while (base > 0) {
        long step = base > static_cast<uint64_t>(kStep)
                        ? kStep : static_cast<long>(base);
        loader->adjustVma(step);
        base -= static_cast<uint64_t>(step);
    }
}

// Write `bytes` to a unique scratch file and return its path (""on failure).
// The Ghidra decompiler builds a raw Architecture only from a file on disk
// (RawLoadImage::open reads it lazily), and the Sleigh translator captures that
// loader at init — so loadProject can't swap the loader afterwards; it must hand
// the arch a file that already holds the correct bytes. BFD is not compiled here,
// so a leading "MZ" still selects the "raw" capability (as the real .exe does).
static std::string write_scratch_image(const std::vector<uint8_t>& bytes)
{
    static std::atomic<uint64_t> counter{0};
    std::error_code ec;
    std::filesystem::path dir = std::filesystem::temp_directory_path(ec);
    if (ec) return "";
    std::filesystem::path p =
        dir / ("libghidra_projimg_" + std::to_string(counter.fetch_add(1)) + "_" +
               std::to_string(reinterpret_cast<uintptr_t>(&counter)) + ".bin");
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) return "";
    if (!bytes.empty())
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
    if (!f) return "";
    f.close();
    return p.string();
}

template <typename T>
static bool read_pe_le(const std::vector<uint8_t>& bytes, size_t offset, T& out)
{
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset)
        return false;
    out = 0;
    for (size_t i = 0; i < sizeof(T); ++i)
        out |= static_cast<T>(bytes[offset + i]) << (i * 8);
    return true;
}

static PeImageStatus prepare_pe_image(const std::string& filepath,
                                      std::vector<uint8_t>& mapped,
                                      uint64_t& image_base,
                                      std::string& error)
{
    std::ifstream input(filepath, std::ios::binary | std::ios::ate);
    if (!input) {
        error = "Cannot open PE image: " + filepath;
        return PeImageStatus::Error;
    }

    const std::streamoff end = input.tellg();
    if (end < 0) {
        error = "Cannot determine PE image size: " + filepath;
        return PeImageStatus::Error;
    }

    std::vector<uint8_t> file(static_cast<size_t>(end));
    input.seekg(0);
    if (!file.empty()) {
        input.read(reinterpret_cast<char*>(file.data()),
                   static_cast<std::streamsize>(file.size()));
        if (!input) {
            error = "Cannot read PE image: " + filepath;
            return PeImageStatus::Error;
        }
    }

    if (file.size() < 2 || file[0] != 'M' || file[1] != 'Z')
        return PeImageStatus::NotPe;
    if (file.size() < 0x40) {
        error = "Malformed PE image: truncated DOS header";
        return PeImageStatus::Error;
    }

    uint32_t pe_offset = 0;
    if (!read_pe_le(file, 0x3c, pe_offset) ||
        pe_offset > file.size() || 24 > file.size() - pe_offset) {
        error = "Malformed PE image: invalid PE header offset";
        return PeImageStatus::Error;
    }
    if (file[pe_offset] != 'P' || file[pe_offset + 1] != 'E' ||
        file[pe_offset + 2] != 0 || file[pe_offset + 3] != 0) {
        // Some raw firmware begins with MZ bytes but is not a PE.
        return PeImageStatus::NotPe;
    }

    uint16_t section_count = 0;
    uint16_t optional_size = 0;
    if (!read_pe_le(file, pe_offset + 6, section_count) ||
        !read_pe_le(file, pe_offset + 20, optional_size)) {
        error = "Malformed PE image: truncated COFF header";
        return PeImageStatus::Error;
    }

    const size_t optional_offset = static_cast<size_t>(pe_offset) + 24;
    if (optional_offset > file.size() ||
        optional_size > file.size() - optional_offset ||
        optional_size < 64) {
        error = "Malformed PE image: truncated optional header";
        return PeImageStatus::Error;
    }

    uint16_t magic = 0;
    uint32_t image_size = 0;
    uint32_t headers_size = 0;
    if (!read_pe_le(file, optional_offset, magic) ||
        !read_pe_le(file, optional_offset + 56, image_size) ||
        !read_pe_le(file, optional_offset + 60, headers_size)) {
        error = "Malformed PE image: incomplete optional header";
        return PeImageStatus::Error;
    }

    if (magic == 0x10b) {
        uint32_t base32 = 0;
        if (!read_pe_le(file, optional_offset + 28, base32)) {
            error = "Malformed PE32 image: missing image base";
            return PeImageStatus::Error;
        }
        image_base = base32;
    } else if (magic == 0x20b) {
        if (!read_pe_le(file, optional_offset + 24, image_base)) {
            error = "Malformed PE32+ image: missing image base";
            return PeImageStatus::Error;
        }
    } else {
        error = "Malformed PE image: unsupported optional-header magic";
        return PeImageStatus::Error;
    }

    constexpr uint64_t kMaxMappedImageBytes = uint64_t{4} << 30;
    if (image_size == 0 || image_size > kMaxMappedImageBytes) {
        error = "PE image size is zero or exceeds the 4 GiB safety limit";
        return PeImageStatus::Error;
    }

    const size_t section_table = optional_offset + optional_size;
    const uint64_t section_bytes = static_cast<uint64_t>(section_count) * 40;
    if (section_table > file.size() ||
        section_bytes > file.size() - section_table) {
        error = "Malformed PE image: truncated section table";
        return PeImageStatus::Error;
    }

    try {
        mapped.assign(image_size, 0);
    } catch (const std::bad_alloc&) {
        error = "Unable to allocate PE image mapping";
        return PeImageStatus::Error;
    }

    const size_t header_copy =
        std::min({static_cast<size_t>(headers_size), file.size(), mapped.size()});
    std::copy_n(file.begin(), header_copy, mapped.begin());

    for (uint16_t i = 0; i < section_count; ++i) {
        const size_t section = section_table + static_cast<size_t>(i) * 40;
        uint32_t virtual_address = 0;
        uint32_t raw_size = 0;
        uint32_t raw_offset = 0;
        if (!read_pe_le(file, section + 12, virtual_address) ||
            !read_pe_le(file, section + 16, raw_size) ||
            !read_pe_le(file, section + 20, raw_offset)) {
            error = "Malformed PE image: incomplete section header";
            return PeImageStatus::Error;
        }
        if (raw_size == 0)
            continue;
        if (raw_offset >= file.size() ||
            raw_size > file.size() - static_cast<size_t>(raw_offset) ||
            virtual_address >= mapped.size() ||
            raw_size > mapped.size() - static_cast<size_t>(virtual_address)) {
            error = "Malformed PE image: section lies outside the file or image";
            return PeImageStatus::Error;
        }
        std::copy_n(file.begin() + raw_offset, raw_size,
                    mapped.begin() + virtual_address);
    }

    return PeImageStatus::Ready;
}

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

    // Preferred path: reconstruct the loaded memory image from the project db and
    // serve bytes at their real VAs. This needs no external binary and is correct
    // for a PE (whose file layout != memory layout), unlike raw-loading the .exe.
    ghidra_db::MemoryImage img;
    if (proj.loadMemoryImage(img)) {
        // Flatten the reconstructed image into a VA-relative buffer (offset 0 ==
        // image base; uninitialized gaps zero-filled), write it to a scratch file,
        // raw-load it, and shift the loader's vma up to the image base. Then
        // loadFill(0x140001000) reads scratch[0x1000] = the real .text bytes.
        const uint64_t base = img.imageBase();
        const uint64_t span = img.imageEnd() - base;
        // The flatten-to-scratch strategy materializes the whole [base, end) span
        // as one buffer, so a sparse / high-VA layout (a huge end - base) would
        // demand an unbounded allocation. Reject it rather than attempt a
        // multi-GB+ allocation (any realistic program image is far under this).
        constexpr uint64_t kMaxFlatImageBytes = uint64_t(4) << 30;  // 4 GiB
        if (span > kMaxFlatImageBytes) {
            impl_->lastError =
                "Offline project image span too large to flatten (" +
                std::to_string(span) + " bytes); sparse/high-VA layout unsupported";
            return false;
        }
        std::vector<uint8_t> flat(span);
        img.readBytes(base, flat.data(), span);

        std::string temp = write_scratch_image(flat);
        if (temp.empty()) {
            impl_->lastError = "Failed to create scratch image for offline project load";
            return false;
        }
        // Build a raw arch from the scratch file (destroyArch() inside clears any
        // prior bootstrap temp), then record ours so teardown removes it.
        if (!loadBinary(temp, data.info.language_id, 0, "raw")) {
            std::error_code ec;
            std::filesystem::remove(temp, ec);
            return false;  // lastError set by loadBinary
        }
        impl_->bootstrapTempPath = temp;
        // Rebase the raw loader onto the image base. For RawLoadImage this sets
        // vma += base, so every subsequent loadFill maps addr -> scratch[addr -
        // base]. The Sleigh translator shares this same loader object, so its
        // instruction reads see the shift too.
        rebase_loader_vma(impl_->arch->loader, base);
    } else {
        // Fallback: the project carries no File Bytes (older/raw import). Raw-load
        // the external binary (override wins over the stored executable path).
        std::string binary_path = binary_override.empty() ? data.info.exe_path : binary_override;
        if (binary_path.empty()) {
            impl_->lastError = "Project has no image bytes (" + proj.getError() +
                               ") and no executable path/override to fall back on";
            return false;
        }
        if (!loadBinary(binary_path, data.info.language_id)) {
            return false; // lastError already set
        }
    }

    // Apply function names from the project (skip empty names — auto-generated)
    int named = 0;
    for (auto& func : data.functions) {
        if (!func.name.empty() && nameFunction(func.address, func.name))
            ++named;
    }
    (void)named;

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
            // Dynamic (hash-identified) storage has no address to report.
            const auto *mapped = libghidra::detail::as_map_entry(entry);
            if (fsym != nullptr && mapped != nullptr) {
                FunctionInfo fi;
                fi.name = fsym->getName();
                fi.address = mapped->getAddr().getOffset();
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
