// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "ghidra_decompiler.h"
#include "ghidra_project.h"
#include "ghidradb/memory_image.h"
#include "ghidra_cpp_init.h"
#include "project_types.h"
#include "host_print.h"
#include "core_types.h"
#include "libdecomp.hh"
#include "function_state.h"
#include "program_listing.h"
#include "../symbol_entry.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <sstream>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <new>
#include <set>

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

/// The project image's bytes that lie outside the flattened scratch image: a
/// block held entirely in BUFFER sub-blocks, such as a PE's `tdb` far above the
/// image. Reads inside one of these runs come from it; every other read goes to
/// the scratch loader, which still throws past its end. The decompiler reads
/// data through Architecture::loader, so a read-only TEB pointer (`Self`) folds
/// to its value as it does on the host.
class ProjectRunsLoadImage : public LoadImage {
 public:
  ProjectRunsLoadImage(LoadImage* underlying, std::vector<ghidra_db::MemoryImage::Run> runs)
      : LoadImage("project"), underlying_(underlying), runs_(std::move(runs)) {}
  ~ProjectRunsLoadImage() override { delete underlying_; }

  void loadFill(uint1* ptr, int4 size, const Address& addr) override {
    const uint64_t start = addr.getOffset();
    for (const auto& r : runs_) {
      if (start >= r.va && size >= 0 && start - r.va + static_cast<uint64_t>(size) <= r.bytes.size()) {
        std::memcpy(ptr, r.bytes.data() + (start - r.va), static_cast<size_t>(size));
        return;
      }
    }
    underlying_->loadFill(ptr, size, addr);
  }

  string getArchType(void) const override { return underlying_->getArchType(); }
  void adjustVma(long adjust) override { underlying_->adjustVma(adjust); }

 private:
  LoadImage* underlying_;
  std::vector<ghidra_db::MemoryImage::Run> runs_;
};

// Ghidra's decompiler library keeps process-wide state that building or tearing
// down an Architecture touches: startDecompilerLibrary's capability and
// attribute registries, the Sleigh spec path list and language descriptions,
// shutdownDecompilerLibrary. None of it is locked, so two Decompilers set up in
// two threads at once corrupted it -- a crash, or a livelock spinning in a
// corrupted container (measured: 2 threads never finished a round; with this
// lock 4 threads x 5 rounds all load and decompile).
// Every setup and teardown step takes this lock; decompiling with a built
// Architecture does not, so a DecompilerPool still decompiles in parallel.
static std::recursive_mutex& engine_setup_mutex()
{
    static std::recursive_mutex mutex;
    return mutex;
}

// One token of a C declaration (ParseDeclarations).
struct CToken {
    std::string text;
};

struct Decompiler::Impl {
    Architecture *arch = nullptr;
    std::string lastError;
    EngineError lastKind = EngineError::kNone;
    bool usingEmbeddedSpecs = false;
    OverlayLoadImage *overlay = nullptr;  // owned by arch (replaces arch->loader)
    std::string bootstrapTempPath;        // scratch file used only to build a raw arch
    // Leaf entry points from the project's reference index (loadProject only).
    std::optional<std::vector<uint64_t>> projectLeaves;
    // Ghidra category of each program data type loadProject materialised.
    TypeCategories typeCategories;
    // Entry points of the project's thunk functions (loadProject only).
    std::set<uint64_t> projectThunks;
    // Saved prototypes and locals, replayed before every decompile.
    ProjectFunctionState functionState;
    // Import-slot addresses holding an external function stub (loadProject).
    std::set<uint64_t> externalStubs;
    // The program database loadProject read: its function entries, body ranges
    // (first -> {last, entry}) and listing instruction starts.
    bool projectLoaded = false;
    std::set<uint64_t> projectEntries;
    std::map<uint64_t, std::pair<uint64_t, uint64_t>> projectBodies;
    bool hasInstructionIndex = false;
    std::vector<uint64_t> instructionStarts;
    // The program's memory map, in address order (see memoryBlocks()).
    std::vector<MemoryBlockInfo> blocks;
    // Labels, defined data, comments, bookmarks and function tags.
    ProgramListing listing;
    // The program's built-in data types by name (Ghidra id), and the
    // composites that pack their fields (by id).
    std::map<std::string, uint64_t> builtinTypeIds;
    // The packing of every packed composite (by id): 0 default, > 0 explicit.
    // A composite missing here has packing disabled.
    std::map<uint64_t, int> packing;

    bool fail(EngineError kind, std::string message) {
        lastKind = kind;
        lastError = std::move(message);
        return false;
    }
    void setError(EngineError kind, std::string message) {
        lastKind = kind;
        lastError = std::move(message);
    }
    void clearError() {
        lastKind = EngineError::kNone;
        lastError.clear();
    }

    // ParseDeclarations (see parseDeclarations): one parse's state.
    struct ParseState {
        int counter = 1;        // CParser.cnt: struct/union keywords, anonymous enums
        int func_counter = 1;   // CParser.func_cnt: function pointer members
        int temp_counter = 0;
        std::vector<Datatype *> temps;          // bodies parsed under a name of their own
        std::set<Datatype *> composites;        // every composite the parse defined
        ReplaceComposite replace;
    };
    void parseDeclaration(const std::string& decl, ParseState& state);
    std::vector<CToken> resolveSpecifiers(const std::vector<CToken>& t, size_t first,
                                                 size_t last, const std::string& typedefName,
                                                 ParseState& state);
    void defineComposite(bool is_union, const std::string& tag, const std::vector<CToken>& body,
                         ParseState& state);
    void defineEnumeration(const std::string& tag, const std::vector<CToken>& t, size_t first,
                           size_t last, ParseState& state);
    std::string baseTypeName(const std::vector<std::string>& words) const;
    Datatype *namedFunctionPointer(Datatype *dt, const std::string& name);
    uint64_t parseTypeId(const std::string& path) const;

    // Tear down the Architecture and null the cached overlay TOGETHER.
    // ~Architecture deletes arch->loader (== overlay once writeBytes installs it,
    // architecture.cc:215-216), so `overlay` dangles the instant `arch` is freed.
    // Every teardown path must go through here, or a later writeBytes() null-check
    // (overlay != nullptr) would deref freed memory (use-after-free).
    void destroyArch() {
        std::lock_guard<std::recursive_mutex> setup(engine_setup_mutex());
        listing.reset(nullptr, {});  // before the arch its symbols live in
        delete arch;
        arch = nullptr;
        overlay = nullptr;
        projectLeaves.reset();
        typeCategories.clear();
        builtinTypeIds.clear();
        packing.clear();
        projectThunks.clear();
        functionState = ProjectFunctionState{};
        externalStubs.clear();
        projectLoaded = false;
        projectEntries.clear();
        projectBodies.clear();
        hasInstructionIndex = false;
        instructionStarts.clear();
        blocks.clear();
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

    // The entry of the function at `address`, or whose project body holds it.
    std::optional<uint64_t> functionContaining(uint64_t address) const;
    // A (program) function symbol starts at `address`: not an import-slot stub.
    bool functionAt(uint64_t address) const;

    // A fresh listing over the current architecture.
    void resetListing() {
        ProgramListing::Hooks hooks;
        hooks.function_containing = [this](uint64_t a) { return functionContaining(a); };
        hooks.function_at = [this](uint64_t a) { return functionAt(a); };
        hooks.external_ref = [this](uint64_t a) { return externalStubs.count(a) != 0; };
        hooks.instruction_at = [this](uint64_t a) {
            return projectLoaded && hasInstructionIndex &&
                   std::binary_search(instructionStarts.begin(), instructionStarts.end(), a);
        };
        hooks.function_body = [this](uint64_t entry) {
            std::vector<std::pair<uint64_t, uint64_t>> out;
            for (const auto& [first, range] : projectBodies)
                if (range.second == entry) out.emplace_back(first, range.first);
            return out;
        };
        listing.reset(arch, std::move(hooks));
    }

    // What the host's decompiler learns about memory from the program (a hole's
    // MappedEntry.getMutabilityOfAddress, and DecompileOptions "readonly on"):
    // a read-only block is constant unless the program writes there, a
    // volatile block volatile.
    void applyMemoryProperties(const std::set<uint64_t>& written) {
        arch->readonlypropagate = true;
        AddrSpace* code = arch->getDefaultCodeSpace();
        const uintb highest = code->getHighest();
        for (const MemoryBlockInfo& b : blocks) {
            if (b.start > highest) continue;
            const Range range(code, b.start, std::min<uintb>(b.end, highest));
            if (b.is_volatile) {
                arch->symboltab->setPropertyRange(Varnode::volatil, range);
            } else if (!b.write) {
                arch->symboltab->setPropertyRange(Varnode::readonly, range);
                for (auto it = written.lower_bound(b.start); it != written.end() && *it <= b.end; ++it)
                    arch->symboltab->clearPropertyRange(Varnode::readonly, Range(code, *it, *it));
            }
        }
        listing.setMemory(blocks, written);
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

    /// A type named by Ghidra path ("/category/Name") as the host names it,
    /// else a C-style type string (e.g. "int", "char*", "uint4[10]") parsed
    /// into a Ghidra Datatype. Returns nullptr and sets lastError on failure.
    Datatype *parseType(const std::string& type_str) {
        if (arch != nullptr && type_str.find('/') != std::string::npos) {
            // A Ghidra path, with any pointer stars after it ("/cat/T *").
            std::string path = type_str;
            int pointers = 0;
            for (;;) {
                while (!path.empty() && path.back() == ' ') path.pop_back();
                if (path.empty() || path.back() != '*') break;
                path.pop_back();
                ++pointers;
            }
            if (!path.empty() && path[0] != '/') path = "/" + path;
            Datatype *dt = arch->types->findByName(path.substr(path.rfind('/') + 1));
            if (dt != nullptr &&
                ghidraTypePath(dt, arch->types->getSizeOfPointer(), &typeCategories) == path) {
                for (int i = 0; i < pointers; ++i)
                    dt = arch->types->getTypePointer(arch->types->getSizeOfPointer(), dt,
                                                     arch->getDefaultDataSpace()->getWordSize());
                return dt;
            }
            setError(EngineError::kUnknownType, "unknown data type '" + type_str + "'");
            return nullptr;
        }
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
            setError(EngineError::kUnknownType, "unknown data type '" + type_str + "': " + err.explain);
            return nullptr;
        } catch (LowlevelError &err) {
            setError(EngineError::kUnknownType, "unknown data type '" + type_str + "': " + err.explain);
            return nullptr;
        }
    }
};

Decompiler::Decompiler()
    : impl_(new Impl)
{
    std::lock_guard<std::recursive_mutex> setup(engine_setup_mutex());
    impl_->usingEmbeddedSpecs = true;
    std::string spec_dir = ghidra_embedded::EmbeddedSpecManager::acquire();
    vector<string> extrapaths;
    startDecompilerLibrary(spec_dir.c_str(), extrapaths);
}

Decompiler::Decompiler(const std::string& ghidra_root)
    : impl_(new Impl)
{
    std::lock_guard<std::recursive_mutex> setup(engine_setup_mutex());
    vector<string> extrapaths;
    startDecompilerLibrary(ghidra_root.c_str(), extrapaths);
}

Decompiler::~Decompiler()
{
    std::lock_guard<std::recursive_mutex> setup(engine_setup_mutex());
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
                                      std::vector<MemoryBlockInfo>& rva_blocks,
                                      std::string& error);

bool Decompiler::loadBinary(const std::string& filepath, const std::string& arch,
                            uint64_t base_address, const std::string& format)
{
    std::lock_guard<std::recursive_mutex> setup(engine_setup_mutex());
    impl_->destroyArch();

    // Guard: a missing/unreadable binary makes RawBinaryArchitecture::buildLoader
    // throw, and its error path double-frees the RawLoadImage (SEGV during stack
    // unwind). Fail cleanly BEFORE building the architecture rather than crash.
    if (!std::ifstream(filepath, std::ios::binary).good()) {
        impl_->setError(EngineError::kInternal, "Cannot open binary file: " + filepath);
        return false;
    }

    try {
        ArchitectureCapability *capa = ArchitectureCapability::findCapability(filepath);
        if (capa == nullptr) {
            impl_->setError(EngineError::kInternal, "Unable to recognize image file: " + filepath);
            return false;
        }

        // Raw binary format requires an explicit architecture (e.g. "x86:LE:64:default")
        string target = arch;
        if (target.empty()) {
            if (capa->getName() == "raw") {
                impl_->setError(EngineError::kInternal, "Raw binary requires an explicit architecture "
                    "(e.g. \"x86:LE:64:default\")");
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
        std::vector<MemoryBlockInfo> pe_blocks;
        bool is_pe = false;
        if (uses_raw_loader && format != "raw") {
            std::vector<uint8_t> mapped;
            uint64_t pe_image_base = 0;
            std::string map_error;
            PeImageStatus pe_status =
                prepare_pe_image(filepath, mapped, pe_image_base, pe_blocks, map_error);
            if (pe_status == PeImageStatus::Error) {
                impl_->setError(EngineError::kInternal, map_error);
                return false;
            }
            if (pe_status == PeImageStatus::Ready) {
                load_path = write_scratch_image(mapped);
                if (load_path.empty())
                    return impl_->fail(EngineError::kInternal,
                                       "Failed to create scratch image for PE load");
                impl_->bootstrapTempPath = load_path;
                if (effective_base == 0)
                    effective_base = pe_image_base;
                is_pe = true;
            }
        }

        // A raw image gets the host's core data-types (int, uint, undefined4
        // ...) instead of the standalone dialect (int4, uint4, xunknown4 ...).
        impl_->arch = uses_raw_loader
                          ? buildRawArchitecture(load_path, target, &std::cerr)
                          : capa->buildArchitecture(load_path, target, &std::cerr);

        DocumentStorage store;
        impl_->arch->init(store);
        registerTypeNameAliases(impl_->arch);

        // RawLoadImage has no format metadata from which to recover an image
        // base. Honor OpenProgramRequest.base_address so PE/Mach-O callers on
        // builds without BFD address the file at its real virtual addresses.
        // Structured loaders already map their own VMAs and must not be shifted.
        if (uses_raw_loader && effective_base != 0)
            rebase_loader_vma(impl_->arch->loader, effective_base);

        // Read loader symbols if the format supports them (e.g. XML images)
        if (capa->getName() == "xml")
            impl_->arch->readLoaderSymbols();

        // The memory map of a bare image: a PE's headers and sections, else
        // one read/write/execute block over the whole file, named after the
        // code space (Ghidra's raw binary loader). A project load replaces it
        // with the project's own map. Other loaders give none.
        if (uses_raw_loader) {
            if (is_pe) {
                for (MemoryBlockInfo blk : pe_blocks) {
                    blk.start += effective_base;
                    blk.end += effective_base;
                    impl_->blocks.push_back(std::move(blk));
                }
            } else {
                std::error_code size_ec;
                const uint64_t file_size = std::filesystem::file_size(load_path, size_ec);
                if (!size_ec && file_size > 0) {
                    MemoryBlockInfo blk;
                    blk.name = impl_->arch->getDefaultCodeSpace()->getName();
                    blk.start = effective_base;
                    blk.end = effective_base + file_size - 1;
                    blk.read = blk.write = blk.execute = true;
                    blk.initialized = true;
                    impl_->blocks.push_back(std::move(blk));
                }
            }
        }

        impl_->resetListing();
        impl_->applyMemoryProperties({});

    } catch (DecoderError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        impl_->destroyArch();
        return false;
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        impl_->destroyArch();
        return false;
    } catch (std::exception &err) {
        impl_->setError(EngineError::kInternal, err.what());
        impl_->destroyArch();
        return false;
    }

    impl_->clearError();
    return true;
}

std::string Decompiler::decompileAt(uint64_t address)
{
    if (impl_->arch == nullptr) {
        impl_->setError(EngineError::kInternal, "No binary loaded");
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

        prepareSavedFunction(fd, impl_->functionState);

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
            impl_->setError(EngineError::kInternal, "Decompilation did not complete");
            impl_->arch->clearAnalysis(fd);
            return "";
        }

        // The host's text: markup tokens rebuilt into lines, symbols sanitized.
        std::string text = printFunctionLikeHost(impl_->arch, fd);

        // Clean up analysis for this function
        impl_->arch->clearAnalysis(fd);

        impl_->clearError();
        return text;

    } catch (RecovError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return "";
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return "";
    } catch (std::exception &err) {
        impl_->setError(EngineError::kInternal, err.what());
        return "";
    }
}

std::string Decompiler::getError() const
{
    return impl_->lastError;
}

EngineError Decompiler::getErrorKind() const
{
    return impl_->lastKind;
}

// ---------------------------------------------------------------------------
// Type Creation
// ---------------------------------------------------------------------------

bool Decompiler::defineStruct(const std::string& name, const std::vector<FieldDef>& fields, int size)
{
    if (impl_->arch == nullptr)
        return impl_->fail(EngineError::kInternal, "No binary loaded");

    try {
        TypeFactory *types = impl_->arch->types;
        if (types->findByName(name) != nullptr)
            return impl_->fail(EngineError::kInvalid, "a type named '" + name + "' already exists");

        // Create an incomplete struct
        TypeStruct *st = types->getTypeStruct(name);

        vector<TypeField> fieldVec;
        for (size_t i = 0; i < fields.size(); i++) {
            Datatype *ftype = impl_->parseType(fields[i].type_name);
            if (ftype == nullptr)
                return false;  // parseType set the error
            fieldVec.push_back(TypeField((int4)i, fields[i].offset, fields[i].name, ftype));
        }

        // Complete the struct definition
        vector<TypeBitField> bitVec;
        types->assignRawFields(st, fieldVec, bitVec);
        // A size beyond the fields is undefined bytes (StructureDataType(name, size)).
        if (size > st->getSize())
            types->redefineStruct(st, fieldVec, bitVec, size, std::max(1, st->getAlignment()));

        impl_->clearError();
        return true;

    } catch (LowlevelError &err) {
        return impl_->fail(EngineError::kInternal, err.explain);
    } catch (std::exception &err) {
        return impl_->fail(EngineError::kInternal, err.what());
    }
}

bool Decompiler::defineUnion(const std::string& name)
{
    if (impl_->arch == nullptr)
        return impl_->fail(EngineError::kInternal, "No binary loaded");
    try {
        TypeFactory *types = impl_->arch->types;
        if (types->findByName(name) != nullptr)
            return impl_->fail(EngineError::kInvalid, "a type named '" + name + "' already exists");
        TypeUnion *un = types->getTypeUnion(name);
        vector<TypeField> fields;
        types->assignRawFields(un, fields);
        impl_->clearError();
        return true;
    } catch (LowlevelError &err) {
        return impl_->fail(EngineError::kInternal, err.explain);
    }
}

// ---------------------------------------------------------------------------
// ParseDeclarations: C declarations, read as Ghidra's CParser reads them
// ---------------------------------------------------------------------------
//
// The decompiler's own grammar (parse_C) takes one declaration at a time and
// differs from CParser in what it creates: it renames a struct to the typedef
// naming it, knows neither forward references nor multi-word C base types,
// sizes enums by the pointer, names no anonymous type and makes no function
// definitions. Each declaration is therefore taken apart here, specifier by
// specifier, and the grammar is only handed what it reads the same way:
//   - every `struct`/`union` keyword and every anonymous `enum` takes a number
//     from one counter (CParser.cnt), which names the anonymous ones
//     _struct_<n>, _union_<n> and enum_<n>;
//   - `typedef struct {...} T` names the struct T; a typedef of a named type
//     is a typedef of it;
//   - `struct S` naming no type declares an empty one;
//   - a definition of a type that exists replaces it in place
//     (DataTypeConflictHandler.REPLACE_HANDLER), so its users see it;
//   - an enum is int-sized unless its values need more, and a value out of
//     range for it is dropped (EnumDataType);
//   - a function declaration, or a function pointer declared alone or by a
//     typedef, makes a function definition in /functions named after it; a
//     function pointer member makes /functions/_func_<n>;
//   - every parsed composite packs its fields (default packing);
//   - an anonymous struct or union declared alone, and a variable, create nothing.

static bool namesCallingConvention(Architecture *arch, const std::string &prototype);
std::string dropTypeQualifiers(const std::string &text);

namespace {

bool isIdentStart(char c) { return std::isalpha(static_cast<unsigned char>(c)) || c == '_'; }
bool isIdentChar(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }
bool isIdentifier(const std::string& t) { return !t.empty() && isIdentStart(t[0]); }

std::vector<CToken> tokenizeC(const std::string& s)
{
    std::vector<CToken> out;
    size_t i = 0;
    while (i < s.size()) {
        const char c = s[i];
        if (std::isspace(static_cast<unsigned char>(c))) {
            ++i;
            continue;
        }
        const size_t start = i;
        if (isIdentStart(c)) {
            while (i < s.size() && isIdentChar(s[i])) ++i;
        } else if (std::isdigit(static_cast<unsigned char>(c))) {
            while (i < s.size() && (isIdentChar(s[i]) || s[i] == '.')) ++i;
        } else if (c == '"' || c == '\'') {
            ++i;
            while (i < s.size() && s[i] != c) i += s[i] == '\\' ? 2 : 1;
            i = std::min(s.size(), i + 1);
        } else if (s.compare(i, 3, "...") == 0) {
            i += 3;
        } else {
            ++i;
        }
        out.push_back({s.substr(start, i - start)});
    }
    return out;
}

// The index of the token closing the bracket opened at `open`.
size_t matchingClose(const std::vector<CToken>& t, size_t open)
{
    const std::string o = t[open].text;
    const std::string c = o == "{" ? "}" : o == "(" ? ")" : "]";
    int depth = 0;
    for (size_t i = open; i < t.size(); ++i) {
        if (t[i].text == o) ++depth;
        else if (t[i].text == c && --depth == 0) return i;
    }
    throw ParseError("Unbalanced '" + o + "'");
}

std::string joinTokens(const std::vector<CToken>& t, size_t first, size_t last)
{
    std::string out;
    for (size_t i = first; i < last && i < t.size(); ++i) {
        if (!out.empty()) out += ' ';
        out += t[i].text;
    }
    return out;
}

// Where the declarator begins in a "<specifier> <declarator>" token run: at a
// "(*" function-pointer declarator, else at the pointer stars before the last
// identifier. `last` when there is no declarator.
size_t declaratorStart(const std::vector<CToken>& t, size_t first, size_t last)
{
    for (size_t i = first; i + 1 < last; ++i)
        if (t[i].text == "(" && t[i + 1].text == "*") return i;
    size_t name = last;
    for (size_t i = last; i-- > first;) {
        if (t[i].text == "]") {
            while (i > first && t[i].text != "[") --i;
            continue;
        }
        if (isIdentifier(t[i].text)) {
            name = i;
            break;
        }
    }
    if (name == last || name == first) return last;
    size_t start = name;
    while (start > first && (t[start - 1].text == "*" || t[start - 1].text == "const" ||
                             t[start - 1].text == "volatile"))
        --start;
    return start;
}

// Split [first, last) at the commas outside brackets.
std::vector<std::pair<size_t, size_t>> splitCommas(const std::vector<CToken>& t, size_t first, size_t last)
{
    std::vector<std::pair<size_t, size_t>> out;
    int depth = 0;
    size_t start = first;
    for (size_t i = first; i < last; ++i) {
        const std::string& x = t[i].text;
        if (x == "(" || x == "[" || x == "{") ++depth;
        else if (x == ")" || x == "]" || x == "}") --depth;
        else if (x == "," && depth == 0) {
            out.push_back({start, i});
            start = i + 1;
        }
    }
    out.push_back({start, last});
    return out;
}

bool parseInteger(const std::string& text, int64_t& out)
{
    std::string v = text;
    const bool hex = v.size() > 2 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X');
    while (!v.empty() && (v.back() == 'u' || v.back() == 'U' || v.back() == 'l' || v.back() == 'L') &&
           !(hex && std::isxdigit(static_cast<unsigned char>(v.back()))))
        v.pop_back();  // integer suffixes
    if (v.empty()) return false;
    try {
        size_t used = 0;
        const unsigned long long u = std::stoull(v, &used, 0);
        if (used != v.size()) return false;
        out = static_cast<int64_t>(u);
        return true;
    } catch (...) {
        return false;
    }
}

bool isBaseWord(const std::string& w)
{
    return w == "signed" || w == "unsigned" || w == "short" || w == "long" || w == "int" ||
           w == "char" || w == "double";
}

// A pointer chain ending at an unnamed function type: what a function-pointer
// declarator builds.
TypeCode *unnamedCodeTarget(Datatype *dt)
{
    while (dt != nullptr && dt->getMetatype() == TYPE_PTR)
        dt = static_cast<TypePointer *>(dt)->getPtrTo();
    if (dt == nullptr || dt->getMetatype() != TYPE_CODE || !dt->getName().empty()) return nullptr;
    return static_cast<TypeCode *>(dt);
}

}  // namespace

std::string Decompiler::Impl::baseTypeName(const std::vector<std::string>& words) const
{
    int longs = 0;
    bool is_unsigned = false, is_signed = false, is_short = false, is_char = false, is_double = false;
    for (const std::string& w : words) {
        if (w == "long") ++longs;
        else if (w == "unsigned") is_unsigned = true;
        else if (w == "signed") is_signed = true;
        else if (w == "short") is_short = true;
        else if (w == "char") is_char = true;
        else if (w == "double") is_double = true;
    }
    std::vector<const char *> names;
    if (is_double) names = {longs > 0 ? "longdouble" : "double", "double"};
    else if (is_char) names = {is_unsigned ? "uchar" : is_signed ? "schar" : "char", is_signed ? "sbyte" : "char"};
    else if (is_short) names = {is_unsigned ? "ushort" : "short"};
    else if (longs >= 2) names = {is_unsigned ? "ulonglong" : "longlong"};
    else if (longs == 1) names = {is_unsigned ? "ulong" : "long"};
    else names = {is_unsigned ? "uint" : "int"};
    for (const char *n : names)
        if (arch->types->findByName(n) != nullptr) return n;
    throw ParseError("Unknown base type: " + words.front());
}

Datatype *Decompiler::Impl::namedFunctionPointer(Datatype *dt, const std::string &name)
{
    TypeCode *code = unnamedCodeTarget(dt);
    if (code == nullptr || code->getPrototype() == nullptr) return dt;
    const FuncProto *proto = code->getPrototype();
    FunctionDefinitionSpec spec;
    spec.name = name;
    spec.id = parseTypeId("/functions/" + name);
    spec.output = proto->getOutputType();
    for (int4 i = 0; i < proto->numParams(); ++i)
        spec.params.emplace_back(proto->getParam(i)->getName(), proto->getParam(i)->getType());
    spec.calling_convention = "unknown";
    spec.has_var_args = proto->isDotdotdot();
    Datatype *def = makeFunctionDefinition(arch, spec);
    typeCategories[def->getUnsizedId()] = "/functions";
    // The same pointer chain, now to the definition.
    std::vector<TypePointer *> chain;
    for (Datatype *p = dt; p != code; p = static_cast<TypePointer *>(p)->getPtrTo())
        chain.push_back(static_cast<TypePointer *>(p));
    Datatype *out = def;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it)
        out = arch->types->getTypePointer((*it)->getSize(), out, (*it)->getWordSize());
    return out;
}

uint64_t Decompiler::Impl::parseTypeId(const std::string &path) const
{
    // A program type id of its own (FNV-1a of the path), clear of the
    // decompiler's name hashes (top bits 11) and of the database's kinds.
    uint64_t h = 1469598103934665603ULL;
    for (char c : path) {
        h ^= static_cast<unsigned char>(c);
        h *= 1099511628211ULL;
    }
    return (h & 0x00ffffffffffffffULL) | 0x0700000000000000ULL;
}

void Decompiler::Impl::defineComposite(bool is_union, const std::string &tag,
                                       const std::vector<CToken> &body, ParseState &state)
{
    TypeFactory *types = arch->types;
    // The body, under a name of its own: the grammar cannot define a type
    // whose name it already knows, and the real one may exist (replaced in
    // place) or be referenced from its own body (a stub made before).
    const std::string temp = "__libghidra_parse_" + std::to_string(state.temp_counter++);
    {
        std::istringstream ss(std::string(is_union ? "union " : "struct ") + temp + " { " +
                              joinTokens(body, 0, body.size()) + " } ;");
        parse_C(arch, ss);
    }
    Datatype *parsed = types->findByName(temp);
    if (parsed == nullptr) throw ParseError("Could not define " + tag);
    state.temps.push_back(parsed);
    vector<TypeField> fields;
    vector<TypeBitField> bits;
    if (is_union) {
        auto *tu = static_cast<TypeUnion *>(parsed);
        for (int4 i = 0; i < tu->numDepend(); ++i) fields.push_back(*tu->getField(i));
    } else {
        auto *ts = static_cast<TypeStruct *>(parsed);
        fields.assign(ts->beginField(), ts->endField());
        for (int4 i = 0; i < ts->numBitFields(); ++i) bits.push_back(ts->getBitField(i));
    }
    // A function pointer member points at /functions/_func_<n>.
    for (TypeField &f : fields)
        if (unnamedCodeTarget(f.type) != nullptr)
            f.type = namedFunctionPointer(f.type, "_func_" + std::to_string(state.func_counter++));
    Datatype *target = types->findByName(tag);
    const type_metatype want = is_union ? TYPE_UNION : TYPE_STRUCT;
    if (target == nullptr || target->getMetatype() != want || target->getTypedef() != nullptr)
        throw ParseError("Redefinition of " + tag + " as another kind of type");
    state.composites.insert(target);
    if (target->isIncomplete()) {
        // A stub this parse made: give it the fields, laid out as the grammar
        // lays out C (default packing). A packed union is as long as its
        // longest member rounded up to its alignment.
        for (TypeField &f : fields) f.offset = -1;
        if (is_union) {
            auto *un = static_cast<TypeUnion *>(target);
            types->assignRawFields(un, fields);
            const int4 align = std::max(1, un->getAlignment());
            const int4 size = (un->getSize() + align - 1) / align * align;
            if (size != un->getSize()) {
                vector<TypeField> laid(fields);
                for (TypeField &f : laid) f.offset = 0;
                types->redefineUnion(un, laid, size, align);
            }
        } else {
            types->assignRawFields(static_cast<TypeStruct *>(target), fields, bits);
        }
        return;
    }
    // An existing type: replaced in place.
    packing[target->getUnsizedId()] = 0;
    std::string error;
    if (state.replace) {
        if (!state.replace(target, parsed, fields, error)) throw ParseError(error);
    } else if (is_union) {
        types->redefineUnion(static_cast<TypeUnion *>(target), fields, parsed->getSize(), parsed->getAlignment());
    } else {
        types->redefineStruct(static_cast<TypeStruct *>(target), fields, bits, parsed->getSize(),
                              parsed->getAlignment());
    }
}

void Decompiler::Impl::defineEnumeration(const std::string &tag, const std::vector<CToken> &t,
                                         size_t first, size_t last, ParseState &state)
{
    // EnumDataType(int size): each value added must fit its signedness so far,
    // or it is dropped; the length then grows to what the values need.
    const int size = arch->types->getSizeOfInt();
    const int bits = size * 8;
    std::vector<std::pair<std::string, int64_t>> values;
    int64_t value = 0;
    bool has_negative = false, has_large = false;
    for (const auto &[a, b] : splitCommas(t, first, last)) {
        if (a == b) continue;  // a trailing comma
        if (!isIdentifier(t[a].text)) throw ParseError("Bad enumerator in " + tag);
        if (b > a + 1) {
            if (t[a + 1].text != "=" || b < a + 3) throw ParseError("Bad enumerator in " + tag);
            const bool negative = t[a + 2].text == "-";
            const size_t num = negative ? a + 3 : a + 2;
            if (num + 1 != b || !parseInteger(t[num].text, value))
                throw ParseError("Enumerator value is not a number: " + joinTokens(t, a + 2, b));
            if (negative) value = -value;
        }
        const int64_t min = has_large ? 0 : -(int64_t(1) << (bits - 1));
        const int64_t max = has_negative ? (int64_t(1) << (bits - 1)) - 1 : (int64_t(1) << bits) - 1;
        if (size >= 8 || (value >= min && value <= max)) {
            values.emplace_back(t[a].text, value);
            if (value < 0) has_negative = true;
            if (value > (int64_t(1) << (bits - 1)) - 1) has_large = true;
        }
        ++value;
    }
    Datatype *existing = arch->types->findByName(tag);
    if (existing != nullptr) {
        // Replaced in place (REPLACE_HANDLER): the values; its size stands.
        auto *te = dynamic_cast<TypeEnum *>(existing);
        if (te == nullptr || existing->getTypedef() != nullptr)
            throw ParseError("Redefinition of " + tag + " as another kind of type");
        map<uintb, string> nmap;
        for (const auto &[name, v] : values) nmap.emplace(static_cast<uintb>(v), name);
        arch->types->setEnumValues(nmap, te);
        return;
    }
    makeEnumType(arch, tag, 0, enumLengthFor(values, size), values);
}

std::vector<CToken> Decompiler::Impl::resolveSpecifiers(const std::vector<CToken> &t, size_t first,
                                                        size_t last, const std::string &typedefName,
                                                        ParseState &state)
{
    TypeFactory *types = arch->types;
    std::vector<CToken> out;
    for (size_t i = first; i < last; ++i) {
        const std::string &word = t[i].text;
        const std::string next = i + 1 < last ? t[i + 1].text : "";
        if (word == "struct" || word == "union") {
            const bool is_union = word == "union";
            const int n = state.counter++;
            std::string tag;
            size_t open;
            if (next == "{") {
                tag = !typedefName.empty() && i == first + 1 && t[first].text == "typedef"
                          ? typedefName
                          : (is_union ? "_union_" : "_struct_") + std::to_string(n);
                open = i + 1;
            } else if (isIdentifier(next) && i + 2 < last && t[i + 2].text == "{") {
                tag = next;
                open = i + 2;
            } else if (isIdentifier(next)) {
                // A reference: the type itself, declared empty when there is none
                // (CParser's forward declaration).
                if (types->findByName(next) == nullptr) {
                    if (is_union) {
                        vector<TypeField> none;
                        types->assignRawFields(types->getTypeUnion(next), none);
                    } else {
                        vector<TypeField> none;
                        vector<TypeBitField> nobits;
                        types->assignRawFields(types->getTypeStruct(next), none, nobits);
                    }
                }
                out.push_back({next});
                ++i;
                continue;
            } else {
                throw ParseError("Bad " + word + " specifier");
            }
            // A stub first, so the body may point back at it.
            if (types->findByName(tag) == nullptr) {
                if (is_union) types->getTypeUnion(tag);
                else types->getTypeStruct(tag);
            }
            const size_t close = matchingClose(t, open);
            const std::vector<CToken> body = resolveSpecifiers(t, open + 1, close, "", state);
            defineComposite(is_union, tag, body, state);
            out.push_back({tag});
            i = close;
            continue;
        }
        if (word == "enum") {
            size_t open = i + 1;
            std::string tag;
            if (next == "{") {
                tag = "enum_" + std::to_string(state.counter++);
            } else if (isIdentifier(next)) {
                tag = next;
                open = i + 2;
            } else {
                throw ParseError("Bad enum specifier");
            }
            if (open >= last || t[open].text != "{") {
                if (types->findByName(tag) == nullptr) throw ParseError("Unknown enum " + tag);
                out.push_back({tag});
                i = open - 1;
                continue;
            }
            const size_t close = matchingClose(t, open);
            defineEnumeration(tag, t, open + 1, close, state);
            out.push_back({tag});
            i = close;
            continue;
        }
        if (isBaseWord(word)) {
            // A C base type of several words is one type name to the grammar.
            std::vector<std::string> words;
            while (i < last && (isBaseWord(t[i].text) || t[i].text == "const" || t[i].text == "volatile")) {
                if (isBaseWord(t[i].text)) words.push_back(t[i].text);
                ++i;
            }
            --i;
            out.push_back({baseTypeName(words)});
            continue;
        }
        out.push_back(t[i]);
    }
    return out;
}

void Decompiler::Impl::parseDeclaration(const std::string &decl, ParseState &state)
{
    TypeFactory *types = arch->types;
    std::vector<CToken> raw = tokenizeC(decl);
    while (!raw.empty() && raw.back().text == ";") raw.pop_back();
    if (raw.empty()) return;

    // An anonymous struct or union alone declares nothing CParser keeps; its
    // keywords still count.
    if ((raw[0].text == "struct" || raw[0].text == "union") && raw.size() > 1 && raw[1].text == "{" &&
        matchingClose(raw, 1) + 1 == raw.size()) {
        for (const CToken &x : raw)
            if (x.text == "struct" || x.text == "union") ++state.counter;
        for (size_t i = 0; i + 1 < raw.size(); ++i)
            if (raw[i].text == "enum" && raw[i + 1].text == "{") ++state.counter;
        return;
    }

    // A typedef of an anonymous struct or union names it after its first declarator.
    std::string typedefName;
    if (raw[0].text == "typedef" && raw.size() > 2 && (raw[1].text == "struct" || raw[1].text == "union") &&
        raw[2].text == "{") {
        const size_t close = matchingClose(raw, 2);
        if (close + 1 < raw.size() && isIdentifier(raw[close + 1].text) &&
            (close + 2 == raw.size() || raw[close + 2].text == ","))
            typedefName = raw[close + 1].text;
    }

    const std::vector<CToken> t = resolveSpecifiers(raw, 0, raw.size(), typedefName, state);
    const std::string text = joinTokens(t, 0, t.size());

    if (t[0].text == "typedef") {
        const auto segments = splitCommas(t, 1, t.size());
        const size_t start = declaratorStart(t, segments[0].first, segments[0].second);
        if (start >= segments[0].second) throw ParseError("Missing identifier for typedef");
        const std::string base = joinTokens(t, 1, start);
        bool first = true;
        for (auto [a, b] : segments) {
            if (first) a = start;
            first = false;
            if (a == b) throw ParseError("Missing identifier for typedef");
            if (b == a + 1 && t[a].text == base) continue;  // a typedef naming the type itself
            std::string name;
            std::istringstream ss(base + " " + joinTokens(t, a, b));
            Datatype *ct = parse_type(ss, name, arch);
            if (name.empty()) throw ParseError("Missing identifier for typedef");
            ct = namedFunctionPointer(ct, name);
            Datatype *same = types->findByName(name);
            if (same != nullptr && same->getMetatype() != TYPE_CODE) {
                if (same->getTypedef() == ct) continue;  // already this typedef
                throw ParseError("Redefinition of " + name);
            }
            types->getTypedef(ct, name, 0, 0);
        }
        return;
    }
    if (t.size() == 1) return;  // a struct, union or enum alone: defined above

    // A function declaration becomes a function definition in /functions.
    const size_t open = static_cast<size_t>(
        std::find_if(t.begin(), t.end(), [](const CToken &x) { return x.text == "("; }) - t.begin());
    PrototypePieces pieces;
    bool is_function = false;
    if (open < t.size() && open > 0 && isIdentifier(t[open - 1].text) &&
        types->findByName(t[open - 1].text) == nullptr) {
        std::istringstream ss(text + ";");
        parse_protopieces(pieces, ss, arch);
        is_function = !pieces.name.empty();
    }
    if (is_function) {
        FunctionDefinitionSpec spec;
        spec.name = pieces.name;
        spec.id = parseTypeId("/functions/" + pieces.name);
        spec.output = pieces.outtype;
        for (size_t i = 0; i < pieces.intypes.size(); ++i)
            spec.params.emplace_back(i < pieces.innames.size() ? pieces.innames[i] : "", pieces.intypes[i]);
        spec.calling_convention = namesCallingConvention(arch, text) ? pieces.model->getName() : "unknown";
        spec.has_var_args = pieces.firstVarArgSlot >= 0;
        Datatype *dt = makeFunctionDefinition(arch, spec);
        typeCategories[dt->getUnsizedId()] = "/functions";
        return;
    }
    // Variables create nothing, but a function pointer declared alone makes
    // its function definition.
    const auto segments = splitCommas(t, 0, t.size());
    const size_t start = declaratorStart(t, segments[0].first, segments[0].second);
    const std::string base = joinTokens(t, 0, start);
    bool first = true;
    for (auto [a, b] : segments) {
        if (first) a = start;
        first = false;
        std::string name;
        std::istringstream ss(base + " " + joinTokens(t, a, b));
        Datatype *ct = parse_type(ss, name, arch);
        if (!name.empty()) namedFunctionPointer(ct, name);
    }
}

bool Decompiler::parseDeclarations(const std::string& text, std::vector<std::string>& created,
                                   const ReplaceComposite& replace)
{
    if (impl_->arch == nullptr)
        return impl_->fail(EngineError::kInternal, "No binary loaded");
    TypeFactory *types = impl_->arch->types;
    vector<Datatype *> before;
    types->dependentOrder(before);
    const std::set<Datatype *> existing(before.begin(), before.end());
    // One declaration at a time: split the text at every ';' outside braces
    // (comments dropped first).
    static const char* const kSpace = " \t\r\n";
    std::string code;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text.compare(i, 2, "//") == 0) {
            while (i < text.size() && text[i] != '\n') ++i;
            code += '\n';
        } else if (text.compare(i, 2, "/*") == 0) {
            const size_t end = text.find("*/", i + 2);
            i = end == std::string::npos ? text.size() : end + 1;
            code += ' ';
        } else {
            code += text[i];
        }
    }
    std::vector<std::string> declarations;
    int depth = 0;
    std::string current;
    for (char ch : code) {
        current += ch;
        if (ch == '{') ++depth;
        else if (ch == '}') --depth;
        else if (ch == ';' && depth == 0) {
            declarations.push_back(current);
            current.clear();
        }
    }
    if (current.find_first_not_of(kSpace) != std::string::npos)
        declarations.push_back(current);  // a trailing declaration without ';' fails below
    Impl::ParseState state;
    state.replace = replace;
    std::string error;
    for (const std::string& decl : declarations) {
        const size_t start = decl.find_first_not_of(kSpace);
        if (start == std::string::npos || decl[start] == ';') continue;
        try {
            if (decl.find(';') == std::string::npos) throw ParseError("Missing ';'");
            impl_->parseDeclaration(dropTypeQualifiers(decl), state);
        } catch (ParseError &err) {
            error = err.explain;
        } catch (LowlevelError &err) {
            error = err.explain;
        }
        if (!error.empty()) {
            error += " (in: " + decl.substr(start, 60) + ")";
            break;
        }
    }
    // The bodies parsed under a name of their own are not the program's.
    for (Datatype *temp : state.temps) {
        try {
            types->destroyType(temp);
        } catch (LowlevelError &) {
        }
    }
    vector<Datatype *> after;
    types->dependentOrder(after);
    std::vector<Datatype *> fresh;
    for (Datatype *dt : after)
        if (existing.count(dt) == 0) fresh.push_back(dt);
    if (!error.empty()) {
        // All or nothing: remove what the text had defined before the error,
        // users after what they use (reverse dependency order).
        for (auto it = fresh.rbegin(); it != fresh.rend(); ++it) {
            impl_->typeCategories.erase((*it)->getUnsizedId());
            try {
                types->destroyType(*it);
            } catch (LowlevelError &) {
            }
        }
        return impl_->fail(EngineError::kParse, "parse error: " + error);
    }
    // CParser lays every composite out with default packing.
    for (Datatype *dt : state.composites) impl_->packing[dt->getUnsizedId()] = 0;
    created.clear();
    for (Datatype *dt : fresh) {
        if (dt->getName().empty() || dt->isCoreType()) continue;
        auto category = impl_->typeCategories.find(dt->getUnsizedId());
        const std::string path = category != impl_->typeCategories.end() && category->second != "/"
                                     ? category->second + "/" + dt->getName()
                                     : "/" + dt->getName();
        created.push_back(path);
    }
    // A built-in type the new types use that the program did not hold yet is
    // added to it too, and counted (the host's data type manager resolves it).
    if (impl_->projectLoaded) {
        static const std::set<std::string> kBuiltins = {
            "bool", "char", "uchar", "schar", "short", "ushort", "int", "uint", "long", "ulong",
            "longlong", "ulonglong", "float", "double", "longdouble", "wchar_t", "wchar16", "wchar32"};
        std::vector<Datatype *> work(fresh.begin(), fresh.end());
        work.insert(work.end(), state.composites.begin(), state.composites.end());
        std::set<Datatype *> seen(work.begin(), work.end());
        for (size_t i = 0; i < work.size(); ++i) {
            Datatype *dt = work[i];
            std::vector<Datatype *> next;
            if (dt->getTypedef() != nullptr) next.push_back(dt->getTypedef());
            for (int4 d = 0; d < dt->numDepend(); ++d) next.push_back(dt->getDepend(d));
            if (dt->getMetatype() == TYPE_CODE) {
                if (const FuncProto *proto = static_cast<TypeCode *>(dt)->getPrototype()) {
                    next.push_back(proto->getOutputType());
                    for (int4 p = 0; p < proto->numParams(); ++p) next.push_back(proto->getParam(p)->getType());
                }
            }
            for (Datatype *n : next) {
                if (n == nullptr || !seen.insert(n).second) continue;
                if (n->isCoreType()) {
                    const std::string &name = n->getName();
                    if (kBuiltins.count(name) != 0 && impl_->builtinTypeIds.emplace(name, 0).second)
                        created.push_back("/" + name);
                    continue;
                }
                work.push_back(n);
            }
        }
    }
    impl_->clearError();
    return true;
}

uint64_t Decompiler::ghidraTypeId(const Datatype* type) const
{
    if (type == nullptr) return 0;
    if (impl_->typeCategories.count(type->getUnsizedId()) != 0) return type->getUnsizedId();
    auto it = impl_->builtinTypeIds.find(type->getName());
    return it != impl_->builtinTypeIds.end() ? it->second : 0;
}

bool Decompiler::isPackedType(uint64_t id) const
{
    return impl_->packing.count(id) != 0;
}

int Decompiler::packing(uint64_t id) const
{
    auto it = impl_->packing.find(id);
    return it != impl_->packing.end() ? it->second : -1;
}

void Decompiler::setPacking(uint64_t id, int pack)
{
    if (pack < 0)
        impl_->packing.erase(id);
    else
        impl_->packing[id] = pack;
}

void Decompiler::refreshDataSizes()
{
    impl_->listing.refreshDataSizes();
}

bool Decompiler::defineEnum(const std::string& name, const std::vector<EnumValue>& values, int size)
{
    if (impl_->arch == nullptr)
        return impl_->fail(EngineError::kInternal, "No binary loaded");

    try {
        TypeFactory *types = impl_->arch->types;
        if (types->findByName(name) != nullptr)
            return impl_->fail(EngineError::kInvalid, "a type named '" + name + "' already exists");

        // EnumDataType(name, size): the size the caller asked for (1..8).
        std::vector<std::pair<std::string, int64_t>> list;
        for (const auto &v : values)
            list.emplace_back(v.name, static_cast<int64_t>(v.value));
        makeEnumType(impl_->arch, name, 0, std::max(1, std::min(8, size)), list);

        impl_->clearError();
        return true;

    } catch (LowlevelError &err) {
        return impl_->fail(EngineError::kInternal, err.explain);
    } catch (std::exception &err) {
        return impl_->fail(EngineError::kInternal, err.what());
    }
}

// ---------------------------------------------------------------------------
// Symbol Management
// ---------------------------------------------------------------------------

// The function symbol whose entry is `addr`, in whichever namespace holds it.
static FunctionSymbol *functionSymbolAt(Architecture *arch, const Address &addr)
{
    if (Funcdata *fd = arch->symboltab->getGlobalScope()->queryFunction(addr))
        return fd->getSymbol();
    SymbolEntry *entry = libghidra::detail::find_addr_any_scope(arch, addr);
    return entry != nullptr ? dynamic_cast<FunctionSymbol *>(entry->getSymbol()) : nullptr;
}

bool Decompiler::renameFunction(uint64_t entry, const std::string& name)
{
    if (impl_->arch == nullptr)
        return impl_->fail(EngineError::kInternal, "No binary loaded");

    try {
        const Address addr(impl_->arch->getDefaultCodeSpace(), (uintb)entry);
        FunctionSymbol *sym = functionSymbolAt(impl_->arch, addr);
        if (sym == nullptr) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "no function at 0x%llx", (unsigned long long)entry);
            return impl_->fail(EngineError::kNotFound, buf);
        }
        // Rename the one symbol in its own namespace (adding a function there
        // would leave a second symbol beside it), and the Funcdata it built,
        // which keeps its own copy of the name for declarations and calls.
        Scope *scope = sym->getScope();
        scope->renameSymbol(sym, name);
        scope->setAttribute(sym, Varnode::namelock);
        sym->getFunction()->setName(name);
        impl_->listing.setFunctionSource(entry, true);

        impl_->clearError();
        return true;

    } catch (LowlevelError &err) {
        return impl_->fail(EngineError::kInternal, err.explain);
    } catch (std::exception &err) {
        return impl_->fail(EngineError::kInternal, err.what());
    }
}

bool Decompiler::defineFunction(uint64_t address, const std::string& name)
{
    if (impl_->arch == nullptr)
        return impl_->fail(EngineError::kInternal, "No binary loaded");

    try {
        const Address addr(impl_->arch->getDefaultCodeSpace(), (uintb)address);
        if (functionSymbolAt(impl_->arch, addr) != nullptr) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "a function already starts at 0x%llx",
                          (unsigned long long)address);
            return impl_->fail(EngineError::kInvalid, buf);
        }
        impl_->listing.functionCreated(address);
        impl_->listing.setFunctionId(address, impl_->listing.nextSymbolId());
        char def[40];
        std::snprintf(def, sizeof def, "FUN_%08llx", (unsigned long long)address);
        impl_->listing.setFunctionSource(address, name != def);
        Scope *global = impl_->arch->symboltab->getGlobalScope();
        FunctionSymbol *sym = global->addFunction(addr, name);
        global->setAttribute(sym, Varnode::namelock);

        impl_->clearError();
        return true;

    } catch (LowlevelError &err) {
        return impl_->fail(EngineError::kInternal, err.explain);
    } catch (std::exception &err) {
        return impl_->fail(EngineError::kInternal, err.what());
    }
}

bool Decompiler::renameSymbol(const std::string& old_name, const std::string& new_name)
{
    if (impl_->arch == nullptr) {
        impl_->setError(EngineError::kInternal, "No binary loaded");
        return false;
    }

    try {
        Scope *global = impl_->arch->symboltab->getGlobalScope();
        vector<Symbol *> symList;
        global->queryByName(old_name, symList);

        if (symList.empty()) {
            impl_->setError(EngineError::kInternal, "No symbol named: " + old_name);
            return false;
        }
        if (symList.size() > 1) {
            impl_->setError(EngineError::kInternal, "More than one symbol named: " + old_name);
            return false;
        }

        Symbol *sym = symList[0];
        sym->getScope()->renameSymbol(sym, new_name);
        sym->getScope()->setAttribute(sym, Varnode::namelock | Varnode::typelock);

        impl_->clearError();
        return true;

    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return false;
    } catch (std::exception &err) {
        impl_->setError(EngineError::kInternal, err.what());
        return false;
    }
}

bool Decompiler::retypeSymbol(const std::string& symbol_name, const std::string& type_name)
{
    if (impl_->arch == nullptr) {
        impl_->setError(EngineError::kInternal, "No binary loaded");
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
            impl_->setError(EngineError::kInternal, "No symbol named: " + symbol_name);
            return false;
        }
        if (symList.size() > 1) {
            impl_->setError(EngineError::kInternal, "More than one symbol named: " + symbol_name);
            return false;
        }

        Symbol *sym = symList[0];
        sym->getScope()->retypeSymbol(sym, ct);
        sym->getScope()->setAttribute(sym, Varnode::typelock);

        impl_->clearError();
        return true;

    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return false;
    } catch (std::exception &err) {
        impl_->setError(EngineError::kInternal, err.what());
        return false;
    }
}

bool Decompiler::addGlobalRange(uint64_t address, uint64_t size)
{
    if (impl_->arch == nullptr) {
        impl_->setError(EngineError::kInternal, "No binary loaded");
        return false;
    }

    try {
        AddrSpace *defaultSpace = impl_->arch->getDefaultCodeSpace();
        Scope *global = impl_->arch->symboltab->getGlobalScope();
        impl_->arch->symboltab->addRange(global, defaultSpace, (uintb)address, (uintb)(address + size - 1));

        impl_->clearError();
        return true;

    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return false;
    } catch (std::exception &err) {
        impl_->setError(EngineError::kInternal, err.what());
        return false;
    }
}

// ---------------------------------------------------------------------------
// Function Prototypes
// ---------------------------------------------------------------------------

// FuncProto::setPieces never fails: when the calling convention cannot place a
// parameter (e.g. `int a, int b` on the 8-bit Z80, 6502 and 8051 conventions),
// updateAllTypes swallows ParamUnassignedError, flags the prototype
// error_inputparam and leaves it EMPTY -- `void f()`, which also wipes the
// prototype that was there before. Assign storage on the side first so an
// unrepresentable prototype is rejected before anything is touched, instead of
// being reported as applied.
static bool validatePieces(const PrototypePieces &pieces, std::string &error)
{
    if (pieces.model == nullptr)
        return true;
    std::vector<ParameterPieces> storage;
    try {
        pieces.model->assignParameterStorage(pieces, storage, false);
    } catch (ParamUnassignedError &err) {
        error = "Prototype cannot be represented by calling convention '" +
                pieces.model->getName() + "': " + err.explain;
        return false;
    }
    return true;
}

// Some identifier before the parameter list is a calling convention the
// architecture knows ("int __stdcall f(int)").
static bool namesCallingConvention(Architecture *arch, const std::string &prototype)
{
    const size_t open = prototype.find('(');
    const std::string head = prototype.substr(0, open);
    std::string token;
    for (size_t i = 0; i <= head.size(); ++i) {
        const char c = i < head.size() ? head[i] : ' ';
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            token += c;
            continue;
        }
        if (!token.empty() && arch->getModel(token) != nullptr) return true;
        token.clear();
    }
    return false;
}

// The type qualifiers Ghidra's CParser reads and discards (its C.jj tokens:
// `_*const`, `_*volatile_*`, `_+restrict`) dropped from C text, so the
// decompiler's grammar gives the same types; Ghidra data types carry no
// qualifiers. A bare `restrict` after a `*` is no qualifier to CParser, which
// rejects it there, and so does this (ParseError).
std::string dropTypeQualifiers(const std::string &text)
{
    auto matches = [](const std::string &w, const std::string &core, bool lead, bool trail, bool need_lead) {
        size_t a = 0, b = w.size();
        if (lead) while (a < b && w[a] == '_') ++a;
        if (need_lead && a == 0) return false;
        if (trail) while (b > a && w[b - 1] == '_') --b;
        return w.compare(a, b - a, core) == 0 && b - a == core.size();
    };
    std::string out;
    char last = 0;  // the last non-blank character kept
    for (size_t i = 0; i < text.size();) {
        const char c = text[i];
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            size_t j = i;
            while (j < text.size() && (std::isalnum(static_cast<unsigned char>(text[j])) || text[j] == '_')) ++j;
            const std::string w = text.substr(i, j - i);
            i = j;
            if (matches(w, "const", true, false, false) || matches(w, "volatile", true, true, false) ||
                matches(w, "restrict", true, false, true)) {
                out += ' ';
                continue;
            }
            if (w == "restrict" && last == '*') throw ParseError("Can't resolve datatype: restrict");
            out += w;
            last = w.back();
            continue;
        }
        out += c;
        if (!std::isspace(static_cast<unsigned char>(c))) last = c;
        ++i;
    }
    return out;
}

static bool installPieces(Funcdata *fd, const PrototypePieces &pieces, std::string &error)
{
    if (!validatePieces(pieces, error))
        return false;
    FuncProto &proto = fd->getFuncProto();
    proto.setPieces(pieces);
    if (proto.hasInputErrors() || proto.hasOutputErrors()) {
        error = "Prototype was not fully applied (calling convention '" +
                proto.getModelName() + "' could not represent every parameter)";
        return false;
    }
    return true;
}

bool Decompiler::setPrototype(uint64_t address, const std::string& prototype)
{
    if (impl_->arch == nullptr) {
        impl_->setError(EngineError::kInternal, "No binary loaded");
        return false;
    }

    try {
        const Address addr(impl_->arch->getDefaultCodeSpace(), (uintb)address);
        FunctionSymbol *sym = functionSymbolAt(impl_->arch, addr);
        if (sym == nullptr) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "no function at 0x%llx", (unsigned long long)address);
            return impl_->fail(EngineError::kNotFound, buf);
        }
        Funcdata *fd = sym->getFunction();

        // Parse the prototype string into PrototypePieces.
        // The C grammar requires a trailing semicolon for declarations.
        PrototypePieces pieces;
        std::istringstream ss(dropTypeQualifiers(prototype) + ";");
        parse_protopieces(pieces, ss, impl_->arch);
        // A prototype that names no calling convention keeps the function's own
        // (the host treats the parser's "unknown" as unspecified); the grammar
        // would otherwise substitute the default model.
        if (!namesCallingConvention(impl_->arch, prototype) && fd->getFuncProto().hasModel()) {
            if (ProtoModel *own = impl_->arch->getModel(fd->getFuncProto().getModelName()))
                pieces.model = own;
        }

        std::string error;
        if (!installPieces(fd, pieces, error))
            return impl_->fail(EngineError::kInvalid, error);
        impl_->functionState.prototypes[address] = {pieces, true};

        impl_->clearError();
        return true;

    } catch (ParseError &err) {
        return impl_->fail(EngineError::kParse, "Failed to parse prototype: " + err.explain);
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return false;
    } catch (std::exception &err) {
        impl_->setError(EngineError::kInternal, err.what());
        return false;
    }
}

// Rewrite one parameter of a function's current (locked) prototype in place,
// keeping every other piece -- model, return type, the other parameters'
// data types -- exactly as they are. Round-tripping through a C string would
// lose any type the C grammar cannot name back (e.g. two same-named program
// types from different categories).
static bool editParameter(Architecture *arch, ProjectFunctionState &state, uint64_t address,
                          int ordinal, const std::function<void(PrototypePieces &)> &edit,
                          std::string &error, EngineError &kind)
{
    kind = EngineError::kNotFound;
    FunctionSymbol *sym = functionSymbolAt(arch, Address(arch->getDefaultCodeSpace(), (uintb)address));
    Funcdata *fd = sym != nullptr ? sym->getFunction() : nullptr;
    if (fd == nullptr) {
        error = "No function at address";
        return false;
    }
    // Edit the saved prototype, not the Funcdata's copy: a decompile has reset
    // every size-locked "undefined" in that copy to the core undefined1.
    SavedPrototype next;
    auto saved = state.prototypes.find(address);
    if (saved != state.prototypes.end()) {
        next = saved->second;
    } else {
        fd->getFuncProto().getPieces(next.pieces);
        next.output_locked = fd->getFuncProto().isOutputLocked();
    }
    if (!fd->getFuncProto().isInputLocked() || ordinal < 0 ||
        ordinal >= static_cast<int>(next.pieces.intypes.size())) {
        error = "The function has no parameter " + std::to_string(ordinal);
        return false;
    }
    kind = EngineError::kInvalid;
    next.pieces.name = fd->getName();
    edit(next.pieces);
    if (next.custom) {
        // Custom storage: the parameter stays where the database put it.
        installSavedPrototype(fd, next);
    } else {
        // setPieces locks everything; an unlocked (DEFAULT) return stays unlocked.
        if (!installPieces(fd, next.pieces, error))
            return false;
        if (!next.output_locked)
            fd->getFuncProto().setOutputLock(false);
    }
    state.prototypes[address] = next;
    kind = EngineError::kNone;
    return true;
}

bool Decompiler::setParameterName(uint64_t address, int ordinal, const std::string& name)
{
    if (impl_->arch == nullptr) {
        impl_->setError(EngineError::kInternal, "No binary loaded");
        return false;
    }
    try {
        std::string error;
        EngineError kind = EngineError::kNone;
        if (!editParameter(impl_->arch, impl_->functionState, address, ordinal,
                           [&](PrototypePieces &p) { p.innames[ordinal] = name; },
                           error, kind))
            return impl_->fail(kind, error);
        impl_->clearError();
        return true;
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return false;
    }
}

bool Decompiler::setParameterType(uint64_t address, int ordinal, const std::string& type_name)
{
    if (impl_->arch == nullptr) {
        impl_->setError(EngineError::kInternal, "No binary loaded");
        return false;
    }
    try {
        Datatype *type = impl_->parseType(type_name);
        if (type == nullptr)
            return false;  // lastError set by parseType
        std::string error;
        EngineError kind = EngineError::kNone;
        if (!editParameter(impl_->arch, impl_->functionState, address, ordinal,
                           [&](PrototypePieces &p) { p.intypes[ordinal] = type; },
                           error, kind))
            return impl_->fail(kind, error);
        impl_->clearError();
        return true;
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
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
                                      std::vector<MemoryBlockInfo>& rva_blocks,
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
    uint32_t section_alignment = 0;
    uint32_t image_size = 0;
    uint32_t headers_size = 0;
    if (!read_pe_le(file, optional_offset, magic) ||
        !read_pe_le(file, optional_offset + 32, section_alignment) ||
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

    // The memory map Ghidra's PE loader builds (measured against a project
    // Ghidra imported from the same PE): a read-only "Headers" block over
    // SizeOfHeaders, then one block per section, VirtualSize (or
    // the raw size when it is 0) rounded up to SectionAlignment, with the
    // section's read/write/execute characteristics. Starts are RVAs here.
    rva_blocks.clear();
    auto align_up = [&](uint64_t v) {
        return section_alignment > 1
                   ? (v + section_alignment - 1) / section_alignment * section_alignment
                   : v;
    };
    if (headers_size > 0) {
        MemoryBlockInfo headers;
        headers.name = "Headers";
        headers.start = 0;
        headers.end = static_cast<uint64_t>(headers_size) - 1;
        headers.read = true;
        headers.initialized = true;
        rva_blocks.push_back(headers);
    }

    for (uint16_t i = 0; i < section_count; ++i) {
        const size_t section = section_table + static_cast<size_t>(i) * 40;
        uint32_t virtual_size = 0;
        uint32_t virtual_address = 0;
        uint32_t raw_size = 0;
        uint32_t raw_offset = 0;
        uint32_t characteristics = 0;
        if (!read_pe_le(file, section + 8, virtual_size) ||
            !read_pe_le(file, section + 12, virtual_address) ||
            !read_pe_le(file, section + 16, raw_size) ||
            !read_pe_le(file, section + 20, raw_offset) ||
            !read_pe_le(file, section + 36, characteristics)) {
            error = "Malformed PE image: incomplete section header";
            return PeImageStatus::Error;
        }
        const uint64_t block_size = align_up(virtual_size != 0 ? virtual_size : raw_size);
        if (block_size > 0 && virtual_address < mapped.size()) {
            MemoryBlockInfo blk;
            const char* name = reinterpret_cast<const char*>(file.data() + section);
            blk.name.assign(name, strnlen(name, 8));
            blk.start = virtual_address;
            blk.end = std::min<uint64_t>(virtual_address + block_size, mapped.size()) - 1;
            blk.read = (characteristics & 0x40000000u) != 0;
            blk.write = (characteristics & 0x80000000u) != 0;
            blk.execute = (characteristics & 0x20000000u) != 0;
            blk.initialized = true;
            rva_blocks.push_back(blk);
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

// The decompiler scope of a project namespace, created on first use with the
// Ghidra symbol id as its scope id (what the host's decompiler interface uses).
// Global namespace = 0. A chain deeper than any real program is cut off at the
// global scope rather than recursing on a malformed parent loop.
static Scope *projectScope(Architecture *arch, const ghidra_db::ProjectData &data,
                           int64_t id, int depth = 0)
{
    Scope *global = arch->symboltab->getGlobalScope();
    if (id == 0 || depth > 64) return global;
    auto it = data.namespaces.find(id);
    if (it == data.namespaces.end() || it->second.name.empty()) return global;
    Scope *parent = projectScope(arch, data, it->second.parent_id, depth + 1);
    return arch->symboltab->findCreateScope(static_cast<uint8>(id), it->second.name, parent);
}

// Name every project function in its own namespace. A namespaced function's
// body ranges are given to its scope, so an address lookup from anywhere
// (Scope::queryFunction resolves through Database::mapScope) still finds it.
static void applyProjectFunctions(Architecture *arch, const ghidra_db::ProjectData &data,
                                  std::set<uint64_t> &external_stubs)
{
    AddrSpace *code = arch->getDefaultCodeSpace();
    for (const auto &func : data.functions) {
        if (func.name.empty()) continue;
        Scope *scope = projectScope(arch, data, func.namespace_id);
        FunctionSymbol *sym = scope->addFunction(Address(code, (uintb)func.address), func.name);
        scope->setAttribute(sym, Varnode::namelock);
        if (scope == arch->symboltab->getGlobalScope()) continue;
        for (const auto &[first, last] : func.body)
            arch->symboltab->addRange(scope, code, (uintb)first, (uintb)last);
    }

    // A function's call fixup replaces every call to it with the compiler
    // spec's p-code (FunctionPrototype.injectname on the host), e.g.
    // __security_check_cookie -> security_check_cookie.
    Scope *global = arch->symboltab->getGlobalScope();
    for (const auto &[entry, name] : data.call_fixups) {
        Funcdata *fd = global->queryFunction(Address(code, (uintb)entry));
        if (fd == nullptr) continue;
        const int4 id = arch->pcodeinjectlib->getPayloadId(InjectPayload::CALLFIXUP_TYPE, name);
        if (id >= 0) fd->getFuncProto().setInjectId(id);
    }

    // External function pointers (import slots): the host answers a lookup
    // of the slot with an external reference whose function lives at the slot
    // itself (DecompileCallback.encodeExternalRef), so a call through it is a
    // call to that function with its signature. The stub function is not a
    // program function; listings skip it.
    for (const auto &ext : data.external_refs) {
        const Address slot(code, (uintb)ext.address);
        if (global->queryFunction(slot) != nullptr) continue;
        FunctionSymbol *sym = global->addFunction(slot, ext.name);
        global->setAttribute(sym, Varnode::namelock);
        global->addExternalRef(slot, slot, ext.name);
        external_stubs.insert(ext.address);
    }

    // Instruction flow overrides, given to every function whose body holds
    // the instruction (the host applies them in the instruction's p-code).
    // Funcdata::clear keeps overrides, so once is enough.
    static const char *const kFlow[] = {"", "branch", "call", "callreturn", "return"};
    for (const auto &func : data.functions) {
        Funcdata *fd = nullptr;
        for (const auto &[first, last] : func.body) {
            for (auto it = data.flow_overrides.lower_bound(first);
                 it != data.flow_overrides.end() && it->first <= last; ++it) {
                if (it->second < 1 || it->second > 4) continue;
                if (fd == nullptr) fd = global->queryFunction(Address(code, (uintb)func.address));
                if (fd == nullptr) break;
                fd->getOverride().insertFlowOverride(Address(code, (uintb)it->first),
                                                     kFlow[it->second]);
            }
        }
    }
}

// The program context's register values, as the host's getTrackedRegisters
// answers for an address: every register holding a value there, beside the
// processor spec's own tracked registers (e.g. GS_OFFSET, so a GS-relative load
// resolves to the thread block).
static void applyRegisterValues(Architecture *arch,
                                const std::vector<ghidra_db::RegisterValueEntry> &values)
{
    if (values.empty()) return;
    AddrSpace *code = arch->getDefaultCodeSpace();
    struct Reg {
        VarnodeData loc;
        uint64_t first, last, value;
    };
    std::vector<Reg> regs;
    std::set<uint64_t> cuts;
    for (const auto &v : values) {
        const VarnodeData &loc = arch->translate->getRegister(v.reg);
        if (loc.space == nullptr || loc.space->getType() != IPTR_PROCESSOR) continue;
        regs.push_back({loc, v.first, v.last, v.value});
        cuts.insert(v.first);
        if (v.last != UINT64_MAX) cuts.insert(v.last + 1);
    }
    if (regs.empty()) return;
    // One tracked set per interval between consecutive range ends.
    std::vector<uint64_t> points(cuts.begin(), cuts.end());
    for (size_t i = 0; i < points.size(); ++i) {
        const uint64_t first = points[i];
        const uint64_t last = i + 1 < points.size() ? points[i + 1] - 1 : UINT64_MAX;
        TrackedSet set = arch->context->getTrackedSet(Address(code, first));
        bool any = false;
        for (const Reg &r : regs) {
            if (first < r.first || first > r.last) continue;
            any = true;
            bool replaced = false;
            for (TrackedContext &t : set) {
                if (t.loc.space == r.loc.space && t.loc.offset == r.loc.offset && t.loc.size == r.loc.size) {
                    t.val = r.value;
                    replaced = true;
                }
            }
            if (!replaced) set.push_back({r.loc, r.value});
        }
        if (!any) continue;
        const uintb end = last >= code->getHighest() ? code->getHighest() : last + 1;
        TrackedSet &dest = arch->context->createSet(Address(code, first), Address(code, end));
        dest = set;
    }
}

bool Decompiler::loadProject(const std::string& gpr_path, const std::string& program)
{
    std::lock_guard<std::recursive_mutex> setup(engine_setup_mutex());
    ghidra_db::GhidraProject proj;
    if (!proj.open(gpr_path, program))
        return impl_->fail(proj.isNotFound() ? EngineError::kNotFound : EngineError::kInvalid,
                           "Failed to open project: " + proj.getError());

    ghidra_db::ProjectData data = proj.extract();
    if (data.info.language_id.empty()) {
        impl_->setError(EngineError::kInternal, "No language ID found in project. " + proj.getError());
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
        if (span > kMaxFlatImageBytes)
            return impl_->fail(EngineError::kInvalid,
                               "Offline project image span too large to flatten (" +
                                   std::to_string(span) +
                                   " bytes); sparse/high-VA layout unsupported");
        std::vector<uint8_t> flat(span);
        img.readBytes(base, flat.data(), span);

        std::string temp = write_scratch_image(flat);
        if (temp.empty()) {
            impl_->setError(EngineError::kInternal, "Failed to create scratch image for offline project load");
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
        std::vector<ghidra_db::MemoryImage::Run> runs = img.outsideImage();
        if (!runs.empty())
            impl_->arch->loader = new ProjectRunsLoadImage(impl_->arch->loader, std::move(runs));
    } else {
        // Fallback: the project carries no File Bytes (older/raw import). Raw-load
        // the executable the project was imported from.
        const std::string binary_path = data.info.exe_path;
        if (binary_path.empty()) {
            impl_->setError(EngineError::kInternal, "Project has no image bytes (" + proj.getError() +
                               ") and no executable path/override to fall back on");
            return false;
        }
        if (!loadBinary(binary_path, data.info.language_id)) {
            return false; // lastError already set
        }
    }

    // Apply function names from the project (skip empty names — auto-generated),
    // each in its own namespace, as the host's decompiler sees them: a
    // `__scrt_narrow_argv_policy::configure_argv` is declared qualified.
    try {
        applyProjectFunctions(impl_->arch, data, impl_->externalStubs);
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, "Failed to apply project functions: " + err.explain);
        return false;
    }

    // The saved signatures, over the program's own data types: what the live
    // host hands its decompiler. Without this every function is `void f()`.
    std::map<uint64_t, Datatype *> dataTypes;
    try {
        applyProjectSignatures(impl_->arch, data, impl_->typeCategories, impl_->functionState,
                               &dataTypes);
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, "Failed to apply saved signatures: " + err.explain);
        return false;
    }

    for (const auto& [id, t] : data.types.types) {
        if (t.kind == ghidra_db::DataTypeKind::BUILT_IN && !t.name.empty())
            impl_->builtinTypeIds.emplace(t.name, static_cast<uint64_t>(id));
        if (t.kind == ghidra_db::DataTypeKind::COMPOSITE && t.pack >= 0)
            impl_->packing[static_cast<uint64_t>(id)] = t.pack;
    }

    for (auto& func : data.functions)
        if (func.is_thunk) impl_->projectThunks.insert(func.address);

    for (const auto& func : data.functions) {
        impl_->projectEntries.insert(func.address);
        for (const auto& [first, last] : func.body)
            impl_->projectBodies[first] = {last, func.address};
    }
    impl_->hasInstructionIndex = data.has_instruction_index;
    impl_->instructionStarts = std::move(data.instruction_starts);
    impl_->projectLoaded = true;

    // The project's own memory map replaces the one the scratch load derived:
    // the blocks of the code space (an overlay space is not this space), as the
    // host lists them. Read even when the db carries no image bytes.
    impl_->blocks.clear();
    const std::string code_space = impl_->arch->getDefaultCodeSpace()->getName();
    for (const auto& b : img.blocks()) {
        if (b.length == 0 || (!b.space.empty() && b.space != code_space)) continue;
        MemoryBlockInfo blk;
        blk.name = b.name;
        blk.start = b.start;
        blk.end = b.start + b.length - 1;
        blk.read = (b.flags & ghidra_db::MemoryImage::kRead) != 0;
        blk.write = (b.flags & ghidra_db::MemoryImage::kWrite) != 0;
        blk.execute = (b.flags & ghidra_db::MemoryImage::kExecute) != 0;
        blk.is_volatile = (b.flags & ghidra_db::MemoryImage::kVolatile) != 0;
        blk.initialized = b.initialized;
        blk.source_name = b.source_name;
        blk.comment = b.comment;
        impl_->blocks.push_back(std::move(blk));
    }

    // Memory properties and the listing (labels, data, comments, bookmarks,
    // tags), as the host's DecompileCallback hands them to its decompiler.
    try {
        applyRegisterValues(impl_->arch, data.register_values);
        impl_->applyMemoryProperties(data.written);
        Architecture *arch = impl_->arch;
        impl_->listing.load(data, dataTypes, impl_->blocks, [&](int64_t id) {
            return projectScope(arch, data, id);
        });
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, "Failed to load the program listing: " + err.explain);
        return false;
    }

    if (data.has_reference_index) {
        std::vector<uint64_t> leaves;
        for (auto& func : data.functions)
            if (!func.makes_call) leaves.push_back(func.address);
        std::sort(leaves.begin(), leaves.end());
        impl_->projectLeaves = std::move(leaves);
    }

    impl_->clearError();
    return true;
}

const std::map<uint64_t, std::string>& Decompiler::typeCategories() const
{
    return impl_->typeCategories;
}

const std::set<uint64_t>& Decompiler::projectThunks() const
{
    return impl_->projectThunks;
}

const std::set<uint64_t>& Decompiler::externalStubs() const
{
    return impl_->externalStubs;
}

bool Decompiler::isProjectLoaded() const
{
    return impl_->projectLoaded;
}

std::optional<uint64_t> Decompiler::projectFunctionContaining(uint64_t address) const
{
    if (!impl_->projectLoaded) return std::nullopt;
    if (impl_->projectEntries.count(address) != 0) return address;
    auto it = impl_->projectBodies.upper_bound(address);
    if (it == impl_->projectBodies.begin()) return std::nullopt;
    --it;
    if (address > it->second.first) return std::nullopt;
    return it->second.second;
}

bool Decompiler::projectInstructionAt(uint64_t address) const
{
    if (!impl_->projectLoaded || !impl_->hasInstructionIndex) return true;
    return std::binary_search(impl_->instructionStarts.begin(),
                              impl_->instructionStarts.end(), address);
}

std::optional<uint64_t> Decompiler::projectInstructionAtOrBefore(uint64_t address) const
{
    if (!impl_->projectLoaded || !impl_->hasInstructionIndex) return std::nullopt;
    auto it = std::upper_bound(impl_->instructionStarts.begin(),
                               impl_->instructionStarts.end(), address);
    if (it == impl_->instructionStarts.begin()) return std::nullopt;
    return *(it - 1);
}

const std::vector<MemoryBlockInfo>& Decompiler::memoryBlocks() const
{
    return impl_->blocks;
}

const MemoryBlockInfo* Decompiler::blockAt(uint64_t address) const
{
    auto it = std::upper_bound(impl_->blocks.begin(), impl_->blocks.end(), address,
                               [](uint64_t a, const MemoryBlockInfo& b) { return a < b.start; });
    if (it == impl_->blocks.begin()) return nullptr;
    --it;
    return address <= it->end ? &*it : nullptr;
}

void Decompiler::prepareFunction(Funcdata* fd) const
{
    if (fd != nullptr) prepareSavedFunction(fd, impl_->functionState);
}

const PrototypePieces* Decompiler::savedPrototype(uint64_t entry, bool* output_locked) const
{
    auto it = impl_->functionState.prototypes.find(entry);
    if (it == impl_->functionState.prototypes.end()) return nullptr;
    if (output_locked != nullptr) *output_locked = it->second.output_locked;
    return &it->second.pieces;
}

std::string Decompiler::savedModelName(uint64_t entry) const
{
    auto it = impl_->functionState.default_models.find(entry);
    return it != impl_->functionState.default_models.end() && it->second != nullptr
               ? it->second->getName()
               : std::string();
}

bool Decompiler::savedStateUses(const Datatype* type) const
{
    for (const auto& [entry, saved] : impl_->functionState.prototypes) {
        if (saved.pieces.outtype == type) return true;
        for (const Datatype* in : saved.pieces.intypes)
            if (in == type) return true;
    }
    for (const auto& [entry, locals] : impl_->functionState.locals)
        for (const SavedLocal& local : locals)
            if (local.type == type) return true;
    return false;
}

bool Decompiler::projectLeafEntries(std::vector<uint64_t>& out) const
{
    if (!impl_->projectLeaves) return false;
    out = *impl_->projectLeaves;
    return true;
}

std::optional<uint64_t> Decompiler::Impl::functionContaining(uint64_t address) const
{
    if (arch == nullptr) return std::nullopt;
    if (functionAt(address)) return address;
    if (!projectLoaded) return std::nullopt;
    auto it = projectBodies.upper_bound(address);
    if (it == projectBodies.begin()) return std::nullopt;
    --it;
    if (address > it->second.first) return std::nullopt;
    return it->second.second;
}

bool Decompiler::Impl::functionAt(uint64_t address) const
{
    if (arch == nullptr || externalStubs.count(address) != 0) return false;
    return functionSymbolAt(arch, Address(arch->getDefaultCodeSpace(), (uintb)address)) != nullptr;
}

// ---------------------------------------------------------------------------
// Program listing: labels, data, comments, bookmarks, function tags
// ---------------------------------------------------------------------------

std::vector<LabelInfo> Decompiler::labels(uint64_t first, uint64_t last) const
{
    return impl_->listing.labels(first, last);
}

std::optional<LabelInfo> Decompiler::primaryLabel(uint64_t address) const
{
    return impl_->listing.primaryLabel(address);
}

std::optional<LabelInfo> Decompiler::dynamicSymbol(uint64_t address) const
{
    return impl_->listing.dynamicSymbol(address);
}

std::vector<std::pair<LabelInfo, bool>> Decompiler::externalSymbols(uint64_t first, uint64_t last) const
{
    return impl_->listing.externalSymbols(first, last);
}

bool Decompiler::isExternalEntryPoint(uint64_t address) const
{
    return impl_->listing.isEntryPoint(address);
}

bool Decompiler::functionStartsAt(uint64_t address) const
{
    return impl_->functionAt(address);
}

bool Decompiler::renameSymbolAt(uint64_t address, const std::optional<std::string>& old_name,
                                const std::string& new_name)
{
    if (impl_->arch == nullptr)
        return impl_->fail(EngineError::kInternal, "No binary loaded");
    try {
        const Address addr(impl_->arch->getDefaultCodeSpace(), (uintb)address);
        FunctionSymbol *fn = impl_->functionAt(address) ? functionSymbolAt(impl_->arch, addr) : nullptr;
        if (old_name) {
            if (fn != nullptr) {
                const std::string ns = libghidra::detail::namespace_path(fn->getScope());
                if (fn->getName() == *old_name || (ns != "Global" && ns + "::" + fn->getName() == *old_name))
                    return renameFunction(address, new_name);
            }
            if (impl_->listing.renameLabel(address, *old_name, new_name)) {
                impl_->clearError();
                return true;
            }
            char buf[64];
            std::snprintf(buf, sizeof buf, "' at 0x%llx", (unsigned long long)address);
            return impl_->fail(EngineError::kNotFound, "no symbol named '" + *old_name + buf);
        }
        // The primary symbol: a function's own, else the primary label (created
        // when the address has none, the host's upsert).
        if (fn != nullptr) return renameFunction(address, new_name);
        impl_->listing.renameOrCreatePrimary(address, new_name);
        impl_->clearError();
        return true;
    } catch (LowlevelError &err) {
        return impl_->fail(EngineError::kInternal, err.explain);
    }
}

bool Decompiler::createLabel(uint64_t address, const std::string& name)
{
    if (impl_->arch == nullptr)
        return impl_->fail(EngineError::kInternal, "No binary loaded");
    try {
        if (impl_->functionAt(address)) {
            const Address addr(impl_->arch->getDefaultCodeSpace(), (uintb)address);
            FunctionSymbol *fn = functionSymbolAt(impl_->arch, addr);
            char def[40];
            std::snprintf(def, sizeof def, "FUN_%08llx", (unsigned long long)address);
            // SymbolManager.tryUpdatingDefaultFunction: a default-named function
            // takes the label's name rather than gaining a label.
            if (fn != nullptr && fn->getName() == def) return renameFunction(address, name);
        }
        impl_->listing.addLabel(address, name);
        impl_->clearError();
        return true;
    } catch (LowlevelError &err) {
        return impl_->fail(EngineError::kInternal, err.explain);
    }
}

uint32_t Decompiler::deleteSymbolsAt(uint64_t address, const std::string& name)
{
    if (impl_->arch == nullptr) return 0;
    uint32_t changed = 0;
    try {
        const Address addr(impl_->arch->getDefaultCodeSpace(), (uintb)address);
        if (impl_->functionAt(address)) {
            FunctionSymbol *fn = functionSymbolAt(impl_->arch, addr);
            const std::string ns = libghidra::detail::namespace_path(fn->getScope());
            const bool match = name.empty() || fn->getName() == name ||
                               (ns != "Global" && ns + "::" + fn->getName() == name);
            char def[40];
            std::snprintf(def, sizeof def, "FUN_%08llx", (unsigned long long)address);
            // The function stays; only its name goes back to the default.
            if (match && fn->getName() != def) {
                fn->getScope()->renameSymbol(fn, def);
                fn->getFunction()->setName(def);
                impl_->listing.setFunctionSource(address, false);
                ++changed;
            }
        }
        changed += impl_->listing.removeLabels(address, name);
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
    }
    return changed;
}

bool Decompiler::hasDataAt(uint64_t address) const
{
    return impl_->listing.hasDataAt(address);
}

std::vector<DataItemInfo> Decompiler::dataItems(uint64_t first, uint64_t last) const
{
    return impl_->listing.dataItems(first, last);
}

uint64_t Decompiler::functionSymbolId(uint64_t entry) const
{
    return impl_->listing.functionId(entry);
}

std::string Decompiler::functionSymbolSource(uint64_t entry) const
{
    return impl_->listing.functionSource(entry);
}

bool Decompiler::defineData(uint64_t address, Datatype* type)
{
    if (impl_->arch == nullptr)
        return impl_->fail(EngineError::kInternal, "No binary loaded");
    try {
        impl_->listing.defineData(address, type);
        impl_->clearError();
        return true;
    } catch (LowlevelError &err) {
        return impl_->fail(EngineError::kInternal, err.explain);
    }
}

bool Decompiler::clearData(uint64_t address)
{
    if (impl_->arch == nullptr) return false;
    try {
        return impl_->listing.clearData(address);
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return false;
    }
}

std::vector<ListingComment> Decompiler::comments(uint64_t first, uint64_t last) const
{
    return impl_->listing.comments(first, last);
}

void Decompiler::setComment(uint64_t address, int type, const std::string& text)
{
    if (impl_->arch != nullptr) impl_->listing.setComment(address, type, text);
}

bool Decompiler::deleteComment(uint64_t address, int type)
{
    return impl_->arch != nullptr && impl_->listing.deleteComment(address, type);
}

std::vector<BookmarkInfo> Decompiler::bookmarks() const
{
    return impl_->listing.bookmarks();
}

void Decompiler::setBookmark(uint64_t address, const std::string& type,
                             const std::string& category, const std::string& comment)
{
    impl_->listing.setBookmark(address, type, category, comment);
}

bool Decompiler::removeBookmark(uint64_t address, const std::string& type,
                                const std::string& category)
{
    return impl_->listing.removeBookmark(address, type, category);
}

bool Decompiler::removeBookmarks(uint64_t address, const std::string& type)
{
    return impl_->listing.removeBookmarks(address, type);
}

std::vector<FunctionTagInfo> Decompiler::functionTags() const
{
    return impl_->listing.functionTags();
}

bool Decompiler::hasFunctionTag(const std::string& name) const
{
    return impl_->listing.hasFunctionTag(name);
}

std::vector<std::pair<uint64_t, std::string>> Decompiler::functionTagMappings(uint64_t entry) const
{
    return impl_->listing.tagMappings(entry);
}

bool Decompiler::functionHasTag(uint64_t entry, const std::string& name) const
{
    return impl_->listing.functionHasTag(entry, name);
}

void Decompiler::createFunctionTag(const std::string& name, const std::string& comment)
{
    impl_->listing.createFunctionTag(name, comment);
}

bool Decompiler::deleteFunctionTag(const std::string& name)
{
    return impl_->listing.deleteFunctionTag(name);
}

void Decompiler::tagFunction(uint64_t entry, const std::string& name)
{
    impl_->listing.tagFunction(entry, name);
}

bool Decompiler::untagFunction(uint64_t entry, const std::string& name)
{
    return impl_->listing.untagFunction(entry, name);
}

// ---------------------------------------------------------------------------
// State Persistence
// ---------------------------------------------------------------------------

bool Decompiler::saveState(const std::string& filepath)
{
    if (impl_->arch == nullptr) {
        impl_->setError(EngineError::kInternal, "No binary loaded");
        return false;
    }

    try {
        std::ofstream fs(filepath);
        if (!fs) {
            impl_->setError(EngineError::kInternal, "Unable to open file for writing: " + filepath);
            return false;
        }

        XmlEncode encoder(fs);
        impl_->arch->encode(encoder);
        fs.close();

        impl_->clearError();
        return true;

    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return false;
    } catch (std::exception &err) {
        impl_->setError(EngineError::kInternal, err.what());
        return false;
    }
}

bool Decompiler::loadState(const std::string& filepath)
{
    std::lock_guard<std::recursive_mutex> setup(engine_setup_mutex());
    if (impl_->arch == nullptr) {
        impl_->setError(EngineError::kInternal, "No binary loaded (load a binary first, then restore state)");
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
        registerTypeNameAliases(impl_->arch);

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

        impl_->clearError();
        return true;

    } catch (DecoderError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return false;
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return false;
    } catch (std::exception &err) {
        impl_->setError(EngineError::kInternal, err.what());
        return false;
    }
}

// ---------------------------------------------------------------------------
// Output Control
// ---------------------------------------------------------------------------

bool Decompiler::setPrintLanguage(const std::string& language)
{
    if (impl_->arch == nullptr) {
        impl_->setError(EngineError::kInternal, "No binary loaded");
        return false;
    }

    try {
        impl_->arch->setPrintLanguage(language);

        impl_->clearError();
        return true;

    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
        return false;
    } catch (std::exception &err) {
        impl_->setError(EngineError::kInternal, err.what());
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
        impl_->setError(EngineError::kInternal, "No binary loaded");
        return result;
    }

    try {
        libghidra::detail::for_each_namespace_scope(
            impl_->arch->symboltab->getGlobalScope(), [&](Scope *scope) {
                for (MapIterator it = scope->begin(); it != scope->end(); ++it) {
                    const SymbolEntry *entry = *it;
                    const FunctionSymbol *fsym =
                        dynamic_cast<const FunctionSymbol *>(entry->getSymbol());
                    // Dynamic (hash-identified) storage has no address to report.
                    const auto *mapped = libghidra::detail::as_map_entry(entry);
                    if (fsym == nullptr || mapped == nullptr) continue;
                    if (impl_->externalStubs.count(mapped->getAddr().getOffset())) continue;
                    FunctionInfo fi;
                    fi.name = fsym->getName();
                    fi.address = mapped->getAddr().getOffset();
                    fi.size = fsym->getBytesConsumed();
                    result.push_back(std::move(fi));
                }
            });
        std::sort(result.begin(), result.end(),
                  [](const FunctionInfo &a, const FunctionInfo &b) { return a.address < b.address; });
        impl_->clearError();
    } catch (LowlevelError &err) {
        impl_->setError(EngineError::kInternal, err.explain);
    } catch (std::exception &err) {
        impl_->setError(EngineError::kInternal, err.what());
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
