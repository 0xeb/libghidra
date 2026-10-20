// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once
#include <string>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#ifndef GHIDRA_API
#define GHIDRA_API
#endif

namespace ghidra {
class Datatype;
class Funcdata;
class TypeField;
struct PrototypePieces;
}  // namespace ghidra

namespace ghidra_standalone {

struct FunctionInfo {
    std::string name;
    uint64_t address;
    uint64_t size;
};

/// Definition of a single field within a struct type.
struct FieldDef {
    std::string name;
    std::string type_name;   // C-style: "int", "char*", "uint4", etc.
    int offset;              // byte offset within struct
};

/// Definition of a single named value within an enum type.
struct EnumValue {
    std::string name;
    uint64_t value;
};

/// Definition of a function parameter (name + type).
struct ParamDef {
    std::string name;
    std::string type_name;
};

/// One memory block of the loaded program: a row of Program.getMemory()
/// .getBlocks() on the live host. An address is mapped exactly when a block
/// contains it.
struct MemoryBlockInfo {
    std::string name;
    uint64_t start = 0;
    uint64_t end = 0;               // inclusive
    bool read = false;
    bool write = false;
    bool execute = false;
    bool is_volatile = false;
    bool initialized = false;       // the block holds bytes
    std::string source_name;
    std::string comment;
};

/// A label (a non-function symbol of the symbol table), as the host reports it.
struct LabelInfo {
    uint64_t id = 0;
    uint64_t address = 0;
    std::string name;
    std::string namespace_path;   // Namespace.getName(true); "Global" at the top
    bool primary = false;
    std::string source;           // SourceType.name(): USER_DEFINED, IMPORTED, ...
};

/// A comment of the listing, by CommentType ordinal (0 EOL, 1 PRE, 2 POST,
/// 3 PLATE, 4 REPEATABLE).
struct ListingComment {
    uint64_t address = 0;
    int type = 0;
    std::string text;
};

struct BookmarkInfo {
    uint64_t address = 0;
    std::string type;
    std::string category;
    std::string comment;
};

/// A defined data item: its type and the name of its primary label ("" when
/// it has none, as the host's ListDataItems reports it).
struct DataItemInfo {
    uint64_t address = 0;
    ghidra::Datatype* type = nullptr;
    std::string name;
    int length = 0;   // Data.getLength(): the type's size, unless it outgrew its room
};

struct FunctionTagInfo {
    std::string name;
    std::string comment;
};

/// Why the last call failed, so callers can answer with the right error code
/// instead of guessing from a message.
enum class EngineError {
    kNone,
    kNotFound,      // the call names something that does not exist (a function)
    kParse,         // text the call carries (a prototype) does not parse
    kUnknownType,   // a type named as an argument does not resolve
    kInvalid,       // the request cannot be applied as asked
    kInternal,      // the engine failed
};

class GHIDRA_API Decompiler {
public:
    /// Initialize using embedded spec files (no Ghidra source tree needed).
    /// Extracts bundled .sla/.pspec/.cspec files to a temp directory automatically.
    /// Only available when linked with ghidra_cpp (which includes embedded specs).
    Decompiler();

    /// Initialize with path to Ghidra root (for .sla/.pspec/.cspec files).
    /// This is typically the ghidra/ submodule directory.
    explicit Decompiler(const std::string& ghidra_root);
    ~Decompiler();

    Decompiler(const Decompiler&) = delete;
    Decompiler& operator=(const Decompiler&) = delete;

    /// Load a binary file. arch is a language id like "x86:LE:64:default".
    /// If empty, the format/architecture will be auto-detected. Raw loaders
    /// map structured images into virtual-address layout and place them at
    /// base_address; use format="raw" for an already-flat image.
    bool loadBinary(const std::string& filepath, const std::string& arch = "",
                    uint64_t base_address = 0,
                    const std::string& format = "");

    /// Decompile the function at the given address, returning C source.
    std::string decompileAt(uint64_t address);

    /// Get the last error message.
    std::string getError() const;

    /// Why the last failing call failed (kNone after a success).
    EngineError getErrorKind() const;

    // ----- Type Creation -----

    /// Create a new struct type in the root category. Fields specify name, C
    /// type string, and byte offset. Fails (kInvalid) when a type of that name
    /// exists: an existing type is edited in place, never replaced.
    bool defineStruct(const std::string& name, const std::vector<FieldDef>& fields, int size = 0);

    /// Create a new enum type (4-byte by default) in the root category. Fails
    /// (kInvalid) when a type of that name exists.
    bool defineEnum(const std::string& name, const std::vector<EnumValue>& values, int size = 4);

    /// Create a new, empty union in the root category. Fails (kInvalid) when a
    /// type of that name exists.
    bool defineUnion(const std::string& name);

    /// Replace an existing composite in place with the fields a parse gave it
    /// (`parsed` holds its new size and alignment); false with `error` when it
    /// cannot be done. The caller lays out what holds it again.
    using ReplaceComposite = std::function<bool(ghidra::Datatype* existing, ghidra::Datatype* parsed,
                                                const std::vector<ghidra::TypeField>& fields,
                                                std::string& error)>;
    /// Parse C declarations (structs, unions, enums, typedefs, functions) into
    /// the program's types as Ghidra's CParser reads them, all or nothing: on a
    /// syntax or type error (kParse) every type the text had created is removed
    /// again. A definition of an existing composite goes through `replace` (in
    /// place without it). `created` receives the paths of the new types.
    bool parseDeclarations(const std::string& text, std::vector<std::string>& created,
                           const ReplaceComposite& replace = ReplaceComposite());

    /// The Ghidra data type id of `type` as the host reports it
    /// (DataTypeManager.getID): its program type id, or the program's
    /// built-in id of that name; 0 when the program holds none.
    uint64_t ghidraTypeId(const ghidra::Datatype* type) const;

    /// The structure of this decompiler type id packs its fields
    /// (Composite "Pack" >= 0): no undefined bytes between them.
    bool isPackedType(uint64_t id) const;
    /// The packing of composite `id` (Composite.getPackingType): -1 disabled,
    /// 0 default, > 0 an explicit pack value.
    int packing(uint64_t id) const;
    /// Record the packing of a composite this session created (-1 disables it).
    void setPacking(uint64_t id, int pack);
    /// Bring every defined data item's symbol to its data type's new size
    /// after a type edit changed it (CodeManager.dataTypeChanged).
    void refreshDataSizes();

    // ----- Symbol Management -----

    /// Rename the function whose entry is `entry`, in the namespace that holds
    /// it. Fails (kNotFound) when no function starts there: a rename never
    /// creates a function.
    bool renameFunction(uint64_t entry, const std::string& name);

    /// Create a function at `address` in the global namespace and lock its
    /// name. Fails (kInvalid) when a function already starts there. The one
    /// function-creation path (CreateFunction): renames and prototype edits
    /// never reach it.
    bool defineFunction(uint64_t address, const std::string& name);

    /// Rename any symbol (function, global, local).
    bool renameSymbol(const std::string& old_name, const std::string& new_name);

    /// Retype any symbol with a C type string.
    bool retypeSymbol(const std::string& symbol_name, const std::string& type_name);

    /// Mark an address range as containing global variables.
    bool addGlobalRange(uint64_t address, uint64_t size);

    // ----- Function Prototypes -----

    /// Set the prototype of the function whose entry is `address`, from a
    /// C-style declaration string, e.g. "int process_packet(char* data, int
    /// length)". Fails (kNotFound) when no function starts there, (kParse) when
    /// the declaration does not parse, (kInvalid) when the calling convention
    /// cannot place it.
    bool setPrototype(uint64_t address, const std::string& prototype);

    /// Rename / retype one parameter of a function's current prototype in
    /// place, keeping the model, return type and every other parameter as is.
    /// Fails (kNotFound) when the function has no such parameter, (kUnknownType)
    /// when the new type does not resolve.
    bool setParameterName(uint64_t address, int ordinal, const std::string& name);
    bool setParameterType(uint64_t address, int ordinal, const std::string& type_name);

    // ----- Project Loading -----

    /// Load the program `program` of a Ghidra project (.gpr file) directly:
    /// its project path ("/program.exe") or bare name, or empty for the
    /// project's only program. Fails (kNotFound) when the project or program
    /// does not exist. The program bytes come from the project db itself (the
    /// reconstructed memory image), so no external binary is needed and offline
    /// decompilation reads correct bytes at real virtual addresses. If the db
    /// carries no image bytes (older/raw import), falls back to raw-loading the
    /// executable path the project recorded.
    bool loadProject(const std::string& gpr_path, const std::string& program = "");

    /// Entry points of the functions the loaded project records as leaves: no
    /// reference from their body has a call RefType, read from Ghidra's own
    /// reference index -- the live host's rule, not the decompiler's call graph.
    /// Returns false (out untouched) unless the program came from loadProject()
    /// on a project db carrying that index.
    bool projectLeafEntries(std::vector<uint64_t>& out) const;

    /// Ghidra category path of each program data type loadProject() loaded,
    /// keyed by decompiler type id (= the Ghidra data type id). Empty for a
    /// bare binary.
    const std::map<uint64_t, std::string>& typeCategories() const;

    /// Entry points of the functions the loaded project records as thunks (their
    /// own "Thunk Functions" row, FunctionDB.isThunk). Empty for a bare binary.
    const std::set<uint64_t>& projectThunks() const;

    /// Import-slot addresses where loadProject placed an external function
    /// stub (so calls through the slot resolve). Not program functions:
    /// listings leave them out.
    const std::set<uint64_t>& externalStubs() const;

    /// True once loadProject() loaded a program database: the program's own
    /// function bodies and listing answer which function or instruction an
    /// address names, as they do on the live host.
    bool isProjectLoaded() const;

    /// Entry of the project function at `address`, else of the one whose body
    /// contains it (FunctionManager.getFunctionAt, then getFunctionContaining).
    /// nullopt when no project function covers the address, or for a bare binary.
    std::optional<uint64_t> projectFunctionContaining(uint64_t address) const;

    /// An instruction of the project's listing starts at `address`
    /// (Listing.getInstructionAt). Always true for a bare binary or a project
    /// db without an instruction table: then any decodable address counts.
    bool projectInstructionAt(uint64_t address) const;

    /// The start of the last listing instruction at or below `address`.
    /// nullopt for a bare binary, a project db without an instruction table, or
    /// an address below the first instruction.
    std::optional<uint64_t> projectInstructionAtOrBefore(uint64_t address) const;

    /// The program's memory blocks, in address order: the project's own memory
    /// map, or for a bare binary the PE's headers and sections (one block over
    /// the file for any other raw image). Empty when the loader gives no map.
    const std::vector<MemoryBlockInfo>& memoryBlocks() const;

    /// The block containing `address`, or nullptr when it is unmapped.
    const MemoryBlockInfo* blockAt(uint64_t address) const;

    /// Bring `fd` back to what the program database (and later edits) say
    /// before a decompile: the saved locked prototype, and the saved locals a
    /// previous clearAnalysis dropped. The live host rebuilds every function
    /// from its database the same way before each decompile.
    void prepareFunction(ghidra::Funcdata* fd) const;

    /// The saved locked prototype of the function at `entry` (loaded from a
    /// project or set through setPrototype / setParameterName / Type), or
    /// nullptr. A decompile rewrites the Funcdata's own copy, this one stays.
    const ghidra::PrototypePieces* savedPrototype(uint64_t entry, bool* output_locked) const;

    /// The calling convention a DEFAULT signature carries (a decompile may
    /// replace an unlocked one); empty when the function has none recorded.
    std::string savedModelName(uint64_t entry) const;

    /// A saved prototype or saved local refers to `type` itself (by value).
    /// Destroying or resizing such a type would corrupt every later decompile.
    bool savedStateUses(const ghidra::Datatype* type) const;

    // ----- Program listing (labels, data, comments, bookmarks, tags) -----
    //
    // Loaded from a project db and edited by the
    // write RPCs; the decompiler sees them as the host's DecompileCallback
    // hands them over (data symbols, global code labels, function comments).

    /// The labels in [first, last], in address (then symbol id) order.
    std::vector<LabelInfo> labels(uint64_t first, uint64_t last) const;
    /// The primary label at `address`, if it has one.
    std::optional<LabelInfo> primaryLabel(uint64_t address) const;
    /// The dynamic symbol Ghidra gives a referenced address that has no symbol
    /// of its own (DAT_..., LAB_..., a data item's default name).
    std::optional<LabelInfo> dynamicSymbol(uint64_t address) const;
    /// The program's EXTERNAL-space symbols with offsets in [first, last]; the
    /// bool says a function symbol (else a label).
    std::vector<std::pair<LabelInfo, bool>> externalSymbols(uint64_t first, uint64_t last) const;
    /// `address` is an external entry point (an export, the program entry).
    bool isExternalEntryPoint(uint64_t address) const;
    /// A program function (not an import-slot stub) starts at `address`.
    bool functionStartsAt(uint64_t address) const;
    /// Rename the symbol at `address` named `old_name` (function or label;
    /// kNotFound when there is none), or with no `old_name` the primary symbol,
    /// creating a primary label when the address has no symbol.
    bool renameSymbolAt(uint64_t address, const std::optional<std::string>& old_name,
                        const std::string& new_name);
    /// Add the label `name` at `address` (SymbolTable.createLabel): the address
    /// keeps its symbols and the label is primary only when it had none; a
    /// function that still has its default name takes `name` instead.
    bool createLabel(uint64_t address, const std::string& name);
    /// Delete the symbols at `address` named `name` (all when empty): labels
    /// go, a function's own name goes back to FUN_<address>. Returns how many
    /// changed.
    uint32_t deleteSymbolsAt(uint64_t address, const std::string& name);

    /// A defined data item starts at `address`.
    bool hasDataAt(uint64_t address) const;
    /// The defined data items starting in [first, last], in address order.
    std::vector<DataItemInfo> dataItems(uint64_t first, uint64_t last) const;
    /// The Ghidra symbol id of the function at `entry` (0 when unknown).
    uint64_t functionSymbolId(uint64_t entry) const;
    /// The SourceType name of the function symbol at `entry` ("" when unknown).
    std::string functionSymbolSource(uint64_t entry) const;
    /// Give `address` a data item of `type` (an existing one is retyped).
    bool defineData(uint64_t address, ghidra::Datatype* type);
    /// Clear the data item at `address`; false when there is none.
    bool clearData(uint64_t address);

    /// Comments in [first, last], in address then type order.
    std::vector<ListingComment> comments(uint64_t first, uint64_t last) const;
    void setComment(uint64_t address, int type, const std::string& text);
    bool deleteComment(uint64_t address, int type);

    /// Bookmarks, in type then id order.
    std::vector<BookmarkInfo> bookmarks() const;
    void setBookmark(uint64_t address, const std::string& type, const std::string& category,
                     const std::string& comment);
    bool removeBookmark(uint64_t address, const std::string& type, const std::string& category);
    bool removeBookmarks(uint64_t address, const std::string& type);

    std::vector<FunctionTagInfo> functionTags() const;
    bool hasFunctionTag(const std::string& name) const;
    /// (entry, tag name) pairs; `entry` 0 = every function.
    std::vector<std::pair<uint64_t, std::string>> functionTagMappings(uint64_t entry) const;
    bool functionHasTag(uint64_t entry, const std::string& name) const;
    void createFunctionTag(const std::string& name, const std::string& comment);
    bool deleteFunctionTag(const std::string& name);
    void tagFunction(uint64_t entry, const std::string& name);
    bool untagFunction(uint64_t entry, const std::string& name);

    // ----- State Persistence -----

    /// Save the full decompiler state (types, symbols, overrides) to XML.
    bool saveState(const std::string& filepath);

    /// Load a previously saved state from XML. Restores all types, symbols, overrides.
    bool loadState(const std::string& filepath);

    // ----- Output Control -----

    /// Set the output language: "c-language" (default) or "java-language".
    bool setPrintLanguage(const std::string& language);

    // ----- Enumeration -----

    /// List all functions currently known to the decompiler.
    /// Includes loader symbols (PE/ELF exports/imports), manually named functions,
    /// and functions discovered via project loading.
    std::vector<FunctionInfo> listFunctions();

    // ----- Memory Writes -----

    /// Write bytes at the given address using a copy-on-write overlay.
    /// The original image is never modified; reads through the overlay
    /// return patched bytes where written. The caller checks the range is
    /// mapped and readable first.
    void writeBytes(uint64_t address, const std::vector<uint8_t>& data);

    // ----- Advanced -----

    /// Get a raw pointer to the Architecture object for advanced users
    /// who want to use the Ghidra C++ API directly.
    void* getArchitecturePointer();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ghidra_standalone
