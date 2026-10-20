// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once
#include "program_types.h"

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include <cstdint>

#ifndef GHIDRA_API
#define GHIDRA_API
#endif

namespace ghidra_db {

struct ProjectInfo {
    std::string program_name;    // e.g. "nasm.exe"
    std::string exe_path;        // original binary path
    std::string language_id;     // e.g. "x86:LE:64:default"
    std::string compiler_spec;   // e.g. "windows"
};

// One piece of a variable's storage, parsed from Ghidra's VariableStorage
// serialization ("Stack[-0x10]:4", "register:10:8", "ram:140008000:4").
struct VarnodeEntry {
    std::string space;     // "stack", or the address space name ("register", "ram", ...)
    int64_t offset = 0;    // signed for the stack
    int size = 0;
};

// A saved local variable ("Symbols" row of type LOCAL_VAR) and its storage
// ("Variable Storage" row the symbol's variable address points at).
struct LocalVariableEntry {
    std::string name;          // Ghidra's display name (default local names resolved)
    // NULL_DATATYPE_ID when the symbol names none (VariableSymbolDB.getDataType
    // then reads an undefined of the storage size).
    int64_t type_id = NULL_DATATYPE_ID;
    int first_use = 0;         // first-use offset from the function entry
    std::vector<VarnodeEntry> storage;  // empty when unassigned or unparsable
};

struct FunctionEntry {
    std::string name;
    uint64_t address;
    int64_t symbol_id = 0;     // the function symbol's id ("Symbols" key)
    int source = 0;            // its SourceType storage id (see LabelEntry::source)
    // True when a reference FROM an address in the function's body has a call
    // RefType and a destination whose offset is non-zero -- the exact rule the
    // live host uses for ListLeafFunctions. Meaningful only when
    // ProjectData::has_reference_index is set.
    bool makes_call = false;
    // The function's own "Thunk Functions" row names a thunked function
    // (FunctionDB.isThunk) -- the function's own record, not its chain's end.
    bool is_thunk = false;
    // Symbol id of the parent namespace ("Symbols" column Namespace); 0 is the
    // global namespace. Resolve through ProjectData::namespaces.
    int64_t namespace_id = 0;
    // Body address ranges [first, last] ("Range Map - SCOPE ADDRESSES").
    std::vector<std::pair<uint64_t, uint64_t>> body;
    // Saved local variables, in symbol id order.
    std::vector<LocalVariableEntry> locals;
};

// A namespace-like symbol a function can live in: NAMESPACE, CLASS, LIBRARY,
// or a FUNCTION acting as a namespace (Ghidra lets functions own namespaces).
struct NamespaceEntry {
    std::string name;
    int64_t parent_id = 0;     // 0 = global namespace
    int symbol_type = 0;       // SymbolType id (1 library, 3 namespace, 4 class, 5 function)
};

// A saved parameter ("Symbols" row of type PARAMETER).
struct ParameterEntry {
    int ordinal = 0;
    std::string name;          // Ghidra's display name (param_N when default)
    int64_t type_id = DEFAULT_DATATYPE_ID;
    // The parameter's own storage; only meaningful (and only kept) when the
    // function has custom variable storage -- otherwise it is <UNASSIGNED>
    // and the calling convention places the parameter.
    std::vector<VarnodeEntry> storage;
};

// A function's saved signature ("Function Data" + its PARAMETER symbols),
// already resolved through any thunk chain to the function that owns it --
// the same record the live host's Function.getSignature() reflects.
struct SignatureEntry {
    uint64_t address = 0;      // the (thunk's own) entry point
    std::string name;          // the function's own name
    int64_t return_type = DEFAULT_DATATYPE_ID;
    std::string calling_convention;  // "unknown", "default", or a cspec model name
    bool has_var_args = false;
    // Signature SourceType is not DEFAULT: Ghidra hands the decompiler this
    // prototype locked. A DEFAULT signature is only a model hint.
    bool locked = false;
    // "Function Data" flags (FunctionAdapter): inline 0x02, no-return 0x04,
    // custom variable storage 0x08.
    bool is_inline = false;
    bool no_return = false;
    bool custom_storage = false;
    // Custom storage of the return value ("Function Data" Return Storage).
    std::vector<VarnodeEntry> return_storage;
    std::vector<ParameterEntry> parameters;
};

// A pointer the program defines as data whose primary reference is an
// external function, e.g. an import address table slot. The host's decompiler
// sees it as an external reference (DecompileCallback.getExternalRef): a call
// through the slot is a call to that function, with its saved signature.
struct ExternalRefEntry {
    uint64_t address = 0;          // the pointer's address (the IAT slot)
    std::string name;              // the external function's name
    SignatureEntry signature;      // its saved signature, address = `address`
};

// A defined data item ("Data" table row: CodeUnit address -> data type id).
struct DataEntry {
    uint64_t address = 0;
    int64_t type_id = DEFAULT_DATATYPE_ID;
    // "Property Map - Lengths": the item's length when its type has none of its
    // own (strings and other dynamic types); 0 = the data type's own length.
    int length = 0;
    // The data's "mutability" setting (Instance Settings): 0 normal, 1 volatile,
    // 2 constant; -1 when the item has none (the memory block decides).
    int mutability = -1;
};

// A label: a "Symbols" row of type LABEL at a memory address.
struct LabelEntry {
    int64_t id = 0;                // the symbol id (Symbol.getID)
    uint64_t address = 0;
    std::string name;
    int64_t namespace_id = 0;      // parent namespace symbol id; 0 = global
    bool primary = false;          // the "Primary" column is set
    int source = 0;                // SourceType storage id (0 ANALYSIS, 1 USER_DEFINED,
                                   // 2 DEFAULT, 3 IMPORTED, 4 AI)
};

// A symbol in the EXTERNAL space (an import): a "Symbols" row of type
// FUNCTION or LABEL whose address is an external address. `offset` is that
// address's offset, which is the address the host lists it at.
struct ExternalSymbolEntry {
    int64_t id = 0;
    uint64_t offset = 0;
    std::string name;
    int64_t namespace_id = 0;      // its library (or another namespace)
    bool function = false;
    int source = 0;                // SourceType storage id
};

// One comment of the listing ("Comments" row): its CommentType ordinal
// (0 EOL, 1 PRE, 2 POST, 3 PLATE, 4 REPEATABLE).
struct CommentEntry {
    uint64_t address = 0;
    int type = 0;
    std::string text;
};

// A bookmark ("Bookmarks<type id>" row; its type named by "Bookmark Types").
struct BookmarkEntry {
    int64_t id = 0;                // high 16 bits: the type id
    uint64_t address = 0;
    std::string type;
    std::string category;
    std::string comment;
};

// A function tag ("Function Tags") and the functions carrying it ("Function Tag Map").
struct FunctionTagEntry {
    int64_t id = 0;
    std::string name;
    std::string comment;
    std::vector<uint64_t> functions;   // entry points
};

// A register value the program context holds over an address range
// ("Range Map - Register_<name>"): what the host's decompiler receives as a
// tracked register (DecompileCallback.getTrackedRegisters).
struct RegisterValueEntry {
    std::string reg;
    uint64_t first = 0;
    uint64_t last = 0;
    uint64_t value = 0;
};

struct ProjectData {
    ProjectInfo info;
    std::vector<FunctionEntry> functions;
    // Saved signatures of every function in `functions`, and the program's data
    // types they (and everything else) refer to.
    std::vector<SignatureEntry> signatures;
    ProgramTypes types;
    // Namespace symbols by id, for FunctionEntry::namespace_id chains.
    std::map<int64_t, NamespaceEntry> namespaces;
    // Call fixups by function entry ("Property Map - CallFixup"): the name of
    // the compiler spec's <callfixup> that replaces calls to that function.
    std::map<uint64_t, std::string> call_fixups;
    // Instruction flow overrides ("Instructions" flags bits 1-3, FlowOverride
    // ordinal: 1 BRANCH, 2 CALL, 3 CALL_RETURN, 4 RETURN) by address.
    std::map<uint64_t, int> flow_overrides;
    // Start address of every instruction in the listing ("Instructions" keys),
    // ascending. has_instruction_index says the table was there at all.
    std::vector<uint64_t> instruction_starts;
    bool has_instruction_index = false;
    // External function pointers, by address.
    std::vector<ExternalRefEntry> external_refs;
    // The db carried Ghidra's reference index ("FROM REFS") and namespace bodies
    // ("Range Map - SCOPE ADDRESSES"), so FunctionEntry::makes_call is exact.
    bool has_reference_index = false;
    // The listing beyond functions: defined data, labels, comments, bookmarks
    // and function tags, in address (bookmarks: type, then id) order.
    std::vector<DataEntry> data;
    std::vector<LabelEntry> labels;
    std::vector<ExternalSymbolEntry> external_symbols;
    // External entry points (exports, the program entry): the targets of the
    // references from Ghidra's special EXT_FROM_ADDRESS ("FROM REFS" key -2).
    std::set<uint64_t> entry_points;
    std::vector<CommentEntry> comments;
    std::vector<BookmarkEntry> bookmarks;
    std::vector<FunctionTagEntry> function_tags;
    // Addresses a WRITE reference targets ("TO REFS"): memory in a read-only
    // block that the program writes is not constant
    // (MappedEntry.getMutabilityOfAddress).
    std::set<uint64_t> written;
    // The reference level of every referenced memory address ("TO REFS" Ref
    // Level: 0 UNK, 1 DAT, 2 LAB, 3 SUB, 5 EXT, 6 FUN), which names its
    // dynamic symbol (SymbolUtilities.getDynamicName).
    std::map<uint64_t, int> references;
    // Program context register values, by register then range.
    std::vector<RegisterValueEntry> register_values;
};

class MemoryImage;  // ghidradb/memory_image.h

class GHIDRA_API GhidraProject {
public:
    // Open the program `program` of the project (its project path, e.g.
    // "/program.exe", or its bare name); empty opens the project's only
    // program. False with isNotFound() when the project or program does not exist.
    bool open(const std::string& gpr_path, const std::string& program = "");
    ProjectData extract();

    // The last open() failed because the project or program does not exist.
    bool isNotFound() const { return not_found_; }

    // The project path of the program open() selected ("/program.exe").
    const std::string& programPath() const { return program_path_; }

    // Reconstruct the program's loaded memory image (File Bytes + Memory Blocks)
    // from this project's db, so the offline decompiler can read bytes at their
    // real virtual addresses without the original binary. Returns false if the
    // project carries no image bytes (getError() explains).
    bool loadMemoryImage(MemoryImage& out);

    std::string getError() const { return error_; }

private:
    std::string gbf_path_;
    std::string project_dir_;
    std::string program_path_;
    std::string error_;
    bool not_found_ = false;

    // Locate the .gbf database file of the named program in the project
    bool locateGbf(const std::string& gpr_path, const std::string& program);
};

} // namespace ghidra_db
