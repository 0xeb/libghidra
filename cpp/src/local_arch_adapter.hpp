// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

// Typed wrapper around Ghidra's Architecture* pointer.
// Provides structured access to decompiler internals without void* casting
// in LocalClient code.

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "libghidra/models.hpp"

// Forward-declare Ghidra C++ types to avoid pulling decompiler headers into
// every translation unit that includes this header.
namespace ghidra {
class Architecture;
class Scope;
class TypeFactory;
class Translate;
class Datatype;
class TypeField;
class TypeUnion;
}  // namespace ghidra

namespace ghidra_standalone {
class Decompiler;
struct MemoryBlockInfo;
}  // namespace ghidra_standalone

namespace libghidra::client::detail {

/// Outcome of a function-local mutation (rename/retype). Lets callers surface a
/// precise error code instead of collapsing every failure into one bucket.
enum class LocalMutationStatus {
  kOk,               // applied successfully
  kNotFound,         // the local_id did not resolve to a function-local
  kInvalidType,      // (retype only) the type string did not parse
  kDecompileFailed,  // the function could not be decompiled
  kRetypeRejected,   // (retype only) the decompiler cannot give this local
                     // that type: a size change on a local that is not one
                     // fixed storage location (e.g. a register temporary)
};

/// The outcome of an adapter write: ok, or one code of the RPC vocabulary
/// (libghidra/error_codes.hpp) with a message.
struct WriteStatus {
  std::string code;
  std::string message;

  bool ok() const { return code.empty(); }
  static WriteStatus Ok() { return {}; }
  static WriteStatus Fail(const char* code, std::string message) {
    return {code, std::move(message)};
  }
};

/// Whether a byte range can be read or written offline.
enum class RangeStatus {
  kOk,
  kUnmapped,       // the first byte is in no memory block
  kPastMapped,     // the range runs out of mapped memory
  kUninitialized,  // a block in the range holds no bytes
  kUnavailable,    // mapped and initialized, but the offline image has no bytes there
};

class ArchAdapter {
 public:
  /// `project` (optional) is the Decompiler that owns `arch_ptr`: it carries what
  /// it read from a Ghidra project (type categories, thunks, ...) so records read
  /// back as the live host reports them.
  explicit ArchAdapter(void* arch_ptr, ghidra_standalone::Decompiler* project = nullptr);

  /// Returns true if the adapter holds a valid Architecture pointer.
  bool valid() const { return arch_ != nullptr; }

  /// List functions in the global scope, optionally filtered by address range.
  /// range_start == range_end == 0 means "all functions".
  std::vector<FunctionRecord> listFunctions(std::uint64_t range_start,
                                            std::uint64_t range_end);

  /// The function an address names, as the live host resolves it
  /// (FunctionManager.getFunctionAt, then getFunctionContaining): a function
  /// whose entry is `address`, else -- for an opened project -- the project
  /// function whose body contains it. nullopt = not found.
  std::optional<std::uint64_t> functionEntryFor(std::uint64_t address);

  /// The function GetDecompilation decompiles for `address`: functionEntryFor,
  /// or, for a bare binary (which has no function bodies), `address` itself when
  /// it holds loaded bytes -- decompiling there defines the function. nullopt
  /// (not found) for an address no project function covers, or with no bytes.
  std::optional<std::uint64_t> decompileEntryFor(std::uint64_t address);

  /// A function's entry is exactly `address` (never an address inside one).
  bool functionStartsAt(std::uint64_t address);

  /// Ghidra's default function name, FUN_<address>
  /// (SymbolUtilities.getDefaultFunctionName).
  static std::string defaultFunctionName(std::uint64_t address);

  /// The function `address` names (functionEntryFor). Returns nullopt if not found.
  std::optional<FunctionRecord> getFunction(std::uint64_t address);

  /// The program's symbols in a range, as the host's symbol table lists them:
  /// every function's own symbol and every label (data names, code labels),
  /// in address order. Symbols the decompiler invents while analysing are not
  /// the program's and are left out.
  std::vector<SymbolRecord> listSymbols(std::uint64_t range_start,
                                        std::uint64_t range_end);

  /// The primary symbol at `address` (SymbolTable.getPrimarySymbol): the
  /// function that starts there, else the primary label. nullopt when none.
  std::optional<SymbolRecord> getSymbol(std::uint64_t address);

  /// List all types, optionally filtered by substring query.
  std::vector<TypeRecord> listTypes(const std::string& query);

  /// List enum types, optionally filtered by substring query.
  std::vector<TypeEnumRecord> listTypeEnums(const std::string& query);

  /// List enum members for a type identified by name.
  std::vector<TypeEnumMemberRecord> listTypeEnumMembers(const std::string& type_name);

  /// List struct/union members for a type identified by name.
  std::vector<TypeMemberRecord> listTypeMembers(const std::string& type_name);


  /// Read bytes as the host does: the range from `address` up to the end of
  /// the mapped, initialized memory it starts in (at most `length` bytes).
  /// `status` says why nothing could be read: kUnmapped, kUninitialized, or
  /// kUnavailable when the offline image holds no bytes there.
  std::vector<std::uint8_t> readBytes(std::uint64_t address, std::uint32_t length,
                                      RangeStatus& status);

  // -- Memory map -------------------------------------------------------------

  /// The block containing `address`, or nullptr when it is unmapped. A program
  /// whose loader gives no memory map counts every loadable byte as mapped.
  const ghidra_standalone::MemoryBlockInfo* blockAt(std::uint64_t address) const;

  /// `address` lies in the program's memory.
  bool isMapped(std::uint64_t address);

  /// Whether `length` bytes from `address` can be written offline: every byte
  /// mapped and initialized, and held by the offline image.
  RangeStatus checkWritable(std::uint64_t address, std::uint64_t length);

  /// The start of the listing instruction whose bytes include `address` when
  /// it does not start there (an address inside an instruction). nullopt
  /// otherwise, and always for a bare binary, which has no listing.
  std::optional<std::uint64_t> insideInstruction(std::uint64_t address);

  /// Code occupies some byte of [address, address + length): a listing
  /// instruction for an opened project, a function entry for a bare binary.
  bool codeOverlaps(std::uint64_t address, std::uint64_t length);

  /// Disassemble the instruction that starts at the given address. For an
  /// opened project that must be an instruction of its listing (an address
  /// inside an instruction, or in data, is not found); for a bare binary any
  /// decodable address. Returns nullopt if not found.
  std::optional<InstructionRecord> getInstruction(std::uint64_t address);

  /// Disassemble instructions in a range, up to limit count.
  std::vector<InstructionRecord> listInstructions(std::uint64_t range_start,
                                                  std::uint64_t range_end,
                                                  int limit);

  /// Extract cross-references from a previously decompiled function.
  /// The function at the given address must have been decompiled first.
  /// Returns call xrefs (from PcodeOp CALL/CALLIND targets) and data xrefs
  /// (from constant LOAD/STORE addresses).
  std::vector<XrefRecord> listXrefsForFunction(std::uint64_t func_entry);

  /// Look up a single type by its Ghidra path ("/category/Name", the
  /// path_name records report) or by bare name. Returns nullopt if not found.
  std::optional<TypeRecord> getType(const std::string& path);

  /// List typedef aliases, optionally filtered by substring query.
  std::vector<TypeAliasRecord> listTypeAliases(const std::string& query);

  /// List union types, optionally filtered by substring query.
  std::vector<TypeUnionRecord> listTypeUnions(const std::string& query);

  /// List memory blocks (address spaces) from the loaded binary.
  std::vector<MemoryBlockRecord> listMemoryBlocks();

  /// The function's signature, read from its prototype as Ghidra reports it:
  /// type path names, calling convention, `(void)` for a saved empty list, and
  /// `undefined f()` for a function with no saved signature (the prototype is
  /// not locked, so a decompile only infers parameters transiently).
  /// nullopt when the address names no function (functionEntryFor). Needs no
  /// decompile.
  std::optional<FunctionSignatureRecord> getFunctionSignature(std::uint64_t address);

  /// Decompile a function, extract basic blocks and CFG edges, then clear.
  /// Must be done in one shot because clearAnalysis() destroys the block graph.
  struct CFGResult {
    std::vector<BasicBlockRecord> blocks;
    std::vector<CFGEdgeRecord> edges;
  };
  CFGResult decompileAndExtractCFG(std::uint64_t func_entry);

  /// Decompile a function and return both its pseudocode and its local-variable
  /// surface in one pass.  Locals are enumerated from the function scope BEFORE
  /// clearAnalysis (which discards the HighFunction layer), mirroring the live
  /// host's decomp_lvars.  `ok` is false if the function could not be decompiled.
  struct DecompileWithLocalsResult {
    std::string pseudocode;
    std::vector<DecompileLocalRecord> locals;
    bool ok = false;
    // Populated when ok == false. This path bypasses Decompiler::decompileAt, so
    // the engine's lastError is stale/empty for offline failures; carry the real
    // reason here instead of reading Decompiler::getError() downstream.
    std::string error;
  };
  DecompileWithLocalsResult decompileWithLocals(std::uint64_t func_entry);

  /// Apply a durable rename to a function-local identified by its canonical
  /// local_id (as emitted by decompileWithLocals).  The symbol is name-locked so
  /// the rename survives re-decompilation.  Returns kNotFound if the local_id
  /// does not resolve, or kDecompileFailed if the function cannot be decompiled.
  LocalMutationStatus applyLocalRename(std::uint64_t func_entry,
                                       const std::string& local_id,
                                       const std::string& new_name);

  /// Apply a durable retype to a function-local identified by its canonical
  /// local_id.  The symbol is type-locked.  Returns kInvalidType if the type
  /// string does not parse, kNotFound if the local_id does not resolve, or
  /// kDecompileFailed if the function cannot be decompiled.
  LocalMutationStatus applyLocalRetype(std::uint64_t func_entry,
                                       const std::string& local_id,
                                       const std::string& new_type);

  // -- Types --------------------------------------------------------------------
  //
  // Every type write names its target by Ghidra path ("/category/Name") or
  // bare name and edits that data type in place: an edit never creates a second
  // type beside it. A missing target is not_found, a target of the wrong kind
  // invalid_argument, a type named as an argument that does not resolve
  // unknown_type, a name already taken duplicate_name.

  /// A type of this name exists anywhere (the decompiler holds one type per name).
  bool typeNameTaken(const std::string& name) const;

  /// Delete a type. A core type is invalid_argument.
  WriteStatus deleteType(const std::string& path);

  /// Delete an enum (invalid_argument for any other kind).
  WriteStatus deleteTypeEnum(const std::string& path);

  /// Rename a type, keeping its category.
  WriteStatus renameType(const std::string& path, const std::string& new_name);

  /// Create a typedef `alias_name` of `target_name` in the root category.
  WriteStatus createTypeAlias(const std::string& alias_name, const std::string& target_name);

  /// Delete a typedef.
  WriteStatus deleteTypeAlias(const std::string& path);

  /// Point a typedef at another type. The same target is ok and changes nothing.
  WriteStatus setTypeAliasTarget(const std::string& path, const std::string& new_target_name);

  /// Enum member edits. Ordinals count members in value order, as listed.
  WriteStatus addTypeEnumMember(const std::string& path, const std::string& name,
                                std::int64_t value);
  WriteStatus deleteTypeEnumMember(const std::string& path, std::uint64_t ordinal);
  WriteStatus renameTypeEnumMember(const std::string& path, std::uint64_t ordinal,
                                   const std::string& new_name);
  WriteStatus setTypeEnumMemberValue(const std::string& path, std::uint64_t ordinal,
                                     std::int64_t value);
  WriteStatus setTypeEnumMemberComment(const std::string& path, std::uint64_t ordinal,
                                       const std::string& comment);

  /// Struct and union member edits. Ordinals are the host's component
  /// ordinals: in a structure without packing every undefined byte between
  /// (and after) the members is a component of its own, so they count;
  /// deleting one, or a member, shifts the later members down
  /// (Structure.delete). A member retyped without packing keeps its offset and
  /// takes the undefined bytes after it (Structure.replace). An edit that
  /// changes a type's size lays out again everything holding it by value.
  WriteStatus addTypeMember(const std::string& path, const std::string& name,
                            const std::string& member_type);
  WriteStatus deleteTypeMember(const std::string& path, std::uint64_t ordinal);
  WriteStatus renameTypeMember(const std::string& path, std::uint64_t ordinal,
                               const std::string& new_name);
  WriteStatus setTypeMemberType(const std::string& path, std::uint64_t ordinal,
                                const std::string& member_type);
  WriteStatus setTypeMemberComment(const std::string& path, std::uint64_t ordinal,
                                   const std::string& comment);

  /// Parse C declarations into the program's types, all or nothing, as the
  /// host's CParser does (Decompiler::parseDeclarations); a type the text
  /// redefines is replaced in place and what holds it laid out again.
  /// `created` receives the paths of the new types.
  WriteStatus parseDeclarations(const std::string& text, std::vector<std::string>& created);

  // -- Symbols and data ---------------------------------------------------------

  /// Give the bytes at `address` a data type (a Ghidra path, a bare name or a
  /// C type expression): existing data keeps its name and takes the type,
  /// otherwise a DAT_<address> item is created. unknown_type when the type does
  /// not resolve, invalid_argument when instructions occupy the bytes or they
  /// run out of mapped memory, unmapped_address when the address is unmapped.
  WriteStatus applyDataType(std::uint64_t address, const std::string& type_text);

  /// The defined data items in a range (the host's Listing.getDefinedData):
  /// named by their primary label ("" when they have none).
  struct DataItemEntry {
    std::uint64_t address;
    std::string name;
    std::string data_type;
    std::uint64_t size;
  };
  std::vector<DataItemEntry> listDataItems(std::uint64_t range_start,
                                           std::uint64_t range_end);

 private:
  ghidra::Architecture* arch_ = nullptr;
  ghidra_standalone::Decompiler* project_ = nullptr;
  const std::map<std::uint64_t, std::string>* type_categories_ = nullptr;

  // Persistent local-variable renames, keyed by (function entry, local id) ->
  // new name. A pure name-lock does NOT survive Ghidra's clearUnlocked on the next
  // decompile (only type-locked symbols are held — database.cc:2050), so an offline
  // rename would silently vanish. This registry re-applies the rename after every
  // decompile (reapplyLocalRenames), reproducing the live host's durable-edit model.
  std::map<std::pair<std::uint64_t, std::string>, std::string> local_renames_;

  // The loaded project records the function at `entry` as a thunk.
  bool isProjectThunk(std::uint64_t entry) const;
  // An import slot where the project load placed an external function stub.
  bool isExternalStub(std::uint64_t address) const;
  // An opened project (not a bare binary) backs this adapter.
  bool fromProject() const;
  // The Ghidra path of a type: its program category (Ghidra data type id ->
  // category, as loadProject read it) then its name; "/name" for core types.
  std::string typePath(const void* datatype) const;
  // The type a caller names by Ghidra path or bare name (see getType).
  ghidra::Datatype* findType(const std::string& path_or_name) const;
  // A type named as an argument (member, alias target): a Ghidra path, a bare
  // name, or a C type expression (`int *`, `char[4]`). nullptr when unknown.
  ghidra::Datatype* resolveArgumentType(const std::string& text) const;
  // The first user of `dt` of any kind (a field, array, typedef, pointer,
  // symbol or prototype), for the writes the engine cannot apply to a type in
  // use: a delete would leave it pointing at freed memory. Empty when none.
  std::string typeUser(ghidra::Datatype* dt) const;
  // The struct or union a member edit names, or the reason it cannot be edited.
  WriteStatus compositeTarget(const std::string& path, ghidra::Datatype*& out) const;
  // A composite's packing (-1 disabled, 0 default, > 0 explicit), as the
  // program records it or as the session created it.
  int packingOf(const ghidra::Datatype* dt) const;
  // The layout of a composite or array: its fields (composites) and size.
  struct Layout {
    std::vector<ghidra::TypeField> fields;
    int size = 0;
    int align = 1;
  };
  // An edit's new layouts: the edited composite and every type that holds it
  // by value, in the order to apply them (a type after what it holds).
  struct LayoutPlan {
    std::map<ghidra::Datatype*, Layout> layouts;
    std::vector<ghidra::Datatype*> order;
  };
  // The planned layout of `dt`, else its current one.
  Layout layoutOf(ghidra::Datatype* dt, const LayoutPlan& plan) const;
  // Place the fields of composite `dt` as the host does for its packing:
  // packed offsets and size by alignment; a union as long as its longest member.
  void layOut(ghidra::Datatype* dt, Layout& layout, const LayoutPlan& plan) const;
  // Plan `target`'s new layout and the layout of everything holding it by value.
  // not_supported when a holder cannot take it (it would truncate a member).
  WriteStatus planLayout(ghidra::Datatype* target, Layout layout, LayoutPlan& plan) const;
  void applyLayout(const LayoutPlan& plan);
  // Give `target` the fields of `layout` and lay out what holds it again.
  WriteStatus relayout(ghidra::Datatype* target, Layout layout);
  // A union's member comments, one per member in ordinal order.
  std::vector<std::string>& unionComments(ghidra::TypeUnion* tu);
  // The host's id of a type (DataTypeManager.getID).
  std::uint64_t typeId(const ghidra::Datatype* dt) const;
  // Bring every typedef copy of `te` (a typedef of an enum is a copy of it)
  // to its values.
  void refreshEnumCopies(ghidra::Datatype* te);
  WriteStatus enumTarget(const std::string& path, ghidra::Datatype*& out) const;

  // Re-apply the stored renames for func_entry onto a freshly decompiled Funcdata.
  void reapplyLocalRenames(std::uint64_t func_entry, void* fd);
  // Member comments, which the decompiler's types have no room for: (type id,
  // member name) -> comment. Keyed by name, not ordinal, so a comment follows
  // its member when an edit moves the ordinals; a rename moves the key.
  std::map<std::pair<std::uint64_t, std::string>, std::string> member_comments_;
  // A union's member comments by ordinal (a union may repeat a member name).
  std::map<std::uint64_t, std::vector<std::string>> union_comments_;
};

}  // namespace libghidra::client::detail
