// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

// Typed wrapper around Ghidra's Architecture* pointer.
// Provides structured access to decompiler internals without void* casting
// in LocalClient code.

#include <cstdint>
#include <map>
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
}  // namespace ghidra

namespace libghidra::client::detail {

class ArchAdapter {
 public:
  explicit ArchAdapter(void* arch_ptr);

  /// Returns true if the adapter holds a valid Architecture pointer.
  bool valid() const { return arch_ != nullptr; }

  /// List functions in the global scope, optionally filtered by address range.
  /// range_start == range_end == 0 means "all functions".
  std::vector<FunctionRecord> listFunctions(std::uint64_t range_start,
                                            std::uint64_t range_end);

  /// Get a single function by entry address.  Returns nullopt if not found.
  std::optional<FunctionRecord> getFunction(std::uint64_t address);

  /// List symbols in the global scope, optionally filtered by address range.
  std::vector<SymbolRecord> listSymbols(std::uint64_t range_start,
                                        std::uint64_t range_end);

  /// Get a single symbol by address.
  std::optional<SymbolRecord> getSymbol(std::uint64_t address);

  /// List all types, optionally filtered by substring query.
  std::vector<TypeRecord> listTypes(const std::string& query);

  /// List enum types, optionally filtered by substring query.
  std::vector<TypeEnumRecord> listTypeEnums(const std::string& query);

  /// List enum members for a type identified by name.
  std::vector<TypeEnumMemberRecord> listTypeEnumMembers(const std::string& type_name);

  /// List struct/union members for a type identified by name.
  std::vector<TypeMemberRecord> listTypeMembers(const std::string& type_name);

  /// Read raw bytes from the loaded binary image.
  std::vector<std::uint8_t> readBytes(std::uint64_t address, std::uint32_t length);

  /// Disassemble a single instruction at the given address.
  /// Returns nullopt if the address is invalid.
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

  /// Look up a single type by name.  Returns nullopt if not found.
  std::optional<TypeRecord> getType(const std::string& name);

  /// List typedef aliases, optionally filtered by substring query.
  std::vector<TypeAliasRecord> listTypeAliases(const std::string& query);

  /// List union types, optionally filtered by substring query.
  std::vector<TypeUnionRecord> listTypeUnions(const std::string& query);

  /// List memory blocks (address spaces) from the loaded binary.
  std::vector<MemoryBlockRecord> listMemoryBlocks();

  /// Extract function signature via decompilation at the given address.
  /// Requires that the function has already been decompiled in this instance.
  std::optional<FunctionSignatureRecord> getFunctionSignature(std::uint64_t address);

  /// Decompile a function, extract basic blocks and CFG edges, then clear.
  /// Must be done in one shot because clearAnalysis() destroys the block graph.
  struct CFGResult {
    std::vector<BasicBlockRecord> blocks;
    std::vector<CFGEdgeRecord> edges;
  };
  CFGResult decompileAndExtractCFG(std::uint64_t func_entry);

  /// Delete a type by name.  Returns false if not found or if it's a core type.
  bool deleteType(const std::string& name);

  /// Rename a type.  Returns false if old name not found.
  bool renameType(const std::string& old_name, const std::string& new_name);

  /// Create a type alias (typedef).  Returns false if target type not found.
  bool createTypeAlias(const std::string& alias_name, const std::string& target_name);

  /// Delete a type alias.  Returns false if not found or not a typedef.
  bool deleteTypeAlias(const std::string& alias_name);

  /// Retarget a type alias. Destroys and recreates the typedef.
  bool setTypeAliasTarget(const std::string& alias_name,
                          const std::string& new_target_name);

  /// Rename a data item (non-function symbol) at the given address.
  bool renameDataItem(std::uint64_t address, const std::string& new_name);

  /// Delete a data item (non-function symbol) at the given address.
  bool deleteDataItem(std::uint64_t address);

  /// Delete a symbol at the given address.  Returns false if not found.
  bool deleteSymbol(std::uint64_t address);

  /// Get comments stored for a given address range.
  /// Comments are kept in an in-memory map (not in the decompiler engine).
  struct CommentEntry {
    std::uint64_t address;
    int kind;           // maps to CommentKind enum
    std::string text;
  };
  std::vector<CommentEntry> getComments(std::uint64_t range_start,
                                        std::uint64_t range_end);

  /// Set a comment at a given address/kind. Overwrites any existing comment.
  void setComment(std::uint64_t address, int kind, const std::string& text);

  /// Delete a comment at a given address/kind. Returns false if not found.
  bool deleteComment(std::uint64_t address, int kind);

  /// List non-function, non-label symbols (data items) in a range.
  struct DataItemEntry {
    std::uint64_t address;
    std::string name;
    std::string data_type;
    std::uint64_t size;
  };
  std::vector<DataItemEntry> listDataItems(std::uint64_t range_start,
                                           std::uint64_t range_end);

  /// Set a comment on a struct member (in-memory overlay).
  void setTypeMemberComment(const std::string& type_name, std::uint64_t ordinal,
                            const std::string& comment);

  /// Set a comment on an enum member (in-memory overlay).
  void setTypeEnumMemberComment(const std::string& type_name,
                                std::uint64_t ordinal,
                                const std::string& comment);

 private:
  ghidra::Architecture* arch_ = nullptr;
  // In-memory comment store: (address, kind) → text
  std::map<std::pair<std::uint64_t, int>, std::string> comments_;
  // In-memory type member comment store: (type_name, ordinal) → comment
  std::map<std::pair<std::string, std::uint64_t>, std::string> type_member_comments_;
  // In-memory type enum member comment store: (type_name, ordinal) → comment
  std::map<std::pair<std::string, std::uint64_t>, std::string> type_enum_member_comments_;
};

}  // namespace libghidra::client::detail
