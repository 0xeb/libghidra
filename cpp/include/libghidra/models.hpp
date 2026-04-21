// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace libghidra::client {

enum class ShutdownPolicy {
  kUnspecified = 0,
  kSave = 1,
  kDiscard = 2,
  kNone = 3,
};

enum class CommentKind {
  kUnspecified = 0,
  kEol = 1,
  kPre = 2,
  kPost = 3,
  kPlate = 4,
  kRepeatable = 5,
};

struct Capability {
  std::string id;
  std::string status;
  std::string note;
};

struct HealthStatus {
  bool ok = false;
  std::string service_name;
  std::string service_version;
  std::string host_mode;
  std::uint64_t program_revision = 0;
  std::vector<std::string> warnings;
};

struct OpenProgramResponse {
  std::string program_name;
  std::string language_id;
  std::string compiler_spec;
  std::uint64_t image_base = 0;
};

struct CloseProgramResponse {
  bool closed = false;
};

struct SaveProgramResponse {
  bool saved = false;
};

struct DiscardProgramResponse {
  bool discarded = false;
};

struct RevisionResponse {
  std::uint64_t revision = 0;
};

struct ShutdownResponse {
  bool accepted = false;
};

struct ReadBytesResponse {
  std::vector<std::uint8_t> data;
};

struct WriteBytesResponse {
  std::uint32_t bytes_written = 0;
};

struct PatchBytesBatchResponse {
  std::uint32_t patch_count = 0;
  std::uint32_t bytes_written = 0;
};

struct MemoryBlockRecord {
  std::string name;
  std::uint64_t start_address = 0;
  std::uint64_t end_address = 0;
  std::uint64_t size = 0;
  bool is_read = false;
  bool is_write = false;
  bool is_execute = false;
  bool is_volatile = false;
  bool is_initialized = false;
  std::string source_name;
  std::string comment;
};

struct ListMemoryBlocksResponse {
  std::vector<MemoryBlockRecord> blocks;
};

struct FunctionRecord {
  std::uint64_t entry_address = 0;
  std::string name;
  std::uint64_t start_address = 0;
  std::uint64_t end_address = 0;
  std::uint64_t size = 0;
  std::string namespace_name;
  std::string prototype;
  bool is_thunk = false;
  std::uint32_t parameter_count = 0;
};

struct GetFunctionResponse {
  std::optional<FunctionRecord> function;
};

struct ListFunctionsResponse {
  std::vector<FunctionRecord> functions;
};

struct RenameFunctionResponse {
  bool renamed = false;
  std::string name;
};

struct BasicBlockRecord {
  std::uint64_t function_entry = 0;
  std::uint64_t start_address = 0;
  std::uint64_t end_address = 0;
  std::uint32_t in_degree = 0;
  std::uint32_t out_degree = 0;
};

struct ListBasicBlocksResponse {
  std::vector<BasicBlockRecord> blocks;
};

struct CFGEdgeRecord {
  std::uint64_t function_entry = 0;
  std::uint64_t src_block_start = 0;
  std::uint64_t dst_block_start = 0;
  std::string edge_kind;
};

struct ListCFGEdgesResponse {
  std::vector<CFGEdgeRecord> edges;
};

struct SwitchCaseRecord {
  std::int64_t value = 0;
  std::uint64_t target_address = 0;
};

struct SwitchTableRecord {
  std::uint64_t function_entry = 0;
  std::uint64_t switch_address = 0;
  std::uint32_t case_count = 0;
  std::vector<SwitchCaseRecord> cases;
  std::uint64_t default_address = 0;
};

struct ListSwitchTablesResponse {
  std::vector<SwitchTableRecord> switch_tables;
};

struct DominatorRecord {
  std::uint64_t function_entry = 0;
  std::uint64_t block_address = 0;
  std::uint64_t idom_address = 0;
  std::uint32_t depth = 0;
  bool is_entry = false;
};

struct ListDominatorsResponse {
  std::vector<DominatorRecord> dominators;
};

struct PostDominatorRecord {
  std::uint64_t function_entry = 0;
  std::uint64_t block_address = 0;
  std::uint64_t ipdom_address = 0;
  std::uint32_t depth = 0;
  bool is_exit = false;
};

struct ListPostDominatorsResponse {
  std::vector<PostDominatorRecord> post_dominators;
};

struct LoopRecord {
  std::uint64_t function_entry = 0;
  std::uint64_t header_address = 0;
  std::uint64_t back_edge_source = 0;
  std::string loop_kind;
  std::uint32_t block_count = 0;
  std::uint32_t depth = 0;
};

struct ListLoopsResponse {
  std::vector<LoopRecord> loops;
};

// Function tags — Ghidra-native categorization
struct FunctionTagRecord {
  std::string name;
  std::string comment;
};

struct ListFunctionTagsResponse {
  std::vector<FunctionTagRecord> tags;
};

struct CreateFunctionTagResponse {
  bool created = false;
};

struct DeleteFunctionTagResponse {
  bool deleted = false;
};

struct FunctionTagMappingRecord {
  std::uint64_t function_entry = 0;
  std::string tag_name;
};

struct ListFunctionTagMappingsResponse {
  std::vector<FunctionTagMappingRecord> mappings;
};

struct TagFunctionResponse {
  bool updated = false;
};

struct UntagFunctionResponse {
  bool updated = false;
};

struct SymbolRecord {
  std::uint64_t symbol_id = 0;
  std::uint64_t address = 0;
  std::string name;
  std::string full_name;
  std::string type;
  std::string namespace_name;
  std::string source;
  bool is_primary = false;
  bool is_external = false;
  bool is_dynamic = false;
};

struct GetSymbolResponse {
  std::optional<SymbolRecord> symbol;
};

struct ListSymbolsResponse {
  std::vector<SymbolRecord> symbols;
};

struct RenameSymbolResponse {
  bool renamed = false;
  std::string name;
};

struct DeleteSymbolResponse {
  bool deleted = false;
  std::uint32_t deleted_count = 0;
};

struct XrefRecord {
  std::uint64_t from_address = 0;
  std::uint64_t to_address = 0;
  int operand_index = 0;
  std::string ref_type;
  bool is_primary = false;
  std::string source;
  std::int64_t symbol_id = -1;
  bool is_external = false;
  bool is_memory = false;
  bool is_flow = false;
};

struct ListXrefsResponse {
  std::vector<XrefRecord> xrefs;
};

struct TypeRecord {
  std::uint64_t type_id = 0;
  std::string name;
  std::string path_name;
  std::string category_path;
  std::string display_name;
  std::string kind;
  int length = 0;
  bool is_not_yet_defined = false;
  std::string source_archive;
  std::string universal_id;
};

struct GetTypeResponse {
  std::optional<TypeRecord> type;
};

struct ListTypesResponse {
  std::vector<TypeRecord> types;
};

struct TypeAliasRecord {
  std::uint64_t type_id = 0;
  std::string path_name;
  std::string name;
  std::string target_type;
  std::string declaration;
};

struct ListTypeAliasesResponse {
  std::vector<TypeAliasRecord> aliases;
};

struct TypeUnionRecord {
  std::uint64_t type_id = 0;
  std::string path_name;
  std::string name;
  std::uint64_t size = 0;
  std::string declaration;
};

struct ListTypeUnionsResponse {
  std::vector<TypeUnionRecord> unions;
};

struct TypeEnumRecord {
  std::uint64_t type_id = 0;
  std::string path_name;
  std::string name;
  std::uint64_t width = 0;
  bool is_signed = false;
  std::string declaration;
};

struct ListTypeEnumsResponse {
  std::vector<TypeEnumRecord> enums;
};

struct TypeEnumMemberRecord {
  std::uint64_t type_id = 0;
  std::string type_path_name;
  std::string type_name;
  std::uint64_t ordinal = 0;
  std::string name;
  std::int64_t value = 0;
  std::string comment;
};

struct ListTypeEnumMembersResponse {
  std::vector<TypeEnumMemberRecord> members;
};

struct TypeMemberRecord {
  std::uint64_t parent_type_id = 0;
  std::string parent_type_path_name;
  std::string parent_type_name;
  std::uint64_t ordinal = 0;
  std::string name;
  std::string member_type;
  std::int64_t offset = 0;
  std::uint64_t size = 0;
  std::string comment;
};

struct ListTypeMembersResponse {
  std::vector<TypeMemberRecord> members;
};

struct ParameterRecord {
  int ordinal = 0;
  std::string name;
  std::string data_type;
  std::string formal_data_type;
  bool is_auto_parameter = false;
  bool is_forced_indirect = false;
};

struct FunctionSignatureRecord {
  std::uint64_t function_entry_address = 0;
  std::string function_name;
  std::string prototype;
  std::string return_type;
  bool has_var_args = false;
  std::string calling_convention;
  std::vector<ParameterRecord> parameters;
};

struct GetFunctionSignatureResponse {
  std::optional<FunctionSignatureRecord> signature;
};

struct ListFunctionSignaturesResponse {
  std::vector<FunctionSignatureRecord> signatures;
};

struct SetFunctionSignatureResponse {
  bool updated = false;
  std::string function_name;
  std::string prototype;
};

struct RenameFunctionParameterResponse {
  bool updated = false;
  std::string name;
};

struct SetFunctionParameterTypeResponse {
  bool updated = false;
  std::string data_type;
};

struct RenameFunctionLocalResponse {
  bool updated = false;
  std::string local_id;
  std::string name;
};

struct SetFunctionLocalTypeResponse {
  bool updated = false;
  std::string local_id;
  std::string data_type;
};

struct ApplyDataTypeResponse {
  bool updated = false;
  std::string data_type;
};

struct CreateTypeResponse {
  bool updated = false;
};

struct DeleteTypeResponse {
  bool deleted = false;
};

struct RenameTypeResponse {
  bool updated = false;
  std::string name;
};

struct CreateTypeAliasResponse {
  bool updated = false;
};

struct DeleteTypeAliasResponse {
  bool deleted = false;
};

struct SetTypeAliasTargetResponse {
  bool updated = false;
};

struct CreateTypeEnumResponse {
  bool updated = false;
};

struct DeleteTypeEnumResponse {
  bool deleted = false;
};

struct AddTypeEnumMemberResponse {
  bool updated = false;
};

struct DeleteTypeEnumMemberResponse {
  bool deleted = false;
};

struct RenameTypeEnumMemberResponse {
  bool updated = false;
};

struct SetTypeEnumMemberValueResponse {
  bool updated = false;
};

struct AddTypeMemberResponse {
  bool updated = false;
};

struct DeleteTypeMemberResponse {
  bool deleted = false;
};

struct RenameTypeMemberResponse {
  bool updated = false;
};

struct SetTypeMemberTypeResponse {
  bool updated = false;
};

struct SetTypeMemberCommentResponse {
  bool updated = false;
};

struct SetTypeEnumMemberCommentResponse {
  bool updated = false;
};

struct ParseDeclarationsResponse {
  int types_created = 0;
  std::vector<std::string> type_names;
  std::vector<std::string> errors;
};

enum class DecompileLocalKind {
  kUnspecified = 0,
  kParam = 1,
  kLocal = 2,
  kTemp = 3,
};

struct DecompileLocalRecord {
  std::string local_id;
  DecompileLocalKind kind = DecompileLocalKind::kUnspecified;
  std::string name;
  std::string data_type;
  std::string storage;
  int ordinal = -1;
};

enum class DecompileTokenKind {
  kUnspecified = 0,
  kKeyword = 1,
  kComment = 2,
  kType = 3,
  kFunction = 4,
  kVariable = 5,
  kConst = 6,
  kParameter = 7,
  kGlobal = 8,
  kDefault = 9,
  kError = 10,
  kSpecial = 11,
};

struct DecompileTokenRecord {
  std::string text;
  DecompileTokenKind kind = DecompileTokenKind::kUnspecified;
  int line_number = -1;
  int column_offset = -1;
  std::string var_name;
  std::string var_type;
  std::string var_storage;
};

struct DecompilationRecord {
  std::uint64_t function_entry_address = 0;
  std::string function_name;
  std::string prototype;
  std::string pseudocode;
  bool completed = false;
  bool is_fallback = false;
  std::string error_message;
  std::vector<DecompileLocalRecord> locals;
  std::vector<DecompileTokenRecord> tokens;
};

struct GetDecompilationResponse {
  std::optional<DecompilationRecord> decompilation;
};

struct ListDecompilationsResponse {
  std::vector<DecompilationRecord> decompilations;
};

struct InstructionRecord {
  std::uint64_t address = 0;
  std::string mnemonic;
  std::string operand_text;
  std::string disassembly;
  std::uint32_t length = 0;
};

struct GetInstructionResponse {
  std::optional<InstructionRecord> instruction;
};

struct ListInstructionsResponse {
  std::vector<InstructionRecord> instructions;
};

struct CommentRecord {
  std::uint64_t address = 0;
  CommentKind kind = CommentKind::kUnspecified;
  std::string text;
};

struct GetCommentsResponse {
  std::vector<CommentRecord> comments;
};

struct SetCommentResponse {
  bool updated = false;
};

struct DeleteCommentResponse {
  bool deleted = false;
};

struct RenameDataItemResponse {
  bool updated = false;
  std::string name;
};

struct DeleteDataItemResponse {
  bool deleted = false;
};

struct DataItemRecord {
  std::uint64_t address = 0;
  std::uint64_t end_address = 0;
  std::string name;
  std::string data_type;
  std::uint64_t size = 0;
  std::string value_repr;
};

struct ListDataItemsResponse {
  std::vector<DataItemRecord> data_items;
};

struct BookmarkRecord {
  std::uint64_t address = 0;
  std::string type;
  std::string category;
  std::string comment;
};

struct ListBookmarksResponse {
  std::vector<BookmarkRecord> bookmarks;
};

struct AddBookmarkResponse {
  bool updated = false;
};

struct DeleteBookmarkResponse {
  bool deleted = false;
};

struct BreakpointRecord {
  std::uint64_t address = 0;
  bool enabled = false;
  std::string kind;
  std::uint64_t size = 0;
  std::string condition;
  std::string group;
};

struct ListBreakpointsResponse {
  std::vector<BreakpointRecord> breakpoints;
};

struct AddBreakpointResponse {
  bool updated = false;
};

struct SetBreakpointEnabledResponse {
  bool updated = false;
};

struct SetBreakpointKindResponse {
  bool updated = false;
};

struct SetBreakpointSizeResponse {
  bool updated = false;
};

struct SetBreakpointConditionResponse {
  bool updated = false;
};

struct SetBreakpointGroupResponse {
  bool updated = false;
};

struct DeleteBreakpointResponse {
  bool deleted = false;
};

struct DefinedStringRecord {
  std::uint64_t address = 0;
  std::string value;
  std::uint32_t length = 0;
  std::string data_type;
  std::string encoding;
};

struct ListDefinedStringsResponse {
  std::vector<DefinedStringRecord> strings;
};

}  // namespace libghidra::client
