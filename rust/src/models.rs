// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

// Enums

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShutdownPolicy {
    #[default]
    Unspecified,
    Save,
    Discard,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CommentKind {
    #[default]
    Unspecified,
    Eol,
    Pre,
    Post,
    Plate,
    Repeatable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecompileLocalKind {
    #[default]
    Unspecified,
    Param,
    Local,
    Temp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecompileTokenKind {
    #[default]
    Unspecified,
    Keyword,
    Comment,
    Type,
    Function,
    Variable,
    Const,
    Parameter,
    Global,
    Default,
    Error,
    Special,
}

// Records

#[derive(Debug, Clone, Default)]
pub struct Capability {
    pub id: String,
    pub status: String,
    pub note: String,
}

#[derive(Debug, Clone, Default)]
pub struct HealthStatus {
    pub ok: bool,
    pub service_name: String,
    pub service_version: String,
    pub host_mode: String,
    pub modification_number: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OpenProjectRequest {
    pub project_path: String,
    pub project_name: String,
    pub create: bool,
    pub read_only: bool,
}

#[derive(Debug, Clone, Default)]
pub struct OpenProjectResponse {
    pub project_path: String,
    pub project_name: String,
    pub created: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CloseProjectResponse {
    pub closed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ProjectFile {
    pub path: String,
    pub name: String,
    pub folder_path: String,
    pub content_type: String,
    pub domain_object_class: String,
    pub is_folder: bool,
    pub is_program: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListProjectFilesRequest {
    pub include_folders: bool,
    pub programs_only: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListProjectFilesResponse {
    pub files: Vec<ProjectFile>,
}

#[derive(Debug, Clone, Default)]
pub struct LoaderArg {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct ImportProgramRequest {
    pub source_path: String,
    pub project_folder_path: String,
    pub program_name: String,
    pub overwrite: bool,
    pub analyze: bool,
    pub language_id: String,
    pub compiler_spec_id: String,
    pub loader_class: String,
    pub loader_args: Vec<LoaderArg>,
}

#[derive(Debug, Clone, Default)]
pub struct ImportProgramResponse {
    pub program_paths: Vec<String>,
    pub primary_program_path: String,
}

#[derive(Debug, Clone, Default)]
pub struct OpenProgramRequest {
    pub project_path: String,
    pub project_name: String,
    pub program_path: String,
    pub analyze: bool,
    pub read_only: bool,
    pub language_id: String,
    pub compiler_spec_id: String,
    pub format: String,
    pub base_address: u64,
}

#[derive(Debug, Clone, Default)]
pub struct OpenProgramResponse {
    pub program_name: String,
    pub language_id: String,
    pub compiler_spec: String,
    pub image_base: u64,
    pub md5: String,
    pub sha256: String,
    pub executable_format: String,
    pub entry_point: u64,
    pub has_entry_point: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CloseProgramResponse {
    pub closed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SaveProgramResponse {
    pub saved: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DiscardProgramResponse {
    pub discarded: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RevisionResponse {
    pub program_id: u64,
    pub modification_number: u64,
    pub program_path: String,
    pub file_id: String,
    pub file_version: i32,
    pub file_last_modified_time: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ShutdownResponse {
    pub accepted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ReadBytesResponse {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct WriteBytesResponse {
    pub bytes_written: u32,
}

#[derive(Debug, Clone, Default)]
pub struct BytePatch {
    pub address: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct PatchBytesBatchResponse {
    pub patch_count: u32,
    pub bytes_written: u32,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryBlockRecord {
    pub name: String,
    pub start_address: u64,
    pub end_address: u64,
    pub size: u64,
    pub is_read: bool,
    pub is_write: bool,
    pub is_execute: bool,
    pub is_volatile: bool,
    pub is_initialized: bool,
    pub source_name: String,
    pub comment: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListMemoryBlocksResponse {
    pub blocks: Vec<MemoryBlockRecord>,
}

/// Spec for creating a new memory block (the writable memory map). Mirrors the
/// C++ `CreateMemoryBlockSpec`; `Default` yields a readable+writable,
/// non-executable, uninitialized, non-overlay block.
#[derive(Debug, Clone)]
pub struct CreateMemoryBlockSpec {
    pub name: String,
    pub start_address: u64,
    pub size: u64,
    pub is_read: bool,
    pub is_write: bool,
    pub is_execute: bool,
    pub initialized: bool,
    pub overlay: bool,
}

impl Default for CreateMemoryBlockSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            start_address: 0,
            size: 0,
            is_read: true,
            is_write: true,
            is_execute: false,
            initialized: false,
            overlay: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CreateMemoryBlockResponse {
    pub created: bool,
    pub block: Option<MemoryBlockRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct RemoveMemoryBlockResponse {
    pub removed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MoveMemoryBlockResponse {
    pub moved: bool,
    pub block: Option<MemoryBlockRecord>,
}

/// Attributes to change on an existing memory block.
///
/// Every field is optional and `None` means "leave alone", so a caller can flip a single
/// permission without restating (and clearing) the others. `end_address` is INCLUSIVE,
/// matching [`MemoryBlockRecord`].
#[derive(Debug, Clone, Default)]
pub struct SetMemoryBlockAttributesSpec {
    pub address: u64,
    pub name: Option<String>,
    pub is_read: Option<bool>,
    pub is_write: Option<bool>,
    pub is_execute: Option<bool>,
    pub end_address: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct SetMemoryBlockAttributesResponse {
    pub updated: bool,
    pub block: Option<MemoryBlockRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct FunctionRecord {
    pub entry_address: u64,
    pub name: String,
    pub start_address: u64,
    pub end_address: u64,
    pub size: u64,
    pub namespace_name: String,
    pub prototype: String,
    pub is_thunk: bool,
    pub parameter_count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct GetFunctionResponse {
    pub function: Option<FunctionRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct ListFunctionsResponse {
    pub functions: Vec<FunctionRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct RenameFunctionResponse {
    pub renamed: bool,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct BasicBlockRecord {
    pub function_entry: u64,
    pub start_address: u64,
    pub end_address: u64,
    pub in_degree: u32,
    pub out_degree: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ListBasicBlocksResponse {
    pub blocks: Vec<BasicBlockRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct CFGEdgeRecord {
    pub function_entry: u64,
    pub src_block_start: u64,
    pub dst_block_start: u64,
    pub edge_kind: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListCFGEdgesResponse {
    pub edges: Vec<CFGEdgeRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct SymbolRecord {
    pub symbol_id: u64,
    pub address: u64,
    pub name: String,
    pub full_name: String,
    pub r#type: String,
    pub namespace_name: String,
    pub source: String,
    pub is_primary: bool,
    pub is_external: bool,
    pub is_dynamic: bool,
    pub is_external_entry_point: bool,
}

#[derive(Debug, Clone, Default)]
pub struct GetSymbolResponse {
    pub symbol: Option<SymbolRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct ListSymbolsResponse {
    pub symbols: Vec<SymbolRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct RenameSymbolResponse {
    pub renamed: bool,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteSymbolResponse {
    pub deleted: bool,
    pub deleted_count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct XrefRecord {
    pub from_address: u64,
    pub to_address: u64,
    pub operand_index: i32,
    pub ref_type: String,
    pub is_primary: bool,
    pub source: String,
    pub symbol_id: i64,
    pub is_external: bool,
    pub is_memory: bool,
    pub is_flow: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListXrefsResponse {
    pub xrefs: Vec<XrefRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct StackVariableRecord {
    pub var_id: String,
    pub name: String,
    pub data_type: String,
    pub stack_offset: i64,
    pub size: u32,
    pub is_parameter: bool,
    pub first_use_offset: i32,
    pub source_type: String,
}

#[derive(Debug, Clone, Default)]
pub struct FunctionFrameRecord {
    pub function_entry: u64,
    pub frame_size: i64,
    pub local_size: i64,
    pub parameter_size: i64,
    pub parameter_offset: i64,
    pub return_address_offset: i64,
    pub grows_negative: bool,
    pub stack_pointer_register: String,
    pub stack_variables: Vec<StackVariableRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct PerfBenchmarkRecord {
    pub bench_id: String,
    pub query_family: String,
    pub dataset_profile: String,
    pub cold_ms_p50: f64,
    pub cold_ms_p95: f64,
    pub warm_ms_p50: f64,
    pub warm_ms_p95: f64,
    pub throughput_qps: f64,
    pub regression_pct: f64,
    pub status: String,
}

#[derive(Debug, Clone, Default)]
pub struct ClearPerfBenchmarksResponse {
    pub cleared: bool,
    pub removed_count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct TypeRecord {
    pub type_id: u64,
    pub name: String,
    pub path_name: String,
    pub category_path: String,
    pub display_name: String,
    pub kind: String,
    pub length: i32,
    pub is_not_yet_defined: bool,
    pub source_archive: String,
    pub universal_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct GetTypeResponse {
    pub r#type: Option<TypeRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct ListTypesResponse {
    pub types: Vec<TypeRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct TypeAliasRecord {
    pub type_id: u64,
    pub path_name: String,
    pub name: String,
    pub target_type: String,
    pub declaration: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListTypeAliasesResponse {
    pub aliases: Vec<TypeAliasRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct TypeUnionRecord {
    pub type_id: u64,
    pub path_name: String,
    pub name: String,
    pub size: u64,
    pub declaration: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListTypeUnionsResponse {
    pub unions: Vec<TypeUnionRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct TypeEnumRecord {
    pub type_id: u64,
    pub path_name: String,
    pub name: String,
    pub width: u64,
    pub is_signed: bool,
    pub declaration: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListTypeEnumsResponse {
    pub enums: Vec<TypeEnumRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct TypeEnumMemberRecord {
    pub type_id: u64,
    pub type_path_name: String,
    pub type_name: String,
    pub ordinal: u64,
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ListTypeEnumMembersResponse {
    pub members: Vec<TypeEnumMemberRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct TypeMemberRecord {
    pub parent_type_id: u64,
    pub parent_type_path_name: String,
    pub parent_type_name: String,
    pub ordinal: u64,
    pub name: String,
    pub member_type: String,
    pub offset: i64,
    pub size: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ListTypeMembersResponse {
    pub members: Vec<TypeMemberRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct ParameterRecord {
    pub ordinal: i32,
    pub name: String,
    pub data_type: String,
    pub formal_data_type: String,
    pub is_auto_parameter: bool,
    pub is_forced_indirect: bool,
}

#[derive(Debug, Clone, Default)]
pub struct FunctionSignatureRecord {
    pub function_entry_address: u64,
    pub function_name: String,
    pub prototype: String,
    pub return_type: String,
    pub has_var_args: bool,
    pub calling_convention: String,
    pub parameters: Vec<ParameterRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct GetFunctionSignatureResponse {
    pub signature: Option<FunctionSignatureRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct ListFunctionSignaturesResponse {
    pub signatures: Vec<FunctionSignatureRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct SetFunctionSignatureResponse {
    pub updated: bool,
    pub function_name: String,
    pub prototype: String,
}

#[derive(Debug, Clone, Default)]
pub struct RenameFunctionParameterResponse {
    pub updated: bool,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct SetFunctionParameterTypeResponse {
    pub updated: bool,
    pub data_type: String,
}

#[derive(Debug, Clone, Default)]
pub struct RenameFunctionLocalResponse {
    pub updated: bool,
    pub local_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct SetFunctionLocalTypeResponse {
    pub updated: bool,
    pub local_id: String,
    pub data_type: String,
}

#[derive(Debug, Clone, Default)]
pub struct ApplyDataTypeResponse {
    pub updated: bool,
    pub data_type: String,
}

#[derive(Debug, Clone, Default)]
pub struct CreateTypeResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteTypeResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RenameTypeResponse {
    pub updated: bool,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct CreateTypeAliasResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteTypeAliasResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetTypeAliasTargetResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CreateTypeEnumResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteTypeEnumResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AddTypeEnumMemberResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteTypeEnumMemberResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RenameTypeEnumMemberResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetTypeEnumMemberValueResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AddTypeMemberResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteTypeMemberResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RenameTypeMemberResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetTypeMemberTypeResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetTypeMemberCommentResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetTypeEnumMemberCommentResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DecompileLocalRecord {
    pub local_id: String,
    pub kind: DecompileLocalKind,
    pub name: String,
    pub data_type: String,
    pub storage: String,
    pub ordinal: i32,
}

#[derive(Debug, Clone, Default)]
pub struct DecompileTokenRecord {
    pub text: String,
    pub kind: DecompileTokenKind,
    pub line_number: i32,
    pub column_offset: i32,
    pub var_name: String,
    pub var_type: String,
    pub var_storage: String,
}

#[derive(Debug, Clone, Default)]
pub struct DecompilationRecord {
    pub function_entry_address: u64,
    pub function_name: String,
    pub prototype: String,
    pub pseudocode: String,
    pub completed: bool,
    pub is_fallback: bool,
    pub error_message: String,
    pub locals: Vec<DecompileLocalRecord>,
    pub tokens: Vec<DecompileTokenRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct GetDecompilationResponse {
    pub decompilation: Option<DecompilationRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct ListDecompilationsResponse {
    pub decompilations: Vec<DecompilationRecord>,
}

/// A single P-code varnode (operand). `kind` is the canonical operand kind:
/// `reg` / `imm` / `mem` / `result` / `var`.
#[derive(Debug, Clone, Default)]
pub struct VarnodeRecord {
    pub space: String,
    pub offset: u64,
    pub size: u32,
    pub kind: String,
}

/// A single high P-code (SSA) op. `op` is the canonical P-code mnemonic
/// (COPY, INT_ADD, LOAD, CALL, MULTIEQUAL, ...). `has_address` distinguishes a
/// real address zero from an op with no source address. `has_output` is false
/// when the op defines no varnode (RETURN, STORE, ...), in which case `output`
/// is default.
#[derive(Debug, Clone, Default)]
pub struct PcodeOpRecord {
    pub seq: u64,
    pub op: String,
    pub addr: u64,
    pub has_address: bool,
    pub has_output: bool,
    pub output: VarnodeRecord,
    pub inputs: Vec<VarnodeRecord>,
}

/// P-code maturity rung: `High` (refined SSA, `getPcodeOps`) or `Raw`
/// (per-instruction, non-SSA, `getPcode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PcodeMaturity {
    #[default]
    High,
    Raw,
}

/// A function's P-code op stream (the Ghidra leg of the cross-tool low-IR).
#[derive(Debug, Clone, Default)]
pub struct PcodeRecord {
    pub function_entry_address: u64,
    pub ops: Vec<PcodeOpRecord>,
    pub completed: bool,
    pub error_message: String,
    /// The rung actually produced (echoed by the host).
    pub maturity: PcodeMaturity,
}

#[derive(Debug, Clone, Default)]
pub struct GetPcodeResponse {
    pub pcode: Option<PcodeRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct SwitchCaseRecord {
    pub value: i64,
    pub target_address: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SwitchTableRecord {
    pub function_entry: u64,
    pub switch_address: u64,
    pub case_count: u32,
    pub cases: Vec<SwitchCaseRecord>,
    pub default_address: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ListSwitchTablesResponse {
    pub switch_tables: Vec<SwitchTableRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct DominatorRecord {
    pub function_entry: u64,
    pub block_address: u64,
    pub idom_address: u64,
    pub depth: u32,
    pub is_entry: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListDominatorsResponse {
    pub dominators: Vec<DominatorRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct PostDominatorRecord {
    pub function_entry: u64,
    pub block_address: u64,
    pub ipdom_address: u64,
    pub depth: u32,
    pub is_exit: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListPostDominatorsResponse {
    pub post_dominators: Vec<PostDominatorRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct LoopRecord {
    pub function_entry: u64,
    pub header_address: u64,
    pub back_edge_source: u64,
    pub loop_kind: String,
    pub block_count: u32,
    pub depth: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ListLoopsResponse {
    pub loops: Vec<LoopRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct InstructionRecord {
    pub address: u64,
    pub mnemonic: String,
    pub operand_text: String,
    pub disassembly: String,
    pub length: u32,
}

#[derive(Debug, Clone, Default)]
pub struct GetInstructionResponse {
    pub instruction: Option<InstructionRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct ListInstructionsResponse {
    pub instructions: Vec<InstructionRecord>,
}

/// One decoded operand of an instruction (the operand leg of the low-IR).
#[derive(Debug, Clone, Default)]
pub struct InstructionOperandRecord {
    pub address: u64,
    pub operand_index: u32,
    pub text: String,
    pub type_name: String,
    pub ref_type: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListInstructionOperandsResponse {
    pub operands: Vec<InstructionOperandRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct CommentRecord {
    pub address: u64,
    pub kind: CommentKind,
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct GetCommentsResponse {
    pub comments: Vec<CommentRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct SetCommentResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteCommentResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RenameDataItemResponse {
    pub updated: bool,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteDataItemResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DataItemRecord {
    pub address: u64,
    pub end_address: u64,
    pub name: String,
    pub data_type: String,
    pub size: u64,
    pub value_repr: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListDataItemsResponse {
    pub data_items: Vec<DataItemRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct BookmarkRecord {
    pub address: u64,
    pub r#type: String,
    pub category: String,
    pub comment: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListBookmarksResponse {
    pub bookmarks: Vec<BookmarkRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct AddBookmarkResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteBookmarkResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BreakpointRecord {
    pub address: u64,
    pub enabled: bool,
    pub kind: String,
    pub size: u64,
    pub condition: String,
    pub group: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListBreakpointsResponse {
    pub breakpoints: Vec<BreakpointRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct AddBreakpointResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetBreakpointEnabledResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetBreakpointKindResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetBreakpointSizeResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetBreakpointConditionResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetBreakpointGroupResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteBreakpointResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DefinedStringRecord {
    pub address: u64,
    pub value: String,
    pub length: u32,
    pub data_type: String,
    pub encoding: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListDefinedStringsResponse {
    pub strings: Vec<DefinedStringRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct FunctionTagRecord {
    pub name: String,
    pub comment: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListFunctionTagsResponse {
    pub tags: Vec<FunctionTagRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct CreateFunctionTagResponse {
    pub created: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteFunctionTagResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct FunctionTagMappingRecord {
    pub function_entry: u64,
    pub tag_name: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListFunctionTagMappingsResponse {
    pub mappings: Vec<FunctionTagMappingRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct TagFunctionResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct UntagFunctionResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ParseDeclarationsResponse {
    pub types_created: i32,
    pub type_names: Vec<String>,
    pub errors: Vec<String>,
}
