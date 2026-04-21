# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Typed model classes for the libghidra Python client.

All record and response types are plain dataclasses, decoupled from protobuf.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


# -- Enums -------------------------------------------------------------------


class ShutdownPolicy(IntEnum):
    UNSPECIFIED = 0
    SAVE = 1
    DISCARD = 2
    NONE = 3


class CommentKind(IntEnum):
    UNSPECIFIED = 0
    EOL = 1
    PRE = 2
    POST = 3
    PLATE = 4
    REPEATABLE = 5


class DecompileLocalKind(IntEnum):
    UNSPECIFIED = 0
    PARAM = 1
    LOCAL = 2
    TEMP = 3


class DecompileTokenKind(IntEnum):
    UNSPECIFIED = 0
    KEYWORD = 1
    COMMENT = 2
    TYPE = 3
    FUNCTION = 4
    VARIABLE = 5
    CONST = 6
    PARAMETER = 7
    GLOBAL = 8
    DEFAULT = 9
    ERROR = 10
    SPECIAL = 11


# -- Records -----------------------------------------------------------------


@dataclass
class Capability:
    id: str = ""
    status: str = ""
    note: str = ""


@dataclass
class HealthStatus:
    ok: bool = False
    service_name: str = ""
    service_version: str = ""
    host_mode: str = ""
    program_revision: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass
class OpenProgramRequest:
    project_path: str = ""
    project_name: str = ""
    program_path: str = ""
    analyze: bool = False
    read_only: bool = False


@dataclass
class OpenProgramResponse:
    program_name: str = ""
    language_id: str = ""
    compiler_spec: str = ""
    image_base: int = 0


@dataclass
class CloseProgramResponse:
    closed: bool = False


@dataclass
class SaveProgramResponse:
    saved: bool = False


@dataclass
class DiscardProgramResponse:
    discarded: bool = False


@dataclass
class RevisionResponse:
    revision: int = 0


@dataclass
class ShutdownResponse:
    accepted: bool = False


@dataclass
class ReadBytesResponse:
    data: bytes = b""


@dataclass
class WriteBytesResponse:
    bytes_written: int = 0


@dataclass
class BytePatch:
    address: int = 0
    data: bytes = b""


@dataclass
class PatchBytesBatchResponse:
    patch_count: int = 0
    bytes_written: int = 0


@dataclass
class MemoryBlockRecord:
    name: str = ""
    start_address: int = 0
    end_address: int = 0
    size: int = 0
    is_read: bool = False
    is_write: bool = False
    is_execute: bool = False
    is_volatile: bool = False
    is_initialized: bool = False
    source_name: str = ""
    comment: str = ""


@dataclass
class ListMemoryBlocksResponse:
    blocks: list[MemoryBlockRecord] = field(default_factory=list)


@dataclass
class FunctionRecord:
    entry_address: int = 0
    name: str = ""
    start_address: int = 0
    end_address: int = 0
    size: int = 0
    namespace_name: str = ""
    prototype: str = ""
    is_thunk: bool = False
    parameter_count: int = 0


@dataclass
class GetFunctionResponse:
    function: FunctionRecord | None = None


@dataclass
class ListFunctionsResponse:
    functions: list[FunctionRecord] = field(default_factory=list)


@dataclass
class RenameFunctionResponse:
    renamed: bool = False
    name: str = ""


@dataclass
class BasicBlockRecord:
    function_entry: int = 0
    start_address: int = 0
    end_address: int = 0
    in_degree: int = 0
    out_degree: int = 0


@dataclass
class ListBasicBlocksResponse:
    blocks: list[BasicBlockRecord] = field(default_factory=list)


@dataclass
class CFGEdgeRecord:
    function_entry: int = 0
    src_block_start: int = 0
    dst_block_start: int = 0
    edge_kind: str = ""


@dataclass
class ListCFGEdgesResponse:
    edges: list[CFGEdgeRecord] = field(default_factory=list)


@dataclass
class SymbolRecord:
    symbol_id: int = 0
    address: int = 0
    name: str = ""
    full_name: str = ""
    type: str = ""
    namespace_name: str = ""
    source: str = ""
    is_primary: bool = False
    is_external: bool = False
    is_dynamic: bool = False


@dataclass
class GetSymbolResponse:
    symbol: SymbolRecord | None = None


@dataclass
class ListSymbolsResponse:
    symbols: list[SymbolRecord] = field(default_factory=list)


@dataclass
class RenameSymbolResponse:
    renamed: bool = False
    name: str = ""


@dataclass
class DeleteSymbolResponse:
    deleted: bool = False
    deleted_count: int = 0


@dataclass
class XrefRecord:
    from_address: int = 0
    to_address: int = 0
    operand_index: int = 0
    ref_type: str = ""
    is_primary: bool = False
    source: str = ""
    symbol_id: int = 0
    is_external: bool = False
    is_memory: bool = False
    is_flow: bool = False


@dataclass
class ListXrefsResponse:
    xrefs: list[XrefRecord] = field(default_factory=list)


@dataclass
class TypeRecord:
    type_id: int = 0
    name: str = ""
    path_name: str = ""
    category_path: str = ""
    display_name: str = ""
    kind: str = ""
    length: int = 0
    is_not_yet_defined: bool = False
    source_archive: str = ""
    universal_id: str = ""


@dataclass
class GetTypeResponse:
    type: TypeRecord | None = None


@dataclass
class ListTypesResponse:
    types: list[TypeRecord] = field(default_factory=list)


@dataclass
class TypeAliasRecord:
    type_id: int = 0
    path_name: str = ""
    name: str = ""
    target_type: str = ""
    declaration: str = ""


@dataclass
class ListTypeAliasesResponse:
    aliases: list[TypeAliasRecord] = field(default_factory=list)


@dataclass
class TypeUnionRecord:
    type_id: int = 0
    path_name: str = ""
    name: str = ""
    size: int = 0
    declaration: str = ""


@dataclass
class ListTypeUnionsResponse:
    unions: list[TypeUnionRecord] = field(default_factory=list)


@dataclass
class TypeEnumRecord:
    type_id: int = 0
    path_name: str = ""
    name: str = ""
    width: int = 0
    is_signed: bool = False
    declaration: str = ""


@dataclass
class ListTypeEnumsResponse:
    enums: list[TypeEnumRecord] = field(default_factory=list)


@dataclass
class TypeEnumMemberRecord:
    type_id: int = 0
    type_path_name: str = ""
    type_name: str = ""
    ordinal: int = 0
    name: str = ""
    value: int = 0


@dataclass
class ListTypeEnumMembersResponse:
    members: list[TypeEnumMemberRecord] = field(default_factory=list)


@dataclass
class TypeMemberRecord:
    parent_type_id: int = 0
    parent_type_path_name: str = ""
    parent_type_name: str = ""
    ordinal: int = 0
    name: str = ""
    member_type: str = ""
    offset: int = 0
    size: int = 0


@dataclass
class ListTypeMembersResponse:
    members: list[TypeMemberRecord] = field(default_factory=list)


@dataclass
class ParameterRecord:
    ordinal: int = 0
    name: str = ""
    data_type: str = ""
    formal_data_type: str = ""
    is_auto_parameter: bool = False
    is_forced_indirect: bool = False


@dataclass
class FunctionSignatureRecord:
    function_entry_address: int = 0
    function_name: str = ""
    prototype: str = ""
    return_type: str = ""
    has_var_args: bool = False
    calling_convention: str = ""
    parameters: list[ParameterRecord] = field(default_factory=list)


@dataclass
class GetFunctionSignatureResponse:
    signature: FunctionSignatureRecord | None = None


@dataclass
class ListFunctionSignaturesResponse:
    signatures: list[FunctionSignatureRecord] = field(default_factory=list)


@dataclass
class SetFunctionSignatureResponse:
    updated: bool = False
    function_name: str = ""
    prototype: str = ""


@dataclass
class RenameFunctionParameterResponse:
    updated: bool = False
    name: str = ""


@dataclass
class SetFunctionParameterTypeResponse:
    updated: bool = False
    data_type: str = ""


@dataclass
class RenameFunctionLocalResponse:
    updated: bool = False
    local_id: str = ""
    name: str = ""


@dataclass
class SetFunctionLocalTypeResponse:
    updated: bool = False
    local_id: str = ""
    data_type: str = ""


@dataclass
class ApplyDataTypeResponse:
    updated: bool = False
    data_type: str = ""


@dataclass
class CreateTypeResponse:
    updated: bool = False


@dataclass
class DeleteTypeResponse:
    deleted: bool = False


@dataclass
class RenameTypeResponse:
    updated: bool = False
    name: str = ""


@dataclass
class CreateTypeAliasResponse:
    updated: bool = False


@dataclass
class DeleteTypeAliasResponse:
    deleted: bool = False


@dataclass
class SetTypeAliasTargetResponse:
    updated: bool = False


@dataclass
class CreateTypeEnumResponse:
    updated: bool = False


@dataclass
class DeleteTypeEnumResponse:
    deleted: bool = False


@dataclass
class AddTypeEnumMemberResponse:
    updated: bool = False


@dataclass
class DeleteTypeEnumMemberResponse:
    deleted: bool = False


@dataclass
class RenameTypeEnumMemberResponse:
    updated: bool = False


@dataclass
class SetTypeEnumMemberValueResponse:
    updated: bool = False


@dataclass
class AddTypeMemberResponse:
    updated: bool = False


@dataclass
class DeleteTypeMemberResponse:
    deleted: bool = False


@dataclass
class RenameTypeMemberResponse:
    updated: bool = False


@dataclass
class SetTypeMemberTypeResponse:
    updated: bool = False


@dataclass
class DecompileLocalRecord:
    local_id: str = ""
    kind: DecompileLocalKind = DecompileLocalKind.UNSPECIFIED
    name: str = ""
    data_type: str = ""
    storage: str = ""
    ordinal: int = -1


@dataclass
class DecompileTokenRecord:
    text: str = ""
    kind: DecompileTokenKind = DecompileTokenKind.UNSPECIFIED
    line_number: int = -1
    column_offset: int = -1
    var_name: str = ""
    var_type: str = ""
    var_storage: str = ""


@dataclass
class DecompilationRecord:
    function_entry_address: int = 0
    function_name: str = ""
    prototype: str = ""
    pseudocode: str = ""
    completed: bool = False
    is_fallback: bool = False
    error_message: str = ""
    locals: list[DecompileLocalRecord] = field(default_factory=list)
    tokens: list[DecompileTokenRecord] = field(default_factory=list)


@dataclass
class GetDecompilationResponse:
    decompilation: DecompilationRecord | None = None


@dataclass
class ListDecompilationsResponse:
    decompilations: list[DecompilationRecord] = field(default_factory=list)


@dataclass
class SwitchCaseRecord:
    value: int = 0
    target_address: int = 0


@dataclass
class SwitchTableRecord:
    function_entry: int = 0
    switch_address: int = 0
    case_count: int = 0
    cases: list[SwitchCaseRecord] = field(default_factory=list)
    default_address: int = 0


@dataclass
class ListSwitchTablesResponse:
    switch_tables: list[SwitchTableRecord] = field(default_factory=list)


@dataclass
class DominatorRecord:
    function_entry: int = 0
    block_address: int = 0
    idom_address: int = 0
    depth: int = 0
    is_entry: bool = False


@dataclass
class ListDominatorsResponse:
    dominators: list[DominatorRecord] = field(default_factory=list)


@dataclass
class PostDominatorRecord:
    function_entry: int = 0
    block_address: int = 0
    ipdom_address: int = 0
    depth: int = 0
    is_exit: bool = False


@dataclass
class ListPostDominatorsResponse:
    post_dominators: list[PostDominatorRecord] = field(default_factory=list)


@dataclass
class LoopRecord:
    function_entry: int = 0
    header_address: int = 0
    back_edge_source: int = 0
    loop_kind: str = ""
    block_count: int = 0
    depth: int = 0


@dataclass
class ListLoopsResponse:
    loops: list[LoopRecord] = field(default_factory=list)


@dataclass
class InstructionRecord:
    address: int = 0
    mnemonic: str = ""
    operand_text: str = ""
    disassembly: str = ""
    length: int = 0


@dataclass
class GetInstructionResponse:
    instruction: InstructionRecord | None = None


@dataclass
class ListInstructionsResponse:
    instructions: list[InstructionRecord] = field(default_factory=list)


@dataclass
class CommentRecord:
    address: int = 0
    kind: CommentKind = CommentKind.UNSPECIFIED
    text: str = ""


@dataclass
class GetCommentsResponse:
    comments: list[CommentRecord] = field(default_factory=list)


@dataclass
class SetCommentResponse:
    updated: bool = False


@dataclass
class DeleteCommentResponse:
    deleted: bool = False


@dataclass
class RenameDataItemResponse:
    updated: bool = False
    name: str = ""


@dataclass
class DeleteDataItemResponse:
    deleted: bool = False


@dataclass
class DataItemRecord:
    address: int = 0
    end_address: int = 0
    name: str = ""
    data_type: str = ""
    size: int = 0
    value_repr: str = ""


@dataclass
class ListDataItemsResponse:
    data_items: list[DataItemRecord] = field(default_factory=list)


@dataclass
class BookmarkRecord:
    address: int = 0
    type: str = ""
    category: str = ""
    comment: str = ""


@dataclass
class ListBookmarksResponse:
    bookmarks: list[BookmarkRecord] = field(default_factory=list)


@dataclass
class AddBookmarkResponse:
    updated: bool = False


@dataclass
class DeleteBookmarkResponse:
    deleted: bool = False


@dataclass
class BreakpointRecord:
    address: int = 0
    enabled: bool = False
    kind: str = ""
    size: int = 0
    condition: str = ""
    group: str = ""


@dataclass
class ListBreakpointsResponse:
    breakpoints: list[BreakpointRecord] = field(default_factory=list)


@dataclass
class AddBreakpointResponse:
    updated: bool = False


@dataclass
class SetBreakpointEnabledResponse:
    updated: bool = False


@dataclass
class SetBreakpointKindResponse:
    updated: bool = False


@dataclass
class SetBreakpointSizeResponse:
    updated: bool = False


@dataclass
class SetBreakpointConditionResponse:
    updated: bool = False


@dataclass
class SetBreakpointGroupResponse:
    updated: bool = False


@dataclass
class DeleteBreakpointResponse:
    deleted: bool = False


@dataclass
class DefinedStringRecord:
    address: int = 0
    value: str = ""
    length: int = 0
    data_type: str = ""
    encoding: str = ""


@dataclass
class ListDefinedStringsResponse:
    strings: list[DefinedStringRecord] = field(default_factory=list)


@dataclass
class FunctionTagRecord:
    name: str = ""
    comment: str = ""


@dataclass
class ListFunctionTagsResponse:
    tags: list[FunctionTagRecord] = field(default_factory=list)


@dataclass
class CreateFunctionTagResponse:
    created: bool = False


@dataclass
class DeleteFunctionTagResponse:
    deleted: bool = False


@dataclass
class FunctionTagMappingRecord:
    function_entry: int = 0
    tag_name: str = ""


@dataclass
class ListFunctionTagMappingsResponse:
    mappings: list[FunctionTagMappingRecord] = field(default_factory=list)


@dataclass
class TagFunctionResponse:
    updated: bool = False


@dataclass
class UntagFunctionResponse:
    updated: bool = False


@dataclass
class ParseDeclarationsResponse:
    types_created: int = 0
    type_names: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
