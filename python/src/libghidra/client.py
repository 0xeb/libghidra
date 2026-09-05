# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.

"""Synchronous HTTP client for the libghidra typed RPC layer."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import TypeVar

import requests
from google.protobuf import any_pb2
from google.protobuf.message import Message

from . import (
    common_pb2,
    decompiler_pb2,
    functions_pb2,
    health_pb2,
    listing_pb2,
    memory_pb2,
    rpc_pb2,
    session_pb2,
    symbols_pb2,
    types_pb2,
    xrefs_pb2,
)
from .errors import ErrorCode, GhidraError
from .models import (
    AddBookmarkResponse,
    AddBreakpointResponse,
    AddTypeEnumMemberResponse,
    AddTypeMemberResponse,
    ApplyDataTypeResponse,
    BasicBlockRecord,
    BookmarkRecord,
    BreakpointRecord,
    BytePatch,
    Capability,
    CFGEdgeRecord,
    CommentKind,
    CommentRecord,
    CreateTypeAliasResponse,
    CreateTypeEnumResponse,
    CreateFunctionTagResponse,
    CreateTypeResponse,
    DataItemRecord,
    DecompileLocalKind,
    DecompileLocalRecord,
    DecompileTokenKind,
    DecompileTokenRecord,
    DecompilationRecord,
    DefinedStringRecord,
    DeleteBookmarkResponse,
    DeleteBreakpointResponse,
    DeleteCommentResponse,
    DeleteDataItemResponse,
    DeleteFunctionTagResponse,
    DeleteSymbolResponse,
    DeleteTypeAliasResponse,
    DeleteTypeEnumMemberResponse,
    DeleteTypeEnumResponse,
    DeleteTypeMemberResponse,
    DeleteTypeResponse,
    DiscardProgramResponse,
    DominatorRecord,
    FunctionRecord,
    FunctionSignatureRecord,
    FunctionTagMappingRecord,
    FunctionTagRecord,
    GetCommentsResponse,
    GetDecompilationResponse,
    GetFunctionResponse,
    GetFunctionSignatureResponse,
    GetInstructionResponse,
    GetSymbolResponse,
    GetTypeResponse,
    HealthStatus,
    InstructionOperandRecord,
    InstructionRecord,
    ListBasicBlocksResponse,
    ListBookmarksResponse,
    ListBreakpointsResponse,
    ListCFGEdgesResponse,
    ListDataItemsResponse,
    ListDecompilationsResponse,
    GetPcodeResponse,
    PcodeMaturity,
    PcodeOpRecord,
    PcodeRecord,
    VarnodeRecord,
    ListDefinedStringsResponse,
    ListDominatorsResponse,
    ListFunctionsResponse,
    ListFunctionSignaturesResponse,
    ListFunctionTagMappingsResponse,
    ListFunctionTagsResponse,
    ListInstructionOperandsResponse,
    ListInstructionsResponse,
    ListLoopsResponse,
    ListMemoryBlocksResponse,
    CreateMemoryBlockSpec,
    CreateMemoryBlockResponse,
    RemoveMemoryBlockResponse,
    MoveMemoryBlockResponse,
    SetMemoryBlockAttributesResponse,
    SetTypeMemberCommentResponse,
    SetTypeEnumMemberCommentResponse,
    ListPostDominatorsResponse,
    ListSwitchTablesResponse,
    ListSymbolsResponse,
    ListTypeMembersResponse,
    ListTypeAliasesResponse,
    ListTypeEnumMembersResponse,
    ListTypeEnumsResponse,
    ListTypesResponse,
    ListTypeUnionsResponse,
    ListXrefsResponse,
    LoopRecord,
    MemoryBlockRecord,
    CloseProjectResponse,
    OpenProgramRequest,
    OpenProgramResponse,
    OpenProjectRequest,
    OpenProjectResponse,
    ParameterRecord,
    PostDominatorRecord,
    ParseDeclarationsResponse,
    PatchBytesBatchResponse,
    ProjectFile,
    ReadBytesResponse,
    RenameFunctionParameterResponse,
    RenameFunctionResponse,
    RenameDataItemResponse,
    RenameSymbolResponse,
    RenameTypeEnumMemberResponse,
    RenameTypeMemberResponse,
    RenameTypeResponse,
    RevisionResponse,
    SaveProgramResponse,
    SetBreakpointConditionResponse,
    SetBreakpointEnabledResponse,
    SetBreakpointGroupResponse,
    SetBreakpointKindResponse,
    SetBreakpointSizeResponse,
    SetCommentResponse,
    SetFunctionLocalTypeResponse,
    SetFunctionParameterTypeResponse,
    SetFunctionSignatureResponse,
    SetTypeAliasTargetResponse,
    SetTypeEnumMemberValueResponse,
    SetTypeMemberTypeResponse,
    ShutdownPolicy,
    ShutdownResponse,
    SwitchCaseRecord,
    SwitchTableRecord,
    SymbolRecord,
    TagFunctionResponse,
    TypeAliasRecord,
    TypeEnumMemberRecord,
    TypeEnumRecord,
    TypeMemberRecord,
    TypeRecord,
    TypeUnionRecord,
    UntagFunctionResponse,
    WriteBytesResponse,
    XrefRecord,
    ImportProgramRequest,
    ImportProgramResponse,
    ListProjectFilesRequest,
    ListProjectFilesResponse,
    CloseProgramResponse,
    LoaderArg,
    RenameFunctionLocalResponse,
    ClearPerfBenchmarksResponse,
    FunctionFrameRecord,
    PerfBenchmarkRecord,
    StackVariableRecord,
)


def _to_xref(record: Message) -> XrefRecord:
    return XrefRecord(
        from_address=record.from_address,
        to_address=record.to_address,
        operand_index=record.operand_index,
        ref_type=record.ref_type,
        is_primary=record.is_primary,
        source=record.source,
        symbol_id=record.symbol_id,
        is_external=record.is_external,
        is_memory=record.is_memory,
        is_flow=record.is_flow,
        from_function_address=record.from_function_address,
        from_function_name=record.from_function_name,
        to_function_address=record.to_function_address,
        to_function_name=record.to_function_name,
    )

T = TypeVar("T", bound=Message)


# ---------------------------------------------------------------------------
# Client options
# ---------------------------------------------------------------------------


@dataclass
class ClientOptions:
    base_url: str = "http://127.0.0.1:18080"
    auth_token: str = ""
    connect_timeout: float = 3.0
    read_timeout: float = 120.0
    max_retries: int = 0
    initial_backoff: float = 0.1
    max_backoff: float = 5.0
    jitter: bool = True


# ---------------------------------------------------------------------------
# GhidraClient
# ---------------------------------------------------------------------------


class GhidraClient:
    """Synchronous HTTP client for the Ghidra RPC API.

    Mirrors the C++ ``IClient`` interface and the Rust ``GhidraClient``.
    Transport is binary protobuf over ``POST /rpc``.
    """

    def __init__(self, options: ClientOptions | None = None) -> None:
        self._options = options or ClientOptions()
        self._rpc_url = f"{self._options.base_url.rstrip('/')}/rpc"
        self._http = requests.Session()

    # -- Core transport --------------------------------------------------------

    def _call_rpc(self, method: str, request: Message, resp_class: type[T]) -> T:
        """Serialize *request* into an RpcRequest envelope and POST it."""
        payload_any = any_pb2.Any()
        payload_any.Pack(request)

        rpc_req = rpc_pb2.RpcRequest(method=method, payload=payload_any)
        encoded = rpc_req.SerializeToString()

        max_attempts = self._options.max_retries + 1
        last_err: GhidraError | None = None

        for attempt in range(max_attempts):
            try:
                body = self._post_raw(encoded)
            except GhidraError as exc:
                last_err = exc
                if not exc.code.is_retryable() or attempt + 1 >= max_attempts:
                    break
                time.sleep(self._backoff(attempt))
                continue

            return self._parse_rpc_response(body, resp_class, method)

        raise last_err  # type: ignore[misc]

    def _post_raw(self, body: bytes) -> bytes:
        headers = {"Content-Type": "application/x-protobuf"}
        if self._options.auth_token:
            headers["Authorization"] = f"Bearer {self._options.auth_token}"

        try:
            resp = self._http.post(
                self._rpc_url,
                data=body,
                headers=headers,
                timeout=(self._options.connect_timeout, self._options.read_timeout),
            )
        except requests.ConnectionError as exc:
            raise GhidraError(ErrorCode.CONNECTION_FAILED, str(exc)) from exc
        except requests.Timeout as exc:
            raise GhidraError(ErrorCode.TIMEOUT, str(exc)) from exc
        except requests.RequestException as exc:
            raise GhidraError(ErrorCode.TRANSPORT_ERROR, str(exc)) from exc

        if not 200 <= resp.status_code < 300:
            raise GhidraError(
                ErrorCode.from_http_status(resp.status_code),
                f"HTTP status {resp.status_code} for /rpc",
            )
        return resp.content

    def _parse_rpc_response(self, body: bytes, resp_class: type[T], method: str) -> T:
        rpc_resp = rpc_pb2.RpcResponse()
        rpc_resp.ParseFromString(body)

        if not rpc_resp.success:
            code = (
                ErrorCode.from_rpc_code(rpc_resp.error_code)
                if rpc_resp.error_code
                else ErrorCode.API_ERROR
            )
            message = rpc_resp.error_message or "RPC returned success=false"
            raise GhidraError(code, message)

        result = resp_class()
        if rpc_resp.HasField("payload"):
            rpc_resp.payload.Unpack(result)
        return result

    def _backoff(self, attempt: int) -> float:
        delay = min(
            self._options.initial_backoff * (2**attempt),
            self._options.max_backoff,
        )
        if self._options.jitter:
            delay *= random.random()  # noqa: S311
        return delay

    # -- Helpers ---------------------------------------------------------------

    @staticmethod
    def _pagination(limit: int, offset: int) -> common_pb2.Pagination:
        return common_pb2.Pagination(limit=max(limit, 0), offset=max(offset, 0))

    @staticmethod
    def _address_range(start: int, end: int) -> common_pb2.AddressRange:
        # end == 0 is the "list all" sentinel: the host treats range_end as an
        # exclusive upper bound and an unsigned value, so 0 would select an empty
        # range. Normalize it to the full 64-bit space (matches the C++ client's
        # range_end = UINT64_MAX convention).
        if end == 0:
            end = 0xFFFFFFFFFFFFFFFF
        return common_pb2.AddressRange(start=start, end=end)

    # =========================================================================
    # Health
    # =========================================================================

    def get_status(self) -> HealthStatus:
        req = health_pb2.HealthStatusRequest()
        resp = self._call_rpc(
            "libghidra.HealthService/GetStatus",
            req,
            health_pb2.HealthStatusResponse,
        )
        return HealthStatus(
            ok=resp.ok,
            service_name=resp.service_name,
            service_version=resp.service_version,
            host_mode=resp.host_mode,
            modification_number=resp.modification_number,
            warnings=list(resp.warnings),
        )

    def get_capabilities(self) -> list[Capability]:
        req = health_pb2.CapabilityRequest()
        resp = self._call_rpc(
            "libghidra.HealthService/GetCapabilities",
            req,
            health_pb2.CapabilityResponse,
        )
        return [
            Capability(id=c.id, status=c.status, note=c.note)
            for c in resp.capabilities
        ]

    # =========================================================================
    # Session
    # =========================================================================

    def open_project(self, request: OpenProjectRequest) -> OpenProjectResponse:
        req = session_pb2.OpenProjectRequest(
            project_path=request.project_path,
            project_name=request.project_name,
            create=request.create,
            read_only=request.read_only,
        )
        resp = self._call_rpc(
            "libghidra.SessionService/OpenProject",
            req,
            session_pb2.OpenProjectResponse,
        )
        return OpenProjectResponse(
            project_path=resp.project_path,
            project_name=resp.project_name,
            created=resp.created,
        )

    def close_project(self, policy: ShutdownPolicy = ShutdownPolicy.UNSPECIFIED) -> CloseProjectResponse:
        req = session_pb2.CloseProjectRequest(
            shutdown_policy=int(policy),
        )
        resp = self._call_rpc(
            "libghidra.SessionService/CloseProject",
            req,
            session_pb2.CloseProjectResponse,
        )
        return CloseProjectResponse(closed=resp.closed)

    def list_project_files(
        self,
        request: ListProjectFilesRequest | None = None,
    ) -> ListProjectFilesResponse:
        request = request or ListProjectFilesRequest()
        req = session_pb2.ListProjectFilesRequest(
            include_folders=request.include_folders,
            programs_only=request.programs_only,
        )
        resp = self._call_rpc(
            "libghidra.SessionService/ListProjectFiles",
            req,
            session_pb2.ListProjectFilesResponse,
        )
        return ListProjectFilesResponse(
            files=[
                ProjectFile(
                    path=f.path,
                    name=f.name,
                    folder_path=f.folder_path,
                    content_type=f.content_type,
                    domain_object_class=f.domain_object_class,
                    is_folder=f.is_folder,
                    is_program=f.is_program,
                )
                for f in resp.files
            ],
        )

    def import_program(self, request: ImportProgramRequest) -> ImportProgramResponse:
        req = session_pb2.ImportProgramRequest(
            source_path=request.source_path,
            project_folder_path=request.project_folder_path,
            program_name=request.program_name,
            overwrite=request.overwrite,
            analyze=request.analyze,
            language_id=request.language_id,
            compiler_spec_id=request.compiler_spec_id,
            loader_class=request.loader_class,
            loader_args=[
                session_pb2.LoaderArg(name=arg.name, value=arg.value)
                for arg in request.loader_args
            ],
        )
        resp = self._call_rpc(
            "libghidra.SessionService/ImportProgram",
            req,
            session_pb2.ImportProgramResponse,
        )
        return ImportProgramResponse(
            program_paths=list(resp.program_paths),
            primary_program_path=resp.primary_program_path,
        )

    def open_program(self, request: OpenProgramRequest) -> OpenProgramResponse:
        req = session_pb2.OpenProgramRequest(
            project_path=request.project_path,
            project_name=request.project_name,
            program_path=request.program_path,
            analyze=request.analyze,
            read_only=request.read_only,
            language_id=request.language_id,
            compiler_spec_id=request.compiler_spec_id,
            format=request.format,
            base_address=request.base_address,
        )
        resp = self._call_rpc(
            "libghidra.SessionService/OpenProgram",
            req,
            session_pb2.OpenProgramResponse,
        )
        return OpenProgramResponse(
            program_name=resp.program_name,
            language_id=resp.language_id,
            compiler_spec=resp.compiler_spec,
            image_base=resp.image_base,
            md5=resp.md5,
            sha256=resp.sha256,
            executable_format=resp.executable_format,
            entry_point=resp.entry_point,
            has_entry_point=resp.has_entry_point,
        )

    def close_program(self, policy: ShutdownPolicy = ShutdownPolicy.UNSPECIFIED) -> CloseProgramResponse:
        req = session_pb2.CloseProgramRequest(
            shutdown_policy=int(policy),
        )
        resp = self._call_rpc(
            "libghidra.SessionService/CloseProgram",
            req,
            session_pb2.CloseProgramResponse,
        )
        return CloseProgramResponse(closed=resp.closed)

    def save_program(self) -> SaveProgramResponse:
        req = session_pb2.SaveProgramRequest()
        resp = self._call_rpc(
            "libghidra.SessionService/SaveProgram",
            req,
            session_pb2.SaveProgramResponse,
        )
        return SaveProgramResponse(saved=resp.saved)

    def discard_program(self) -> DiscardProgramResponse:
        req = session_pb2.DiscardProgramRequest()
        resp = self._call_rpc(
            "libghidra.SessionService/DiscardProgram",
            req,
            session_pb2.DiscardProgramResponse,
        )
        return DiscardProgramResponse(discarded=resp.discarded)

    def get_revision(self) -> RevisionResponse:
        req = session_pb2.GetRevisionRequest()
        resp = self._call_rpc(
            "libghidra.SessionService/GetRevision",
            req,
            session_pb2.GetRevisionResponse,
        )
        return RevisionResponse(
            program_id=resp.program_id,
            modification_number=resp.modification_number,
            program_path=resp.program_path,
            file_id=resp.file_id,
            file_version=resp.file_version,
            file_last_modified_time=resp.file_last_modified_time,
        )

    def shutdown(self, policy: ShutdownPolicy = ShutdownPolicy.UNSPECIFIED) -> ShutdownResponse:
        req = session_pb2.ShutdownRequest(shutdown_policy=int(policy))
        resp = self._call_rpc(
            "libghidra.SessionService/Shutdown",
            req,
            session_pb2.ShutdownResponse,
        )
        return ShutdownResponse(accepted=resp.accepted)

    def add_perf_benchmark(self, record: PerfBenchmarkRecord) -> bool:
        req = session_pb2.AddPerfBenchmarkRequest(record=_perf_to_pb(record))
        resp = self._call_rpc(
            "libghidra.SessionService/AddPerfBenchmark",
            req,
            session_pb2.AddPerfBenchmarkResponse,
        )
        return resp.added

    def list_perf_benchmarks(self) -> list[PerfBenchmarkRecord]:
        req = session_pb2.ListPerfBenchmarksRequest()
        resp = self._call_rpc(
            "libghidra.SessionService/ListPerfBenchmarks",
            req,
            session_pb2.ListPerfBenchmarksResponse,
        )
        return [_perf_from_pb(r) for r in resp.records]

    def clear_perf_benchmarks(self) -> ClearPerfBenchmarksResponse:
        req = session_pb2.ClearPerfBenchmarksRequest()
        resp = self._call_rpc(
            "libghidra.SessionService/ClearPerfBenchmarks",
            req,
            session_pb2.ClearPerfBenchmarksResponse,
        )
        return ClearPerfBenchmarksResponse(
            cleared=resp.cleared, removed_count=resp.removed_count,
        )

    def delete_perf_benchmark(self, bench_id: str) -> bool:
        req = session_pb2.DeletePerfBenchmarkRequest(bench_id=bench_id)
        resp = self._call_rpc(
            "libghidra.SessionService/DeletePerfBenchmark",
            req,
            session_pb2.DeletePerfBenchmarkResponse,
        )
        return resp.deleted

    # =========================================================================
    # Memory
    # =========================================================================

    def read_bytes(self, address: int, length: int) -> ReadBytesResponse:
        req = memory_pb2.ReadBytesRequest(
            address=address, length=length,
        )
        resp = self._call_rpc(
            "libghidra.MemoryService/ReadBytes",
            req,
            memory_pb2.ReadBytesResponse,
        )
        return ReadBytesResponse(data=bytes(resp.data))

    def write_bytes(self, address: int, data: bytes) -> WriteBytesResponse:
        req = memory_pb2.WriteBytesRequest(
            address=address, data=data,
        )
        resp = self._call_rpc(
            "libghidra.MemoryService/WriteBytes",
            req,
            memory_pb2.WriteBytesResponse,
        )
        return WriteBytesResponse(bytes_written=resp.bytes_written)

    def patch_bytes_batch(self, patches: list[BytePatch]) -> PatchBytesBatchResponse:
        pb_cls = memory_pb2.BytePatch
        req = memory_pb2.PatchBytesBatchRequest(
            patches=[pb_cls(address=p.address, data=p.data) for p in patches],
        )
        resp = self._call_rpc(
            "libghidra.MemoryService/PatchBytesBatch",
            req,
            memory_pb2.PatchBytesBatchResponse,
        )
        return PatchBytesBatchResponse(
            patch_count=resp.patch_count, bytes_written=resp.bytes_written,
        )

    def list_memory_blocks(self, limit: int = 0, offset: int = 0) -> ListMemoryBlocksResponse:
        req = memory_pb2.ListMemoryBlocksRequest(
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.MemoryService/ListMemoryBlocks",
            req,
            memory_pb2.ListMemoryBlocksResponse,
        )
        return ListMemoryBlocksResponse(blocks=[_to_memory_block(b) for b in resp.blocks])

    def create_memory_block(self, spec: CreateMemoryBlockSpec) -> CreateMemoryBlockResponse:
        req = memory_pb2.CreateMemoryBlockRequest(
            name=spec.name, start_address=spec.start_address, size=spec.size,
            is_read=spec.is_read, is_write=spec.is_write, is_execute=spec.is_execute,
            initialized=spec.initialized, overlay=spec.overlay,
        )
        resp = self._call_rpc(
            "libghidra.MemoryService/CreateMemoryBlock",
            req,
            memory_pb2.CreateMemoryBlockResponse,
        )
        return CreateMemoryBlockResponse(
            created=resp.created,
            block=_to_memory_block(resp.block) if resp.HasField("block") else None,
        )

    def remove_memory_block(self, address: int) -> RemoveMemoryBlockResponse:
        req = memory_pb2.RemoveMemoryBlockRequest(address=address)
        resp = self._call_rpc(
            "libghidra.MemoryService/RemoveMemoryBlock",
            req,
            memory_pb2.RemoveMemoryBlockResponse,
        )
        return RemoveMemoryBlockResponse(removed=resp.removed)

    def move_memory_block(self, address: int, new_start_address: int) -> MoveMemoryBlockResponse:
        req = memory_pb2.MoveMemoryBlockRequest(
            address=address, new_start_address=new_start_address,
        )
        resp = self._call_rpc(
            "libghidra.MemoryService/MoveMemoryBlock",
            req,
            memory_pb2.MoveMemoryBlockResponse,
        )
        return MoveMemoryBlockResponse(
            moved=resp.moved,
            block=_to_memory_block(resp.block) if resp.HasField("block") else None,
        )

    def set_memory_block_attributes(
        self,
        address: int,
        *,
        name: str | None = None,
        is_read: bool | None = None,
        is_write: bool | None = None,
        is_execute: bool | None = None,
        end_address: int | None = None,
    ) -> SetMemoryBlockAttributesResponse:
        """Change an existing block's name, permissions, and/or extent.

        Every attribute is optional and None means "leave alone" -- the proto fields carry
        explicit presence, so renaming a block does not also reset its permissions.
        ``end_address`` is INCLUSIVE (Ghidra convention); growing appends and joins,
        shrinking splits and drops the tail, discarding the bytes past the new end.
        """
        req = memory_pb2.SetMemoryBlockAttributesRequest(address=address)
        if name is not None:
            req.name = name
        if is_read is not None:
            req.is_read = is_read
        if is_write is not None:
            req.is_write = is_write
        if is_execute is not None:
            req.is_execute = is_execute
        if end_address is not None:
            req.end_address = end_address
        resp = self._call_rpc(
            "libghidra.MemoryService/SetMemoryBlockAttributes",
            req,
            memory_pb2.SetMemoryBlockAttributesResponse,
        )
        return SetMemoryBlockAttributesResponse(
            updated=resp.updated,
            block=_to_memory_block(resp.block) if resp.HasField("block") else None,
        )

    # =========================================================================
    # Functions
    # =========================================================================

    def get_function(self, address: int) -> GetFunctionResponse:
        req = functions_pb2.GetFunctionRequest(
            address=address,
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/GetFunction",
            req,
            functions_pb2.GetFunctionResponse,
        )
        fn = _to_function(resp.function) if resp.HasField("function") else None
        return GetFunctionResponse(function=fn)

    def list_functions(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListFunctionsResponse:
        req = functions_pb2.ListFunctionsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/ListFunctions",
            req,
            functions_pb2.ListFunctionsResponse,
        )
        return ListFunctionsResponse(functions=[_to_function(f) for f in resp.functions])

    def rename_function(self, address: int, new_name: str) -> RenameFunctionResponse:
        req = functions_pb2.RenameFunctionRequest(
            address=address, new_name=new_name,
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/RenameFunction",
            req,
            functions_pb2.RenameFunctionResponse,
        )
        return RenameFunctionResponse(renamed=resp.renamed, name=resp.name)

    def list_basic_blocks(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListBasicBlocksResponse:
        req = functions_pb2.ListBasicBlocksRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/ListBasicBlocks",
            req,
            functions_pb2.ListBasicBlocksResponse,
        )
        return ListBasicBlocksResponse(blocks=[
            BasicBlockRecord(
                function_entry=b.function_entry,
                start_address=b.start_address,
                end_address=b.end_address,
                in_degree=b.in_degree,
                out_degree=b.out_degree,
            )
            for b in resp.blocks
        ])

    def list_cfg_edges(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListCFGEdgesResponse:
        req = functions_pb2.ListCFGEdgesRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/ListCFGEdges",
            req,
            functions_pb2.ListCFGEdgesResponse,
        )
        return ListCFGEdgesResponse(edges=[
            CFGEdgeRecord(
                function_entry=e.function_entry,
                src_block_start=e.src_block_start,
                dst_block_start=e.dst_block_start,
                edge_kind=e.edge_kind,
            )
            for e in resp.edges
        ])

    def list_switch_tables(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListSwitchTablesResponse:
        req = functions_pb2.ListSwitchTablesRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/ListSwitchTables",
            req,
            functions_pb2.ListSwitchTablesResponse,
        )
        return ListSwitchTablesResponse(switch_tables=[
            SwitchTableRecord(
                function_entry=s.function_entry,
                switch_address=s.switch_address,
                case_count=s.case_count,
                cases=[
                    SwitchCaseRecord(value=c.value, target_address=c.target_address)
                    for c in s.cases
                ],
                default_address=s.default_address,
            )
            for s in resp.switch_tables
        ])

    def list_dominators(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListDominatorsResponse:
        req = functions_pb2.ListDominatorsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/ListDominators",
            req,
            functions_pb2.ListDominatorsResponse,
        )
        return ListDominatorsResponse(dominators=[
            DominatorRecord(
                function_entry=d.function_entry,
                block_address=d.block_address,
                idom_address=d.idom_address,
                depth=d.depth,
                is_entry=d.is_entry,
            )
            for d in resp.dominators
        ])

    def list_post_dominators(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListPostDominatorsResponse:
        req = functions_pb2.ListPostDominatorsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/ListPostDominators",
            req,
            functions_pb2.ListPostDominatorsResponse,
        )
        return ListPostDominatorsResponse(post_dominators=[
            PostDominatorRecord(
                function_entry=p.function_entry,
                block_address=p.block_address,
                ipdom_address=p.ipdom_address,
                depth=p.depth,
                is_exit=p.is_exit,
            )
            for p in resp.post_dominators
        ])

    def list_loops(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListLoopsResponse:
        req = functions_pb2.ListLoopsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/ListLoops",
            req,
            functions_pb2.ListLoopsResponse,
        )
        return ListLoopsResponse(loops=[
            LoopRecord(
                function_entry=l.function_entry,
                header_address=l.header_address,
                back_edge_source=l.back_edge_source,
                loop_kind=l.loop_kind,
                block_count=l.block_count,
                depth=l.depth,
            )
            for l in resp.loops
        ])

    def list_function_frames(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> list[FunctionFrameRecord]:
        req = functions_pb2.ListFunctionFramesRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/ListFunctionFrames",
            req,
            functions_pb2.ListFunctionFramesResponse,
        )
        return [_frame_from_pb(f) for f in resp.frames]

    # =========================================================================
    # Symbols
    # =========================================================================

    def get_symbol(self, address: int) -> GetSymbolResponse:
        req = symbols_pb2.GetSymbolRequest(
            address=address,
        )
        resp = self._call_rpc(
            "libghidra.SymbolsService/GetSymbol",
            req,
            symbols_pb2.GetSymbolResponse,
        )
        sym = _to_symbol(resp.symbol) if resp.HasField("symbol") else None
        return GetSymbolResponse(symbol=sym)

    def list_symbols(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListSymbolsResponse:
        req = symbols_pb2.ListSymbolsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.SymbolsService/ListSymbols",
            req,
            symbols_pb2.ListSymbolsResponse,
        )
        return ListSymbolsResponse(symbols=[_to_symbol(s) for s in resp.symbols])

    def rename_symbol(self, address: int, new_name: str) -> RenameSymbolResponse:
        req = symbols_pb2.RenameSymbolRequest(
            address=address, new_name=new_name,
        )
        resp = self._call_rpc(
            "libghidra.SymbolsService/RenameSymbol",
            req,
            symbols_pb2.RenameSymbolResponse,
        )
        return RenameSymbolResponse(renamed=resp.renamed, name=resp.name)

    def delete_symbol(self, address: int, name_filter: str = "") -> DeleteSymbolResponse:
        req = symbols_pb2.DeleteSymbolRequest(
            address=address, name=name_filter,
        )
        resp = self._call_rpc(
            "libghidra.SymbolsService/DeleteSymbol",
            req,
            symbols_pb2.DeleteSymbolResponse,
        )
        return DeleteSymbolResponse(deleted=resp.deleted, deleted_count=resp.deleted_count)

    # =========================================================================
    # Xrefs
    # =========================================================================

    def list_xrefs(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListXrefsResponse:
        req = xrefs_pb2.ListXrefsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.XrefsService/ListXrefs",
            req,
            xrefs_pb2.ListXrefsResponse,
        )
        return ListXrefsResponse(xrefs=[_to_xref(x) for x in resp.xrefs])

    def list_xrefs_to(
        self, to_address: int, limit: int = 0, offset: int = 0,
    ) -> ListXrefsResponse:
        req = xrefs_pb2.ListXrefsRequest(
            exact_to_address=True,
            to_address=to_address,
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.XrefsService/ListXrefs", req, xrefs_pb2.ListXrefsResponse,
        )
        return ListXrefsResponse(xrefs=[_to_xref(x) for x in resp.xrefs])

    def list_xrefs_from_function(
        self, function_address: int, limit: int = 0, offset: int = 0,
    ) -> ListXrefsResponse:
        req = xrefs_pb2.ListXrefsRequest(
            exact_from_function=True,
            function_address=function_address,
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.XrefsService/ListXrefs", req, xrefs_pb2.ListXrefsResponse,
        )
        return ListXrefsResponse(xrefs=[_to_xref(x) for x in resp.xrefs])

    def list_xrefs_to_function(
        self, function_address: int, limit: int = 0, offset: int = 0,
    ) -> ListXrefsResponse:
        req = xrefs_pb2.ListXrefsRequest(
            exact_to_function=True,
            to_function_address=function_address,
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.XrefsService/ListXrefs", req, xrefs_pb2.ListXrefsResponse,
        )
        return ListXrefsResponse(xrefs=[_to_xref(x) for x in resp.xrefs])

    # =========================================================================
    # Types
    # =========================================================================

    def get_type(self, path: str) -> GetTypeResponse:
        req = types_pb2.GetTypeRequest(
            path=path,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/GetType",
            req,
            types_pb2.GetTypeResponse,
        )
        t = _to_type(resp.type) if resp.HasField("type") else None
        return GetTypeResponse(type=t)

    def list_types(self, query: str = "", limit: int = 0, offset: int = 0) -> ListTypesResponse:
        req = types_pb2.ListTypesRequest(
            query=query,
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.TypesService/ListTypes",
            req,
            types_pb2.ListTypesResponse,
        )
        return ListTypesResponse(types=[_to_type(t) for t in resp.types])

    def list_type_aliases(self, query: str = "", limit: int = 0, offset: int = 0) -> ListTypeAliasesResponse:
        req = types_pb2.ListTypeAliasesRequest(
            query=query,
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.TypesService/ListTypeAliases",
            req,
            types_pb2.ListTypeAliasesResponse,
        )
        return ListTypeAliasesResponse(aliases=[
            TypeAliasRecord(
                type_id=a.type_id,
                path_name=a.path_name,
                name=a.name,
                target_type=a.target_type,
                declaration=a.declaration,
            )
            for a in resp.aliases
        ])

    def list_type_unions(self, query: str = "", limit: int = 0, offset: int = 0) -> ListTypeUnionsResponse:
        req = types_pb2.ListTypeUnionsRequest(
            query=query,
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.TypesService/ListTypeUnions",
            req,
            types_pb2.ListTypeUnionsResponse,
        )
        return ListTypeUnionsResponse(unions=[
            TypeUnionRecord(
                type_id=u.type_id,
                path_name=u.path_name,
                name=u.name,
                size=u.size,
                declaration=u.declaration,
            )
            for u in resp.unions
        ])

    def list_type_enums(self, query: str = "", limit: int = 0, offset: int = 0) -> ListTypeEnumsResponse:
        req = types_pb2.ListTypeEnumsRequest(
            query=query,
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.TypesService/ListTypeEnums",
            req,
            types_pb2.ListTypeEnumsResponse,
        )
        return ListTypeEnumsResponse(enums=[
            TypeEnumRecord(
                type_id=e.type_id,
                path_name=e.path_name,
                name=e.name,
                width=e.width,
                is_signed=e.signed,
                declaration=e.declaration,
            )
            for e in resp.enums
        ])

    def list_type_enum_members(
        self, type_id_or_path: str, limit: int = 0, offset: int = 0,
    ) -> ListTypeEnumMembersResponse:
        req = types_pb2.ListTypeEnumMembersRequest(
            type=type_id_or_path,
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.TypesService/ListTypeEnumMembers",
            req,
            types_pb2.ListTypeEnumMembersResponse,
        )
        return ListTypeEnumMembersResponse(members=[
            TypeEnumMemberRecord(
                type_id=m.type_id,
                type_path_name=m.type_path_name,
                type_name=m.type_name,
                ordinal=m.ordinal,
                name=m.name,
                value=m.value,
            )
            for m in resp.members
        ])

    def list_type_members(
        self, type_id_or_path: str, limit: int = 0, offset: int = 0,
    ) -> ListTypeMembersResponse:
        req = types_pb2.ListTypeMembersRequest(
            type=type_id_or_path,
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.TypesService/ListTypeMembers",
            req,
            types_pb2.ListTypeMembersResponse,
        )
        return ListTypeMembersResponse(members=[
            TypeMemberRecord(
                parent_type_id=m.parent_type_id,
                parent_type_path_name=m.parent_type_path_name,
                parent_type_name=m.parent_type_name,
                ordinal=m.ordinal,
                name=m.name,
                member_type=m.member_type,
                offset=m.offset,
                size=m.size,
            )
            for m in resp.members
        ])

    def get_function_signature(self, address: int) -> GetFunctionSignatureResponse:
        req = types_pb2.GetFunctionSignatureRequest(
            address=address,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/GetFunctionSignature",
            req,
            types_pb2.GetFunctionSignatureResponse,
        )
        sig = _to_signature(resp.signature) if resp.HasField("signature") else None
        return GetFunctionSignatureResponse(signature=sig)

    def list_function_signatures(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListFunctionSignaturesResponse:
        req = types_pb2.ListFunctionSignaturesRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.TypesService/ListFunctionSignatures",
            req,
            types_pb2.ListFunctionSignaturesResponse,
        )
        return ListFunctionSignaturesResponse(
            signatures=[_to_signature(s) for s in resp.signatures],
        )

    def set_function_signature(self, address: int, prototype: str, calling_convention: str = "") -> SetFunctionSignatureResponse:
        req = types_pb2.SetFunctionSignatureRequest(
            address=address, prototype=prototype, calling_convention=calling_convention,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/SetFunctionSignature",
            req,
            types_pb2.SetFunctionSignatureResponse,
        )
        return SetFunctionSignatureResponse(
            updated=resp.updated, function_name=resp.function_name, prototype=resp.prototype,
        )

    def rename_function_parameter(
        self, address: int, ordinal: int, new_name: str,
    ) -> RenameFunctionParameterResponse:
        req = types_pb2.RenameFunctionParameterRequest(
            address=address, ordinal=ordinal, new_name=new_name,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/RenameFunctionParameter",
            req,
            types_pb2.RenameFunctionParameterResponse,
        )
        return RenameFunctionParameterResponse(updated=resp.updated, name=resp.name)

    def set_function_parameter_type(
        self, address: int, ordinal: int, data_type: str,
    ) -> SetFunctionParameterTypeResponse:
        req = types_pb2.SetFunctionParameterTypeRequest(
            address=address, ordinal=ordinal, data_type=data_type,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/SetFunctionParameterType",
            req,
            types_pb2.SetFunctionParameterTypeResponse,
        )
        return SetFunctionParameterTypeResponse(updated=resp.updated, data_type=resp.data_type)

    def rename_function_local(
        self, address: int, local_id: str, new_name: str,
    ) -> RenameFunctionLocalResponse:
        req = types_pb2.RenameFunctionLocalRequest(
            address=address, local_id=local_id, new_name=new_name,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/RenameFunctionLocal",
            req,
            types_pb2.RenameFunctionLocalResponse,
        )
        return RenameFunctionLocalResponse(
            updated=resp.updated, local_id=resp.local_id, name=resp.name,
        )

    def set_function_local_type(
        self, address: int, local_id: str, data_type: str,
    ) -> SetFunctionLocalTypeResponse:
        req = types_pb2.SetFunctionLocalTypeRequest(
            address=address, local_id=local_id, data_type=data_type,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/SetFunctionLocalType",
            req,
            types_pb2.SetFunctionLocalTypeResponse,
        )
        return SetFunctionLocalTypeResponse(
            updated=resp.updated, local_id=resp.local_id, data_type=resp.data_type,
        )

    def apply_data_type(self, address: int, data_type: str) -> ApplyDataTypeResponse:
        req = types_pb2.ApplyDataTypeRequest(
            address=address, data_type=data_type,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/ApplyDataType",
            req,
            types_pb2.ApplyDataTypeResponse,
        )
        return ApplyDataTypeResponse(updated=resp.updated, data_type=resp.data_type)

    def create_type(self, name: str, kind: str, size: int) -> CreateTypeResponse:
        req = types_pb2.CreateTypeRequest(
            name=name, kind=kind, size=size,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/CreateType",
            req,
            types_pb2.CreateTypeResponse,
        )
        return CreateTypeResponse(updated=resp.updated)

    def delete_type(self, type_id_or_path: str) -> DeleteTypeResponse:
        req = types_pb2.DeleteTypeRequest(
            type=type_id_or_path,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/DeleteType",
            req,
            types_pb2.DeleteTypeResponse,
        )
        return DeleteTypeResponse(deleted=resp.deleted)

    def rename_type(self, type_id_or_path: str, new_name: str) -> RenameTypeResponse:
        req = types_pb2.RenameTypeRequest(
            type=type_id_or_path, new_name=new_name,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/RenameType",
            req,
            types_pb2.RenameTypeResponse,
        )
        return RenameTypeResponse(updated=resp.updated, name=resp.name)

    def create_type_alias(self, name: str, target_type: str) -> CreateTypeAliasResponse:
        req = types_pb2.CreateTypeAliasRequest(
            name=name, target_type=target_type,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/CreateTypeAlias",
            req,
            types_pb2.CreateTypeAliasResponse,
        )
        return CreateTypeAliasResponse(updated=resp.updated)

    def delete_type_alias(self, type_id_or_path: str) -> DeleteTypeAliasResponse:
        req = types_pb2.DeleteTypeAliasRequest(
            type=type_id_or_path,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/DeleteTypeAlias",
            req,
            types_pb2.DeleteTypeAliasResponse,
        )
        return DeleteTypeAliasResponse(deleted=resp.deleted)

    def set_type_alias_target(self, type_id_or_path: str, target_type: str) -> SetTypeAliasTargetResponse:
        req = types_pb2.SetTypeAliasTargetRequest(
            type=type_id_or_path, target_type=target_type,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/SetTypeAliasTarget",
            req,
            types_pb2.SetTypeAliasTargetResponse,
        )
        return SetTypeAliasTargetResponse(updated=resp.updated)

    def create_type_enum(self, name: str, width: int, is_signed: bool = False) -> CreateTypeEnumResponse:
        req = types_pb2.CreateTypeEnumRequest(
            name=name, width=width, signed=is_signed,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/CreateTypeEnum",
            req,
            types_pb2.CreateTypeEnumResponse,
        )
        return CreateTypeEnumResponse(updated=resp.updated)

    def delete_type_enum(self, type_id_or_path: str) -> DeleteTypeEnumResponse:
        req = types_pb2.DeleteTypeEnumRequest(
            type=type_id_or_path,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/DeleteTypeEnum",
            req,
            types_pb2.DeleteTypeEnumResponse,
        )
        return DeleteTypeEnumResponse(deleted=resp.deleted)

    def add_type_enum_member(self, type_id_or_path: str, name: str, value: int) -> AddTypeEnumMemberResponse:
        req = types_pb2.AddTypeEnumMemberRequest(
            type=type_id_or_path, name=name, value=value,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/AddTypeEnumMember",
            req,
            types_pb2.AddTypeEnumMemberResponse,
        )
        return AddTypeEnumMemberResponse(updated=resp.updated)

    def delete_type_enum_member(self, type_id_or_path: str, ordinal: int) -> DeleteTypeEnumMemberResponse:
        req = types_pb2.DeleteTypeEnumMemberRequest(
            type=type_id_or_path, ordinal=ordinal,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/DeleteTypeEnumMember",
            req,
            types_pb2.DeleteTypeEnumMemberResponse,
        )
        return DeleteTypeEnumMemberResponse(deleted=resp.deleted)

    def rename_type_enum_member(
        self, type_id_or_path: str, ordinal: int, new_name: str,
    ) -> RenameTypeEnumMemberResponse:
        req = types_pb2.RenameTypeEnumMemberRequest(
            type=type_id_or_path, ordinal=ordinal, new_name=new_name,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/RenameTypeEnumMember",
            req,
            types_pb2.RenameTypeEnumMemberResponse,
        )
        return RenameTypeEnumMemberResponse(updated=resp.updated)

    def set_type_enum_member_value(
        self, type_id_or_path: str, ordinal: int, value: int,
    ) -> SetTypeEnumMemberValueResponse:
        req = types_pb2.SetTypeEnumMemberValueRequest(
            type=type_id_or_path, ordinal=ordinal, value=value,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/SetTypeEnumMemberValue",
            req,
            types_pb2.SetTypeEnumMemberValueResponse,
        )
        return SetTypeEnumMemberValueResponse(updated=resp.updated)

    def add_type_member(
        self, parent_type_id_or_path: str, member_name: str, member_type: str, size: int,
    ) -> AddTypeMemberResponse:
        req = types_pb2.AddTypeMemberRequest(
            type=parent_type_id_or_path,
            name=member_name,
            member_type=member_type,
            size=size,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/AddTypeMember",
            req,
            types_pb2.AddTypeMemberResponse,
        )
        return AddTypeMemberResponse(updated=resp.updated)

    def delete_type_member(self, parent_type_id_or_path: str, ordinal: int) -> DeleteTypeMemberResponse:
        req = types_pb2.DeleteTypeMemberRequest(
            type=parent_type_id_or_path, ordinal=ordinal,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/DeleteTypeMember",
            req,
            types_pb2.DeleteTypeMemberResponse,
        )
        return DeleteTypeMemberResponse(deleted=resp.deleted)

    def rename_type_member(
        self, parent_type_id_or_path: str, ordinal: int, new_name: str,
    ) -> RenameTypeMemberResponse:
        req = types_pb2.RenameTypeMemberRequest(
            type=parent_type_id_or_path, ordinal=ordinal, new_name=new_name,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/RenameTypeMember",
            req,
            types_pb2.RenameTypeMemberResponse,
        )
        return RenameTypeMemberResponse(updated=resp.updated)

    def set_type_member_type(
        self, parent_type_id_or_path: str, ordinal: int, member_type: str,
    ) -> SetTypeMemberTypeResponse:
        req = types_pb2.SetTypeMemberTypeRequest(
            type=parent_type_id_or_path, ordinal=ordinal, member_type=member_type,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/SetTypeMemberType",
            req,
            types_pb2.SetTypeMemberTypeResponse,
        )
        return SetTypeMemberTypeResponse(updated=resp.updated)

    def set_type_member_comment(
        self, parent_type_id_or_path: str, ordinal: int, comment: str,
    ) -> SetTypeMemberCommentResponse:
        req = types_pb2.SetTypeMemberCommentRequest(
            type=parent_type_id_or_path, ordinal=ordinal, comment=comment,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/SetTypeMemberComment",
            req,
            types_pb2.SetTypeMemberCommentResponse,
        )
        return SetTypeMemberCommentResponse(updated=resp.updated)

    def set_type_enum_member_comment(
        self, parent_type_id_or_path: str, ordinal: int, comment: str,
    ) -> SetTypeEnumMemberCommentResponse:
        req = types_pb2.SetTypeEnumMemberCommentRequest(
            type=parent_type_id_or_path, ordinal=ordinal, comment=comment,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/SetTypeEnumMemberComment",
            req,
            types_pb2.SetTypeEnumMemberCommentResponse,
        )
        return SetTypeEnumMemberCommentResponse(updated=resp.updated)

    # =========================================================================
    # Decompiler
    # =========================================================================

    def get_decompilation(self, address: int, timeout_ms: int = 0) -> GetDecompilationResponse:
        req = decompiler_pb2.DecompileFunctionRequest(
            address=address, timeout_ms=timeout_ms,
        )
        resp = self._call_rpc(
            "libghidra.DecompilerService/DecompileFunction",
            req,
            decompiler_pb2.DecompileFunctionResponse,
        )
        d = _to_decompilation(resp.decompilation) if resp.HasField("decompilation") else None
        return GetDecompilationResponse(decompilation=d)

    def list_decompilations(
        self,
        range_start: int = 0,
        range_end: int = 0,
        limit: int = 0,
        offset: int = 0,
        timeout_ms: int = 0,
    ) -> ListDecompilationsResponse:
        req = decompiler_pb2.ListDecompilationsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
            timeout_ms=timeout_ms,
        )
        resp = self._call_rpc(
            "libghidra.DecompilerService/ListDecompilations",
            req,
            decompiler_pb2.ListDecompilationsResponse,
        )
        return ListDecompilationsResponse(
            decompilations=[_to_decompilation(d) for d in resp.decompilations],
        )

    def get_pcode(
        self,
        address: int,
        maturity: PcodeMaturity = PcodeMaturity.HIGH,
        timeout_ms: int = 0,
    ) -> GetPcodeResponse:
        """P-code op stream for a single function at the requested maturity rung
        (HIGH=refined SSA, RAW=per-instruction, non-SSA) -- the Ghidra leg of the
        cross-tool low-IR. One RPC per function."""
        req = decompiler_pb2.GetPcodeRequest(
            address=address,
            timeout_ms=timeout_ms,
            maturity=(
                decompiler_pb2.PCODE_MATURITY_RAW
                if maturity == PcodeMaturity.RAW
                else decompiler_pb2.PCODE_MATURITY_HIGH
            ),
        )
        resp = self._call_rpc(
            "libghidra.DecompilerService/GetPcode",
            req,
            decompiler_pb2.GetPcodeResponse,
        )
        pcode = _to_pcode(resp.pcode) if resp.HasField("pcode") else None
        return GetPcodeResponse(pcode=pcode)

    # =========================================================================
    # Listing
    # =========================================================================

    def get_instruction(self, address: int) -> GetInstructionResponse:
        req = listing_pb2.GetInstructionRequest(
            address=address,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/GetInstruction",
            req,
            listing_pb2.GetInstructionResponse,
        )
        instr = _to_instruction(resp.instruction) if resp.HasField("instruction") else None
        return GetInstructionResponse(instruction=instr)

    def list_instructions(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListInstructionsResponse:
        req = listing_pb2.ListInstructionsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.ListingService/ListInstructions",
            req,
            listing_pb2.ListInstructionsResponse,
        )
        return ListInstructionsResponse(instructions=[_to_instruction(i) for i in resp.instructions])

    def list_instruction_operands(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListInstructionOperandsResponse:
        req = listing_pb2.ListInstructionOperandsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.ListingService/ListInstructionOperands",
            req,
            listing_pb2.ListInstructionOperandsResponse,
        )
        return ListInstructionOperandsResponse(
            operands=[_to_instruction_operand(o) for o in resp.operands]
        )

    def get_comments(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> GetCommentsResponse:
        req = listing_pb2.GetCommentsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.ListingService/GetComments",
            req,
            listing_pb2.GetCommentsResponse,
        )
        return GetCommentsResponse(comments=[
            CommentRecord(
                address=c.address,
                kind=CommentKind(c.kind) if c.kind in CommentKind._value2member_map_ else CommentKind.UNSPECIFIED,
                text=c.text,
            )
            for c in resp.comments
        ])

    def set_comment(self, address: int, kind: CommentKind, text: str) -> SetCommentResponse:
        req = listing_pb2.SetCommentRequest(
            address=address, kind=int(kind), text=text,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/SetComment",
            req,
            listing_pb2.SetCommentResponse,
        )
        return SetCommentResponse(updated=resp.updated)

    def delete_comment(self, address: int, kind: CommentKind) -> DeleteCommentResponse:
        req = listing_pb2.DeleteCommentRequest(
            address=address, kind=int(kind),
        )
        resp = self._call_rpc(
            "libghidra.ListingService/DeleteComment",
            req,
            listing_pb2.DeleteCommentResponse,
        )
        return DeleteCommentResponse(deleted=resp.deleted)

    def rename_data_item(self, address: int, new_name: str) -> RenameDataItemResponse:
        req = listing_pb2.RenameDataItemRequest(
            address=address, new_name=new_name,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/RenameDataItem",
            req,
            listing_pb2.RenameDataItemResponse,
        )
        return RenameDataItemResponse(updated=resp.updated, name=resp.name)

    def delete_data_item(self, address: int) -> DeleteDataItemResponse:
        req = listing_pb2.DeleteDataItemRequest(
            address=address,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/DeleteDataItem",
            req,
            listing_pb2.DeleteDataItemResponse,
        )
        return DeleteDataItemResponse(deleted=resp.deleted)

    def list_data_items(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListDataItemsResponse:
        req = listing_pb2.ListDataItemsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.ListingService/ListDataItems",
            req,
            listing_pb2.ListDataItemsResponse,
        )
        return ListDataItemsResponse(data_items=[
            DataItemRecord(
                address=d.address,
                end_address=d.end_address,
                name=d.name,
                data_type=d.data_type,
                size=d.size,
                value_repr=d.value_repr,
            )
            for d in resp.data_items
        ])

    def list_bookmarks(
        self,
        range_start: int = 0,
        range_end: int = 0,
        limit: int = 0,
        offset: int = 0,
        type_filter: str = "",
        category_filter: str = "",
    ) -> ListBookmarksResponse:
        req = listing_pb2.ListBookmarksRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
            type_filter=type_filter,
            category_filter=category_filter,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/ListBookmarks",
            req,
            listing_pb2.ListBookmarksResponse,
        )
        return ListBookmarksResponse(bookmarks=[
            BookmarkRecord(address=b.address, type=b.type, category=b.category, comment=b.comment)
            for b in resp.bookmarks
        ])

    def add_bookmark(
        self, address: int, type: str, category: str = "", comment: str = "",
    ) -> AddBookmarkResponse:
        req = listing_pb2.AddBookmarkRequest(
            address=address, type=type, category=category, comment=comment,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/AddBookmark",
            req,
            listing_pb2.AddBookmarkResponse,
        )
        return AddBookmarkResponse(updated=resp.updated)

    def delete_bookmark(self, address: int, type: str, category: str = "") -> DeleteBookmarkResponse:
        req = listing_pb2.DeleteBookmarkRequest(
            address=address, type=type, category=category,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/DeleteBookmark",
            req,
            listing_pb2.DeleteBookmarkResponse,
        )
        return DeleteBookmarkResponse(deleted=resp.deleted)

    def list_breakpoints(
        self,
        range_start: int = 0,
        range_end: int = 0,
        limit: int = 0,
        offset: int = 0,
        kind_filter: str = "",
        group_filter: str = "",
    ) -> ListBreakpointsResponse:
        req = listing_pb2.ListBreakpointsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
            kind_filter=kind_filter,
            group_filter=group_filter,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/ListBreakpoints",
            req,
            listing_pb2.ListBreakpointsResponse,
        )
        return ListBreakpointsResponse(breakpoints=[
            BreakpointRecord(
                address=b.address, enabled=b.enabled, kind=b.kind,
                size=b.size, condition=b.condition, group=b.group,
            )
            for b in resp.breakpoints
        ])

    def add_breakpoint(
        self,
        address: int,
        kind: str = "",
        size: int = 0,
        enabled: bool = True,
        condition: str = "",
        group: str = "",
    ) -> AddBreakpointResponse:
        req = listing_pb2.AddBreakpointRequest(
            address=address, kind=kind, size=size,
            enabled=enabled, condition=condition, group=group,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/AddBreakpoint",
            req,
            listing_pb2.AddBreakpointResponse,
        )
        return AddBreakpointResponse(updated=resp.updated)

    def set_breakpoint_enabled(self, address: int, enabled: bool) -> SetBreakpointEnabledResponse:
        req = listing_pb2.SetBreakpointEnabledRequest(
            address=address, enabled=enabled,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/SetBreakpointEnabled",
            req,
            listing_pb2.SetBreakpointEnabledResponse,
        )
        return SetBreakpointEnabledResponse(updated=resp.updated)

    def set_breakpoint_kind(self, address: int, kind: str) -> SetBreakpointKindResponse:
        req = listing_pb2.SetBreakpointKindRequest(
            address=address, kind=kind,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/SetBreakpointKind",
            req,
            listing_pb2.SetBreakpointKindResponse,
        )
        return SetBreakpointKindResponse(updated=resp.updated)

    def set_breakpoint_size(self, address: int, size: int) -> SetBreakpointSizeResponse:
        req = listing_pb2.SetBreakpointSizeRequest(
            address=address, size=size,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/SetBreakpointSize",
            req,
            listing_pb2.SetBreakpointSizeResponse,
        )
        return SetBreakpointSizeResponse(updated=resp.updated)

    def set_breakpoint_condition(self, address: int, condition: str) -> SetBreakpointConditionResponse:
        req = listing_pb2.SetBreakpointConditionRequest(
            address=address, condition=condition,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/SetBreakpointCondition",
            req,
            listing_pb2.SetBreakpointConditionResponse,
        )
        return SetBreakpointConditionResponse(updated=resp.updated)

    def set_breakpoint_group(self, address: int, group: str) -> SetBreakpointGroupResponse:
        req = listing_pb2.SetBreakpointGroupRequest(
            address=address, group=group,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/SetBreakpointGroup",
            req,
            listing_pb2.SetBreakpointGroupResponse,
        )
        return SetBreakpointGroupResponse(updated=resp.updated)

    def delete_breakpoint(self, address: int) -> DeleteBreakpointResponse:
        req = listing_pb2.DeleteBreakpointRequest(
            address=address,
        )
        resp = self._call_rpc(
            "libghidra.ListingService/DeleteBreakpoint",
            req,
            listing_pb2.DeleteBreakpointResponse,
        )
        return DeleteBreakpointResponse(deleted=resp.deleted)

    def list_function_tags(self) -> ListFunctionTagsResponse:
        req = functions_pb2.ListFunctionTagsRequest(
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/ListFunctionTags",
            req,
            functions_pb2.ListFunctionTagsResponse,
        )
        return ListFunctionTagsResponse(tags=[
            FunctionTagRecord(name=t.name, comment=t.comment)
            for t in resp.tags
        ])

    def create_function_tag(self, name: str, comment: str = "") -> CreateFunctionTagResponse:
        req = functions_pb2.CreateFunctionTagRequest(
            name=name, comment=comment,
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/CreateFunctionTag",
            req,
            functions_pb2.CreateFunctionTagResponse,
        )
        return CreateFunctionTagResponse(created=resp.created)

    def delete_function_tag(self, name: str) -> DeleteFunctionTagResponse:
        req = functions_pb2.DeleteFunctionTagRequest(
            name=name,
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/DeleteFunctionTag",
            req,
            functions_pb2.DeleteFunctionTagResponse,
        )
        return DeleteFunctionTagResponse(deleted=resp.deleted)

    def list_function_tag_mappings(
        self, function_entry: int = 0,
    ) -> ListFunctionTagMappingsResponse:
        req = functions_pb2.ListFunctionTagMappingsRequest(
            function_entry=function_entry,
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/ListFunctionTagMappings",
            req,
            functions_pb2.ListFunctionTagMappingsResponse,
        )
        return ListFunctionTagMappingsResponse(mappings=[
            FunctionTagMappingRecord(
                function_entry=m.function_entry, tag_name=m.tag_name,
            )
            for m in resp.mappings
        ])

    def tag_function(self, function_entry: int, tag_name: str) -> TagFunctionResponse:
        req = functions_pb2.TagFunctionRequest(
            function_entry=function_entry, tag_name=tag_name,
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/TagFunction",
            req,
            functions_pb2.TagFunctionResponse,
        )
        return TagFunctionResponse(updated=resp.updated)

    def untag_function(self, function_entry: int, tag_name: str) -> UntagFunctionResponse:
        req = functions_pb2.UntagFunctionRequest(
            function_entry=function_entry, tag_name=tag_name,
        )
        resp = self._call_rpc(
            "libghidra.FunctionsService/UntagFunction",
            req,
            functions_pb2.UntagFunctionResponse,
        )
        return UntagFunctionResponse(updated=resp.updated)

    def parse_declarations(self, source_text: str) -> ParseDeclarationsResponse:
        req = types_pb2.ParseDeclarationsRequest(
            source_text=source_text,
        )
        resp = self._call_rpc(
            "libghidra.TypesService/ParseDeclarations",
            req,
            types_pb2.ParseDeclarationsResponse,
        )
        return ParseDeclarationsResponse(
            types_created=resp.types_created,
            type_names=list(resp.type_names),
            errors=list(resp.errors),
        )

    def list_defined_strings(
        self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0,
    ) -> ListDefinedStringsResponse:
        req = listing_pb2.ListDefinedStringsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset),
        )
        resp = self._call_rpc(
            "libghidra.ListingService/ListDefinedStrings",
            req,
            listing_pb2.ListDefinedStringsResponse,
        )
        return ListDefinedStringsResponse(strings=[
            DefinedStringRecord(
                address=s.address, value=s.value, length=s.length,
                data_type=s.data_type, encoding=s.encoding,
            )
            for s in resp.strings
        ])


# ---------------------------------------------------------------------------
# Proto → model conversion helpers
# ---------------------------------------------------------------------------


def _to_memory_block(pb_block: memory_pb2.MemoryBlockRecord) -> MemoryBlockRecord:
    return MemoryBlockRecord(
        name=pb_block.name,
        start_address=pb_block.start_address,
        end_address=pb_block.end_address,
        size=pb_block.size,
        is_read=pb_block.is_read,
        is_write=pb_block.is_write,
        is_execute=pb_block.is_execute,
        is_volatile=pb_block.is_volatile,
        is_initialized=pb_block.is_initialized,
        source_name=pb_block.source_name,
        comment=pb_block.comment,
    )


def _frame_from_pb(pb_frame: functions_pb2.FunctionFrameRecord) -> FunctionFrameRecord:
    return FunctionFrameRecord(
        function_entry=pb_frame.function_entry,
        frame_size=pb_frame.frame_size,
        local_size=pb_frame.local_size,
        parameter_size=pb_frame.parameter_size,
        parameter_offset=pb_frame.parameter_offset,
        return_address_offset=pb_frame.return_address_offset,
        grows_negative=pb_frame.grows_negative,
        stack_pointer_register=pb_frame.stack_pointer_register,
        stack_variables=[
            StackVariableRecord(
                var_id=v.var_id,
                name=v.name,
                data_type=v.data_type,
                stack_offset=v.stack_offset,
                size=v.size,
                is_parameter=v.is_parameter,
                first_use_offset=v.first_use_offset,
                source_type=v.source_type,
            )
            for v in pb_frame.stack_variables
        ],
    )


def _perf_from_pb(pb_rec: session_pb2.PerfBenchmarkRecord) -> PerfBenchmarkRecord:
    return PerfBenchmarkRecord(
        bench_id=pb_rec.bench_id,
        query_family=pb_rec.query_family,
        dataset_profile=pb_rec.dataset_profile,
        cold_ms_p50=pb_rec.cold_ms_p50,
        cold_ms_p95=pb_rec.cold_ms_p95,
        warm_ms_p50=pb_rec.warm_ms_p50,
        warm_ms_p95=pb_rec.warm_ms_p95,
        throughput_qps=pb_rec.throughput_qps,
        regression_pct=pb_rec.regression_pct,
        status=pb_rec.status,
    )


def _perf_to_pb(record: PerfBenchmarkRecord) -> session_pb2.PerfBenchmarkRecord:
    return session_pb2.PerfBenchmarkRecord(
        bench_id=record.bench_id,
        query_family=record.query_family,
        dataset_profile=record.dataset_profile,
        cold_ms_p50=record.cold_ms_p50,
        cold_ms_p95=record.cold_ms_p95,
        warm_ms_p50=record.warm_ms_p50,
        warm_ms_p95=record.warm_ms_p95,
        throughput_qps=record.throughput_qps,
        regression_pct=record.regression_pct,
        status=record.status,
    )


def _to_function(pb_func: functions_pb2.FunctionRecord) -> FunctionRecord:
    return FunctionRecord(
        entry_address=pb_func.entry_address,
        name=pb_func.name,
        start_address=pb_func.start_address,
        end_address=pb_func.end_address,
        size=pb_func.size,
        namespace_name=pb_func.namespace_name,
        prototype=pb_func.prototype,
        is_thunk=pb_func.is_thunk,
        parameter_count=pb_func.parameter_count,
    )


def _to_symbol(pb_sym: symbols_pb2.SymbolRecord) -> SymbolRecord:
    return SymbolRecord(
        symbol_id=pb_sym.symbol_id,
        address=pb_sym.address,
        name=pb_sym.name,
        full_name=pb_sym.full_name,
        type=pb_sym.type,
        namespace_name=pb_sym.namespace_name,
        source=pb_sym.source,
        is_primary=pb_sym.is_primary,
        is_external=pb_sym.is_external,
        is_dynamic=pb_sym.is_dynamic,
        is_external_entry_point=pb_sym.is_external_entry_point,
    )


def _to_type(pb_type: types_pb2.TypeRecord) -> TypeRecord:
    return TypeRecord(
        type_id=pb_type.type_id,
        name=pb_type.name,
        path_name=pb_type.path_name,
        category_path=pb_type.category_path,
        display_name=pb_type.display_name,
        kind=pb_type.kind,
        length=pb_type.length,
        is_not_yet_defined=pb_type.is_not_yet_defined,
        source_archive=pb_type.source_archive,
        universal_id=pb_type.universal_id,
    )


def _to_signature(pb_sig: types_pb2.FunctionSignatureRecord) -> FunctionSignatureRecord:
    return FunctionSignatureRecord(
        function_entry_address=pb_sig.function_entry_address,
        function_name=pb_sig.function_name,
        prototype=pb_sig.prototype,
        return_type=pb_sig.return_type,
        has_var_args=pb_sig.has_var_args,
        calling_convention=pb_sig.calling_convention,
        parameters=[
            ParameterRecord(
                ordinal=p.ordinal,
                name=p.name,
                data_type=p.data_type,
                formal_data_type=p.formal_data_type,
                is_auto_parameter=p.is_auto_parameter,
                is_forced_indirect=p.is_forced_indirect,
            )
            for p in pb_sig.parameters
        ],
    )


def _to_decompilation(pb_dec: decompiler_pb2.DecompilationRecord) -> DecompilationRecord:
    return DecompilationRecord(
        function_entry_address=pb_dec.function_entry_address,
        function_name=pb_dec.function_name,
        prototype=pb_dec.prototype,
        pseudocode=pb_dec.pseudocode,
        completed=pb_dec.completed,
        is_fallback=pb_dec.is_fallback,
        error_message=pb_dec.error_message,
        locals=[
            DecompileLocalRecord(
                local_id=local.local_id,
                kind=DecompileLocalKind(local.kind),
                name=local.name,
                data_type=local.data_type,
                storage=local.storage,
                ordinal=local.ordinal,
            )
            for local in pb_dec.locals
        ],
        tokens=[
            DecompileTokenRecord(
                text=t.text,
                kind=DecompileTokenKind(t.kind),
                line_number=t.line_number,
                column_offset=t.column_offset,
                var_name=t.var_name,
                var_type=t.var_type,
                var_storage=t.var_storage,
            )
            for t in pb_dec.tokens
        ],
    )


def _to_varnode(pb_vn: decompiler_pb2.VarnodeRecord) -> VarnodeRecord:
    return VarnodeRecord(
        space=pb_vn.space,
        offset=pb_vn.offset,
        size=pb_vn.size,
        kind=pb_vn.kind,
    )


def _to_pcode(pb_pc: decompiler_pb2.PcodeRecord) -> PcodeRecord:
    return PcodeRecord(
        function_entry_address=pb_pc.function_entry_address,
        ops=[
            PcodeOpRecord(
                seq=op.seq,
                op=op.op,
                addr=op.addr,
                has_address=op.has_address,
                # Message presence: an absent output varnode means the op
                # defines nothing (RETURN, STORE, ...).
                has_output=op.HasField("output"),
                output=_to_varnode(op.output),
                inputs=[_to_varnode(i) for i in op.inputs],
            )
            for op in pb_pc.ops
        ],
        completed=pb_pc.completed,
        error_message=pb_pc.error_message,
        maturity=(
            PcodeMaturity.RAW
            if pb_pc.maturity == decompiler_pb2.PCODE_MATURITY_RAW
            else PcodeMaturity.HIGH
        ),
    )


def _to_instruction(pb_instr: listing_pb2.InstructionRecord) -> InstructionRecord:
    return InstructionRecord(
        address=pb_instr.address,
        mnemonic=pb_instr.mnemonic,
        operand_text=pb_instr.operand_text,
        disassembly=pb_instr.disassembly,
        length=pb_instr.length,
    )


def _to_instruction_operand(
    pb_operand: listing_pb2.InstructionOperandRecord,
) -> InstructionOperandRecord:
    return InstructionOperandRecord(
        address=pb_operand.address,
        operand_index=pb_operand.operand_index,
        text=pb_operand.text,
        type_name=pb_operand.type_name,
        ref_type=pb_operand.ref_type,
    )
