# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Async HTTP client for the libghidra typed RPC layer.

Drop-in async replacement for ``GhidraClient``.  Every public method is
an ``async def`` returning the same typed models.  Requires ``aiohttp``.

Usage::

    import asyncio
    from libghidra.async_client import AsyncGhidraClient
    from libghidra import ConnectOptions

    async def main():
        client = AsyncGhidraClient(ConnectOptions())
        status = await client.get_status()
        print(status.service_name)
        await client.close()

    asyncio.run(main())
"""

from __future__ import annotations

import random
import asyncio
from dataclasses import dataclass
from typing import TypeVar

import aiohttp
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
from .client import (
    ClientOptions,
    _to_decompilation,
    _to_function,
    _to_instruction,
    _to_memory_block,
    _to_signature,
    _to_symbol,
    _to_type,
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
    CloseProgramResponse,
    CommentKind,
    CommentRecord,
    CreateTypeAliasResponse,
    CreateTypeEnumResponse,
    CreateTypeResponse,
    DataItemRecord,
    DefinedStringRecord,
    DeleteBookmarkResponse,
    DeleteBreakpointResponse,
    DeleteCommentResponse,
    DeleteDataItemResponse,
    DeleteSymbolResponse,
    DeleteTypeAliasResponse,
    DeleteTypeEnumMemberResponse,
    DeleteTypeEnumResponse,
    DeleteTypeMemberResponse,
    DeleteTypeResponse,
    DiscardProgramResponse,
    DominatorRecord,
    GetCommentsResponse,
    GetDecompilationResponse,
    GetFunctionResponse,
    GetFunctionSignatureResponse,
    GetInstructionResponse,
    GetSymbolResponse,
    GetTypeResponse,
    HealthStatus,
    ListBasicBlocksResponse,
    ListBookmarksResponse,
    ListBreakpointsResponse,
    ListCFGEdgesResponse,
    ListDataItemsResponse,
    ListDecompilationsResponse,
    ListDefinedStringsResponse,
    ListDominatorsResponse,
    ListFunctionsResponse,
    ListFunctionSignaturesResponse,
    ListInstructionsResponse,
    ListLoopsResponse,
    ListMemoryBlocksResponse,
    ListPostDominatorsResponse,
    ListSwitchTablesResponse,
    ListSymbolsResponse,
    ListTypeAliasesResponse,
    ListTypeEnumMembersResponse,
    ListTypeEnumsResponse,
    ListTypeMembersResponse,
    ListTypesResponse,
    ListTypeUnionsResponse,
    ListXrefsResponse,
    LoopRecord,
    OpenProgramRequest,
    OpenProgramResponse,
    PatchBytesBatchResponse,
    PostDominatorRecord,
    ReadBytesResponse,
    RenameDataItemResponse,
    RenameFunctionLocalResponse,
    RenameFunctionParameterResponse,
    RenameFunctionResponse,
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
    TypeAliasRecord,
    TypeEnumMemberRecord,
    TypeEnumRecord,
    TypeMemberRecord,
    TypeRecord,
    TypeUnionRecord,
    WriteBytesResponse,
    XrefRecord,
)

T = TypeVar("T", bound=Message)


class AsyncGhidraClient:
    """Async HTTP client for the Ghidra RPC API.

    Same API surface as ``GhidraClient`` but all methods are coroutines.
    Uses ``aiohttp`` for non-blocking HTTP.
    """

    def __init__(self, options: ClientOptions | None = None) -> None:
        self._options = options or ClientOptions()
        self._rpc_url = f"{self._options.base_url.rstrip('/')}/rpc"
        self._http: aiohttp.ClientSession | None = None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._http is None or self._http.closed:
            timeout = aiohttp.ClientTimeout(
                sock_connect=self._options.connect_timeout,
                sock_read=self._options.read_timeout,
            )
            self._http = aiohttp.ClientSession(timeout=timeout)
        return self._http

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._http and not self._http.closed:
            await self._http.close()

    async def __aenter__(self) -> AsyncGhidraClient:
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()

    # -- Core transport --------------------------------------------------------

    async def _call_rpc(self, method: str, request: Message, resp_class: type[T]) -> T:
        payload_any = any_pb2.Any()
        payload_any.Pack(request)

        rpc_req = rpc_pb2.RpcRequest(method=method, payload=payload_any)
        encoded = rpc_req.SerializeToString()

        max_attempts = self._options.max_retries + 1
        last_err: GhidraError | None = None

        for attempt in range(max_attempts):
            try:
                body = await self._post_raw(encoded)
            except GhidraError as exc:
                last_err = exc
                if not exc.code.is_retryable() or attempt + 1 >= max_attempts:
                    break
                await asyncio.sleep(self._backoff(attempt))
                continue

            return self._parse_rpc_response(body, resp_class, method)

        raise last_err  # type: ignore[misc]

    async def _post_raw(self, body: bytes) -> bytes:
        session = await self._ensure_session()
        headers = {"Content-Type": "application/x-protobuf"}
        if self._options.auth_token:
            headers["Authorization"] = f"Bearer {self._options.auth_token}"

        try:
            async with session.post(self._rpc_url, data=body, headers=headers) as resp:
                if not 200 <= resp.status < 300:
                    raise GhidraError(
                        ErrorCode.from_http_status(resp.status),
                        f"HTTP status {resp.status} for /rpc",
                    )
                return await resp.read()
        except aiohttp.ClientConnectorError as exc:
            raise GhidraError(ErrorCode.CONNECTION_FAILED, str(exc)) from exc
        except asyncio.TimeoutError as exc:
            raise GhidraError(ErrorCode.TIMEOUT, str(exc)) from exc
        except aiohttp.ClientError as exc:
            raise GhidraError(ErrorCode.TRANSPORT_ERROR, str(exc)) from exc

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

    @staticmethod
    def _pagination(limit: int, offset: int) -> common_pb2.Pagination:
        return common_pb2.Pagination(limit=max(limit, 0), offset=max(offset, 0))

    @staticmethod
    def _address_range(start: int, end: int) -> common_pb2.AddressRange:
        return common_pb2.AddressRange(start=start, end=end)

    # =========================================================================
    # Health
    # =========================================================================

    async def get_status(self) -> HealthStatus:
        req = health_pb2.HealthStatusRequest()
        resp = await self._call_rpc(
            "libghidra.HealthService/GetStatus", req, health_pb2.HealthStatusResponse,
        )
        return HealthStatus(
            ok=resp.ok, service_name=resp.service_name,
            service_version=resp.service_version, host_mode=resp.host_mode,
            program_revision=resp.program_revision, warnings=list(resp.warnings),
        )

    async def get_capabilities(self) -> list[Capability]:
        req = health_pb2.CapabilityRequest()
        resp = await self._call_rpc(
            "libghidra.HealthService/GetCapabilities", req, health_pb2.CapabilityResponse,
        )
        return [Capability(id=c.id, status=c.status, note=c.note) for c in resp.capabilities]

    # =========================================================================
    # Session
    # =========================================================================

    async def open_program(self, request: OpenProgramRequest) -> OpenProgramResponse:
        req = session_pb2.OpenProgramRequest(
            project_path=request.project_path, project_name=request.project_name,
            program_path=request.program_path, analyze=request.analyze, read_only=request.read_only,
            language_id=request.language_id, compiler_spec_id=request.compiler_spec_id,
            format=request.format, base_address=request.base_address,
        )
        resp = await self._call_rpc(
            "libghidra.SessionService/OpenProgram", req, session_pb2.OpenProgramResponse,
        )
        return OpenProgramResponse(
            program_name=resp.program_name,
            language_id=resp.language_id, compiler_spec=resp.compiler_spec, image_base=resp.image_base,
        )

    async def close_program(self, policy: ShutdownPolicy = ShutdownPolicy.UNSPECIFIED) -> CloseProgramResponse:
        req = session_pb2.CloseProgramRequest(shutdown_policy=int(policy))
        resp = await self._call_rpc(
            "libghidra.SessionService/CloseProgram", req, session_pb2.CloseProgramResponse,
        )
        return CloseProgramResponse(closed=resp.closed)

    async def save_program(self) -> SaveProgramResponse:
        req = session_pb2.SaveProgramRequest()
        resp = await self._call_rpc(
            "libghidra.SessionService/SaveProgram", req, session_pb2.SaveProgramResponse,
        )
        return SaveProgramResponse(saved=resp.saved)

    async def discard_program(self) -> DiscardProgramResponse:
        req = session_pb2.DiscardProgramRequest()
        resp = await self._call_rpc(
            "libghidra.SessionService/DiscardProgram", req, session_pb2.DiscardProgramResponse,
        )
        return DiscardProgramResponse(discarded=resp.discarded)

    async def get_revision(self) -> RevisionResponse:
        req = session_pb2.GetRevisionRequest()
        resp = await self._call_rpc(
            "libghidra.SessionService/GetRevision", req, session_pb2.GetRevisionResponse,
        )
        return RevisionResponse(revision=resp.revision)

    async def shutdown(self, policy: ShutdownPolicy = ShutdownPolicy.UNSPECIFIED) -> ShutdownResponse:
        req = session_pb2.ShutdownRequest(shutdown_policy=int(policy))
        resp = await self._call_rpc(
            "libghidra.SessionService/Shutdown", req, session_pb2.ShutdownResponse,
        )
        return ShutdownResponse(accepted=resp.accepted)

    # =========================================================================
    # Memory
    # =========================================================================

    async def read_bytes(self, address: int, length: int) -> ReadBytesResponse:
        req = memory_pb2.ReadBytesRequest(address=address, length=length)
        resp = await self._call_rpc("libghidra.MemoryService/ReadBytes", req, memory_pb2.ReadBytesResponse)
        return ReadBytesResponse(data=bytes(resp.data))

    async def write_bytes(self, address: int, data: bytes) -> WriteBytesResponse:
        req = memory_pb2.WriteBytesRequest(address=address, data=data)
        resp = await self._call_rpc("libghidra.MemoryService/WriteBytes", req, memory_pb2.WriteBytesResponse)
        return WriteBytesResponse(bytes_written=resp.bytes_written)

    async def patch_bytes_batch(self, patches: list[BytePatch]) -> PatchBytesBatchResponse:
        pb_cls = common_pb2.BytePatch
        req = memory_pb2.PatchBytesBatchRequest(
            patches=[pb_cls(address=p.address, data=p.data) for p in patches],
        )
        resp = await self._call_rpc("libghidra.MemoryService/PatchBytesBatch", req, memory_pb2.PatchBytesBatchResponse)
        return PatchBytesBatchResponse(patch_count=resp.patch_count, bytes_written=resp.bytes_written)

    async def list_memory_blocks(self, limit: int = 0, offset: int = 0) -> ListMemoryBlocksResponse:
        req = memory_pb2.ListMemoryBlocksRequest(page=self._pagination(limit, offset))
        resp = await self._call_rpc("libghidra.MemoryService/ListMemoryBlocks", req, memory_pb2.ListMemoryBlocksResponse)
        return ListMemoryBlocksResponse(blocks=[_to_memory_block(b) for b in resp.blocks])

    # =========================================================================
    # Functions
    # =========================================================================

    async def get_function(self, address: int) -> GetFunctionResponse:
        req = functions_pb2.GetFunctionRequest(address=address)
        resp = await self._call_rpc("libghidra.FunctionsService/GetFunction", req, functions_pb2.GetFunctionResponse)
        fn = _to_function(resp.function) if resp.HasField("function") else None
        return GetFunctionResponse(function=fn)

    async def list_functions(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListFunctionsResponse:
        req = functions_pb2.ListFunctionsRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.FunctionsService/ListFunctions", req, functions_pb2.ListFunctionsResponse)
        return ListFunctionsResponse(functions=[_to_function(f) for f in resp.functions])

    async def rename_function(self, address: int, new_name: str) -> RenameFunctionResponse:
        req = functions_pb2.RenameFunctionRequest(address=address, new_name=new_name)
        resp = await self._call_rpc("libghidra.FunctionsService/RenameFunction", req, functions_pb2.RenameFunctionResponse)
        return RenameFunctionResponse(renamed=resp.renamed, name=resp.name)

    async def list_basic_blocks(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListBasicBlocksResponse:
        req = functions_pb2.ListBasicBlocksRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.FunctionsService/ListBasicBlocks", req, functions_pb2.ListBasicBlocksResponse)
        return ListBasicBlocksResponse(blocks=[
            BasicBlockRecord(function_entry=b.function_entry, start_address=b.start_address, end_address=b.end_address, in_degree=b.in_degree, out_degree=b.out_degree)
            for b in resp.blocks
        ])

    async def list_cfg_edges(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListCFGEdgesResponse:
        req = functions_pb2.ListCFGEdgesRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.FunctionsService/ListCFGEdges", req, functions_pb2.ListCFGEdgesResponse)
        return ListCFGEdgesResponse(edges=[
            CFGEdgeRecord(function_entry=e.function_entry, src_block_start=e.src_block_start, dst_block_start=e.dst_block_start, edge_kind=e.edge_kind)
            for e in resp.edges
        ])

    async def list_switch_tables(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListSwitchTablesResponse:
        req = functions_pb2.ListSwitchTablesRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.FunctionsService/ListSwitchTables", req, functions_pb2.ListSwitchTablesResponse)
        return ListSwitchTablesResponse(switch_tables=[
            SwitchTableRecord(function_entry=s.function_entry, switch_address=s.switch_address, case_count=s.case_count,
                cases=[SwitchCaseRecord(value=c.value, target_address=c.target_address) for c in s.cases],
                default_address=s.default_address)
            for s in resp.switch_tables
        ])

    async def list_dominators(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListDominatorsResponse:
        req = functions_pb2.ListDominatorsRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.FunctionsService/ListDominators", req, functions_pb2.ListDominatorsResponse)
        return ListDominatorsResponse(dominators=[
            DominatorRecord(function_entry=d.function_entry, block_address=d.block_address, idom_address=d.idom_address, depth=d.depth, is_entry=d.is_entry)
            for d in resp.dominators
        ])

    async def list_post_dominators(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListPostDominatorsResponse:
        req = functions_pb2.ListPostDominatorsRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.FunctionsService/ListPostDominators", req, functions_pb2.ListPostDominatorsResponse)
        return ListPostDominatorsResponse(post_dominators=[
            PostDominatorRecord(function_entry=p.function_entry, block_address=p.block_address, ipdom_address=p.ipdom_address, depth=p.depth, is_exit=p.is_exit)
            for p in resp.post_dominators
        ])

    async def list_loops(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListLoopsResponse:
        req = functions_pb2.ListLoopsRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.FunctionsService/ListLoops", req, functions_pb2.ListLoopsResponse)
        return ListLoopsResponse(loops=[
            LoopRecord(function_entry=l.function_entry, header_address=l.header_address, back_edge_source=l.back_edge_source, loop_kind=l.loop_kind, block_count=l.block_count, depth=l.depth)
            for l in resp.loops
        ])

    # =========================================================================
    # Symbols
    # =========================================================================

    async def get_symbol(self, address: int) -> GetSymbolResponse:
        req = symbols_pb2.GetSymbolRequest(address=address)
        resp = await self._call_rpc("libghidra.SymbolsService/GetSymbol", req, symbols_pb2.GetSymbolResponse)
        sym = _to_symbol(resp.symbol) if resp.HasField("symbol") else None
        return GetSymbolResponse(symbol=sym)

    async def list_symbols(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListSymbolsResponse:
        req = symbols_pb2.ListSymbolsRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.SymbolsService/ListSymbols", req, symbols_pb2.ListSymbolsResponse)
        return ListSymbolsResponse(symbols=[_to_symbol(s) for s in resp.symbols])

    async def rename_symbol(self, address: int, new_name: str) -> RenameSymbolResponse:
        req = symbols_pb2.RenameSymbolRequest(address=address, new_name=new_name)
        resp = await self._call_rpc("libghidra.SymbolsService/RenameSymbol", req, symbols_pb2.RenameSymbolResponse)
        return RenameSymbolResponse(renamed=resp.renamed, name=resp.name)

    async def delete_symbol(self, address: int, name_filter: str = "") -> DeleteSymbolResponse:
        req = symbols_pb2.DeleteSymbolRequest(address=address, name=name_filter)
        resp = await self._call_rpc("libghidra.SymbolsService/DeleteSymbol", req, symbols_pb2.DeleteSymbolResponse)
        return DeleteSymbolResponse(deleted=resp.deleted, deleted_count=resp.deleted_count)

    # =========================================================================
    # Xrefs
    # =========================================================================

    async def list_xrefs(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListXrefsResponse:
        req = xrefs_pb2.ListXrefsRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.XrefsService/ListXrefs", req, xrefs_pb2.ListXrefsResponse)
        return ListXrefsResponse(xrefs=[
            XrefRecord(from_address=x.from_address, to_address=x.to_address, operand_index=x.operand_index,
                       ref_type=x.ref_type, is_primary=x.is_primary, source=x.source, symbol_id=x.symbol_id,
                       is_external=x.is_external, is_memory=x.is_memory, is_flow=x.is_flow)
            for x in resp.xrefs
        ])

    # =========================================================================
    # Types
    # =========================================================================

    async def get_type(self, path: str) -> GetTypeResponse:
        req = types_pb2.GetTypeRequest(path=path)
        resp = await self._call_rpc("libghidra.TypesService/GetType", req, types_pb2.GetTypeResponse)
        t = _to_type(resp.type) if resp.HasField("type") else None
        return GetTypeResponse(type=t)

    async def list_types(self, query: str = "", limit: int = 0, offset: int = 0) -> ListTypesResponse:
        req = types_pb2.ListTypesRequest(query=query, page=self._pagination(limit, offset))
        resp = await self._call_rpc("libghidra.TypesService/ListTypes", req, types_pb2.ListTypesResponse)
        return ListTypesResponse(types=[_to_type(t) for t in resp.types])

    async def list_type_aliases(self, query: str = "", limit: int = 0, offset: int = 0) -> ListTypeAliasesResponse:
        req = types_pb2.ListTypeAliasesRequest(query=query, page=self._pagination(limit, offset))
        resp = await self._call_rpc("libghidra.TypesService/ListTypeAliases", req, types_pb2.ListTypeAliasesResponse)
        return ListTypeAliasesResponse(aliases=[
            TypeAliasRecord(type_id=a.type_id, path_name=a.path_name, name=a.name, target_type=a.target_type, declaration=a.declaration)
            for a in resp.aliases
        ])

    async def list_type_unions(self, query: str = "", limit: int = 0, offset: int = 0) -> ListTypeUnionsResponse:
        req = types_pb2.ListTypeUnionsRequest(query=query, page=self._pagination(limit, offset))
        resp = await self._call_rpc("libghidra.TypesService/ListTypeUnions", req, types_pb2.ListTypeUnionsResponse)
        return ListTypeUnionsResponse(unions=[
            TypeUnionRecord(type_id=u.type_id, path_name=u.path_name, name=u.name, size=u.size, declaration=u.declaration)
            for u in resp.unions
        ])

    async def list_type_enums(self, query: str = "", limit: int = 0, offset: int = 0) -> ListTypeEnumsResponse:
        req = types_pb2.ListTypeEnumsRequest(query=query, page=self._pagination(limit, offset))
        resp = await self._call_rpc("libghidra.TypesService/ListTypeEnums", req, types_pb2.ListTypeEnumsResponse)
        return ListTypeEnumsResponse(enums=[
            TypeEnumRecord(type_id=e.type_id, path_name=e.path_name, name=e.name, width=e.width, is_signed=e.is_signed, declaration=e.declaration)
            for e in resp.enums
        ])

    async def list_type_enum_members(self, type_id_or_path: str, limit: int = 0, offset: int = 0) -> ListTypeEnumMembersResponse:
        req = types_pb2.ListTypeEnumMembersRequest(type=type_id_or_path, page=self._pagination(limit, offset))
        resp = await self._call_rpc("libghidra.TypesService/ListTypeEnumMembers", req, types_pb2.ListTypeEnumMembersResponse)
        return ListTypeEnumMembersResponse(members=[
            TypeEnumMemberRecord(type_id=m.type_id, type_path_name=m.type_path_name, type_name=m.type_name, ordinal=m.ordinal, name=m.name, value=m.value)
            for m in resp.members
        ])

    async def list_type_members(self, type_id_or_path: str, limit: int = 0, offset: int = 0) -> ListTypeMembersResponse:
        req = types_pb2.ListTypeMembersRequest(type=type_id_or_path, page=self._pagination(limit, offset))
        resp = await self._call_rpc("libghidra.TypesService/ListTypeMembers", req, types_pb2.ListTypeMembersResponse)
        return ListTypeMembersResponse(members=[
            TypeMemberRecord(parent_type_id=m.parent_type_id, parent_type_path_name=m.parent_type_path_name,
                             parent_type_name=m.parent_type_name, ordinal=m.ordinal, name=m.name,
                             member_type=m.member_type, offset=m.offset, size=m.size)
            for m in resp.members
        ])

    async def get_function_signature(self, address: int) -> GetFunctionSignatureResponse:
        req = types_pb2.GetFunctionSignatureRequest(address=address)
        resp = await self._call_rpc("libghidra.TypesService/GetFunctionSignature", req, types_pb2.GetFunctionSignatureResponse)
        sig = _to_signature(resp.signature) if resp.HasField("signature") else None
        return GetFunctionSignatureResponse(signature=sig)

    async def list_function_signatures(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListFunctionSignaturesResponse:
        req = types_pb2.ListFunctionSignaturesRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.TypesService/ListFunctionSignatures", req, types_pb2.ListFunctionSignaturesResponse)
        return ListFunctionSignaturesResponse(signatures=[_to_signature(s) for s in resp.signatures])

    async def set_function_signature(self, address: int, prototype: str, calling_convention: str = "") -> SetFunctionSignatureResponse:
        req = types_pb2.SetFunctionSignatureRequest(address=address, prototype=prototype, calling_convention=calling_convention)
        resp = await self._call_rpc("libghidra.TypesService/SetFunctionSignature", req, types_pb2.SetFunctionSignatureResponse)
        return SetFunctionSignatureResponse(updated=resp.updated, function_name=resp.function_name, prototype=resp.prototype)

    async def rename_function_parameter(self, address: int, ordinal: int, new_name: str) -> RenameFunctionParameterResponse:
        req = types_pb2.RenameFunctionParameterRequest(address=address, ordinal=ordinal, new_name=new_name)
        resp = await self._call_rpc("libghidra.TypesService/RenameFunctionParameter", req, types_pb2.RenameFunctionParameterResponse)
        return RenameFunctionParameterResponse(updated=resp.updated, name=resp.name)

    async def set_function_parameter_type(self, address: int, ordinal: int, data_type: str) -> SetFunctionParameterTypeResponse:
        req = types_pb2.SetFunctionParameterTypeRequest(address=address, ordinal=ordinal, data_type=data_type)
        resp = await self._call_rpc("libghidra.TypesService/SetFunctionParameterType", req, types_pb2.SetFunctionParameterTypeResponse)
        return SetFunctionParameterTypeResponse(updated=resp.updated, data_type=resp.data_type)

    async def rename_function_local(self, address: int, local_id: str, new_name: str) -> RenameFunctionLocalResponse:
        req = types_pb2.RenameFunctionLocalRequest(address=address, local_id=local_id, new_name=new_name)
        resp = await self._call_rpc("libghidra.TypesService/RenameFunctionLocal", req, types_pb2.RenameFunctionLocalResponse)
        return RenameFunctionLocalResponse(updated=resp.updated, local_id=resp.local_id, name=resp.name)

    async def set_function_local_type(self, address: int, local_id: str, data_type: str) -> SetFunctionLocalTypeResponse:
        req = types_pb2.SetFunctionLocalTypeRequest(address=address, local_id=local_id, data_type=data_type)
        resp = await self._call_rpc("libghidra.TypesService/SetFunctionLocalType", req, types_pb2.SetFunctionLocalTypeResponse)
        return SetFunctionLocalTypeResponse(updated=resp.updated, local_id=resp.local_id, data_type=resp.data_type)

    async def apply_data_type(self, address: int, data_type: str) -> ApplyDataTypeResponse:
        req = types_pb2.ApplyDataTypeRequest(address=address, data_type=data_type)
        resp = await self._call_rpc("libghidra.TypesService/ApplyDataType", req, types_pb2.ApplyDataTypeResponse)
        return ApplyDataTypeResponse(updated=resp.updated, data_type=resp.data_type)

    async def create_type(self, name: str, kind: str, size: int) -> CreateTypeResponse:
        req = types_pb2.CreateTypeRequest(name=name, kind=kind, size=size)
        resp = await self._call_rpc("libghidra.TypesService/CreateType", req, types_pb2.CreateTypeResponse)
        return CreateTypeResponse(updated=resp.updated)

    async def delete_type(self, type_id_or_path: str) -> DeleteTypeResponse:
        req = types_pb2.DeleteTypeRequest(type=type_id_or_path)
        resp = await self._call_rpc("libghidra.TypesService/DeleteType", req, types_pb2.DeleteTypeResponse)
        return DeleteTypeResponse(deleted=resp.deleted)

    async def rename_type(self, type_id_or_path: str, new_name: str) -> RenameTypeResponse:
        req = types_pb2.RenameTypeRequest(type=type_id_or_path, new_name=new_name)
        resp = await self._call_rpc("libghidra.TypesService/RenameType", req, types_pb2.RenameTypeResponse)
        return RenameTypeResponse(updated=resp.updated, name=resp.name)

    async def create_type_alias(self, name: str, target_type: str) -> CreateTypeAliasResponse:
        req = types_pb2.CreateTypeAliasRequest(name=name, target_type=target_type)
        resp = await self._call_rpc("libghidra.TypesService/CreateTypeAlias", req, types_pb2.CreateTypeAliasResponse)
        return CreateTypeAliasResponse(updated=resp.updated)

    async def delete_type_alias(self, type_id_or_path: str) -> DeleteTypeAliasResponse:
        req = types_pb2.DeleteTypeAliasRequest(type=type_id_or_path)
        resp = await self._call_rpc("libghidra.TypesService/DeleteTypeAlias", req, types_pb2.DeleteTypeAliasResponse)
        return DeleteTypeAliasResponse(deleted=resp.deleted)

    async def set_type_alias_target(self, type_id_or_path: str, target_type: str) -> SetTypeAliasTargetResponse:
        req = types_pb2.SetTypeAliasTargetRequest(type=type_id_or_path, target_type=target_type)
        resp = await self._call_rpc("libghidra.TypesService/SetTypeAliasTarget", req, types_pb2.SetTypeAliasTargetResponse)
        return SetTypeAliasTargetResponse(updated=resp.updated)

    async def create_type_enum(self, name: str, width: int, is_signed: bool = False) -> CreateTypeEnumResponse:
        req = types_pb2.CreateTypeEnumRequest(name=name, width=width, signed=is_signed)
        resp = await self._call_rpc("libghidra.TypesService/CreateTypeEnum", req, types_pb2.CreateTypeEnumResponse)
        return CreateTypeEnumResponse(updated=resp.updated)

    async def delete_type_enum(self, type_id_or_path: str) -> DeleteTypeEnumResponse:
        req = types_pb2.DeleteTypeEnumRequest(type=type_id_or_path)
        resp = await self._call_rpc("libghidra.TypesService/DeleteTypeEnum", req, types_pb2.DeleteTypeEnumResponse)
        return DeleteTypeEnumResponse(deleted=resp.deleted)

    async def add_type_enum_member(self, type_id_or_path: str, name: str, value: int) -> AddTypeEnumMemberResponse:
        req = types_pb2.AddTypeEnumMemberRequest(type=type_id_or_path, name=name, value=value)
        resp = await self._call_rpc("libghidra.TypesService/AddTypeEnumMember", req, types_pb2.AddTypeEnumMemberResponse)
        return AddTypeEnumMemberResponse(updated=resp.updated)

    async def delete_type_enum_member(self, type_id_or_path: str, ordinal: int) -> DeleteTypeEnumMemberResponse:
        req = types_pb2.DeleteTypeEnumMemberRequest(type=type_id_or_path, ordinal=ordinal)
        resp = await self._call_rpc("libghidra.TypesService/DeleteTypeEnumMember", req, types_pb2.DeleteTypeEnumMemberResponse)
        return DeleteTypeEnumMemberResponse(deleted=resp.deleted)

    async def rename_type_enum_member(self, type_id_or_path: str, ordinal: int, new_name: str) -> RenameTypeEnumMemberResponse:
        req = types_pb2.RenameTypeEnumMemberRequest(type=type_id_or_path, ordinal=ordinal, new_name=new_name)
        resp = await self._call_rpc("libghidra.TypesService/RenameTypeEnumMember", req, types_pb2.RenameTypeEnumMemberResponse)
        return RenameTypeEnumMemberResponse(updated=resp.updated)

    async def set_type_enum_member_value(self, type_id_or_path: str, ordinal: int, value: int) -> SetTypeEnumMemberValueResponse:
        req = types_pb2.SetTypeEnumMemberValueRequest(type=type_id_or_path, ordinal=ordinal, value=value)
        resp = await self._call_rpc("libghidra.TypesService/SetTypeEnumMemberValue", req, types_pb2.SetTypeEnumMemberValueResponse)
        return SetTypeEnumMemberValueResponse(updated=resp.updated)

    async def add_type_member(self, parent_type_id_or_path: str, member_name: str, member_type: str, size: int) -> AddTypeMemberResponse:
        req = types_pb2.AddTypeMemberRequest(type=parent_type_id_or_path, name=member_name, member_type=member_type, size=size)
        resp = await self._call_rpc("libghidra.TypesService/AddTypeMember", req, types_pb2.AddTypeMemberResponse)
        return AddTypeMemberResponse(updated=resp.updated)

    async def delete_type_member(self, parent_type_id_or_path: str, ordinal: int) -> DeleteTypeMemberResponse:
        req = types_pb2.DeleteTypeMemberRequest(type=parent_type_id_or_path, ordinal=ordinal)
        resp = await self._call_rpc("libghidra.TypesService/DeleteTypeMember", req, types_pb2.DeleteTypeMemberResponse)
        return DeleteTypeMemberResponse(deleted=resp.deleted)

    async def rename_type_member(self, parent_type_id_or_path: str, ordinal: int, new_name: str) -> RenameTypeMemberResponse:
        req = types_pb2.RenameTypeMemberRequest(type=parent_type_id_or_path, ordinal=ordinal, new_name=new_name)
        resp = await self._call_rpc("libghidra.TypesService/RenameTypeMember", req, types_pb2.RenameTypeMemberResponse)
        return RenameTypeMemberResponse(updated=resp.updated)

    async def set_type_member_type(self, parent_type_id_or_path: str, ordinal: int, member_type: str) -> SetTypeMemberTypeResponse:
        req = types_pb2.SetTypeMemberTypeRequest(type=parent_type_id_or_path, ordinal=ordinal, member_type=member_type)
        resp = await self._call_rpc("libghidra.TypesService/SetTypeMemberType", req, types_pb2.SetTypeMemberTypeResponse)
        return SetTypeMemberTypeResponse(updated=resp.updated)

    # =========================================================================
    # Decompiler
    # =========================================================================

    async def get_decompilation(self, address: int, timeout_ms: int = 0) -> GetDecompilationResponse:
        req = decompiler_pb2.DecompileFunctionRequest(address=address, timeout_ms=timeout_ms)
        resp = await self._call_rpc("libghidra.DecompilerService/DecompileFunction", req, decompiler_pb2.DecompileFunctionResponse)
        d = _to_decompilation(resp.decompilation) if resp.HasField("decompilation") else None
        return GetDecompilationResponse(decompilation=d)

    async def list_decompilations(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0, timeout_ms: int = 0) -> ListDecompilationsResponse:
        req = decompiler_pb2.ListDecompilationsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset), timeout_ms=timeout_ms,
        )
        resp = await self._call_rpc("libghidra.DecompilerService/ListDecompilations", req, decompiler_pb2.ListDecompilationsResponse)
        return ListDecompilationsResponse(decompilations=[_to_decompilation(d) for d in resp.decompilations])

    # =========================================================================
    # Listing
    # =========================================================================

    async def get_instruction(self, address: int) -> GetInstructionResponse:
        req = listing_pb2.GetInstructionRequest(address=address)
        resp = await self._call_rpc("libghidra.ListingService/GetInstruction", req, listing_pb2.GetInstructionResponse)
        instr = _to_instruction(resp.instruction) if resp.HasField("instruction") else None
        return GetInstructionResponse(instruction=instr)

    async def list_instructions(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListInstructionsResponse:
        req = listing_pb2.ListInstructionsRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.ListingService/ListInstructions", req, listing_pb2.ListInstructionsResponse)
        return ListInstructionsResponse(instructions=[_to_instruction(i) for i in resp.instructions])

    async def get_comments(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> GetCommentsResponse:
        req = listing_pb2.GetCommentsRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.ListingService/GetComments", req, listing_pb2.GetCommentsResponse)
        return GetCommentsResponse(comments=[
            CommentRecord(address=c.address, kind=CommentKind(c.kind) if c.kind in CommentKind._value2member_map_ else CommentKind.UNSPECIFIED, text=c.text)
            for c in resp.comments
        ])

    async def set_comment(self, address: int, kind: CommentKind, text: str) -> SetCommentResponse:
        req = listing_pb2.SetCommentRequest(address=address, kind=int(kind), text=text)
        resp = await self._call_rpc("libghidra.ListingService/SetComment", req, listing_pb2.SetCommentResponse)
        return SetCommentResponse(updated=resp.updated)

    async def delete_comment(self, address: int, kind: CommentKind) -> DeleteCommentResponse:
        req = listing_pb2.DeleteCommentRequest(address=address, kind=int(kind))
        resp = await self._call_rpc("libghidra.ListingService/DeleteComment", req, listing_pb2.DeleteCommentResponse)
        return DeleteCommentResponse(deleted=resp.deleted)

    async def rename_data_item(self, address: int, new_name: str) -> RenameDataItemResponse:
        req = listing_pb2.RenameDataItemRequest(address=address, new_name=new_name)
        resp = await self._call_rpc("libghidra.ListingService/RenameDataItem", req, listing_pb2.RenameDataItemResponse)
        return RenameDataItemResponse(updated=resp.updated, name=resp.name)

    async def delete_data_item(self, address: int) -> DeleteDataItemResponse:
        req = listing_pb2.DeleteDataItemRequest(address=address)
        resp = await self._call_rpc("libghidra.ListingService/DeleteDataItem", req, listing_pb2.DeleteDataItemResponse)
        return DeleteDataItemResponse(deleted=resp.deleted)

    async def list_data_items(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListDataItemsResponse:
        req = listing_pb2.ListDataItemsRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.ListingService/ListDataItems", req, listing_pb2.ListDataItemsResponse)
        return ListDataItemsResponse(data_items=[
            DataItemRecord(address=d.address, end_address=d.end_address, name=d.name, data_type=d.data_type, size=d.size, value_repr=d.value_repr)
            for d in resp.data_items
        ])

    async def list_bookmarks(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0, type_filter: str = "", category_filter: str = "") -> ListBookmarksResponse:
        req = listing_pb2.ListBookmarksRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset), type_filter=type_filter, category_filter=category_filter,
        )
        resp = await self._call_rpc("libghidra.ListingService/ListBookmarks", req, listing_pb2.ListBookmarksResponse)
        return ListBookmarksResponse(bookmarks=[
            BookmarkRecord(address=b.address, type=b.type, category=b.category, comment=b.comment)
            for b in resp.bookmarks
        ])

    async def add_bookmark(self, address: int, type: str, category: str = "", comment: str = "") -> AddBookmarkResponse:
        req = listing_pb2.AddBookmarkRequest(address=address, type=type, category=category, comment=comment)
        resp = await self._call_rpc("libghidra.ListingService/AddBookmark", req, listing_pb2.AddBookmarkResponse)
        return AddBookmarkResponse(updated=resp.updated)

    async def delete_bookmark(self, address: int, type: str, category: str = "") -> DeleteBookmarkResponse:
        req = listing_pb2.DeleteBookmarkRequest(address=address, type=type, category=category)
        resp = await self._call_rpc("libghidra.ListingService/DeleteBookmark", req, listing_pb2.DeleteBookmarkResponse)
        return DeleteBookmarkResponse(deleted=resp.deleted)

    async def list_breakpoints(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0, kind_filter: str = "", group_filter: str = "") -> ListBreakpointsResponse:
        req = listing_pb2.ListBreakpointsRequest(
            range=self._address_range(range_start, range_end),
            page=self._pagination(limit, offset), kind_filter=kind_filter, group_filter=group_filter,
        )
        resp = await self._call_rpc("libghidra.ListingService/ListBreakpoints", req, listing_pb2.ListBreakpointsResponse)
        return ListBreakpointsResponse(breakpoints=[
            BreakpointRecord(address=b.address, enabled=b.enabled, kind=b.kind, size=b.size, condition=b.condition, group=b.group)
            for b in resp.breakpoints
        ])

    async def add_breakpoint(self, address: int, kind: str = "", size: int = 0, enabled: bool = True, condition: str = "", group: str = "") -> AddBreakpointResponse:
        req = listing_pb2.AddBreakpointRequest(address=address, kind=kind, size=size, enabled=enabled, condition=condition, group=group)
        resp = await self._call_rpc("libghidra.ListingService/AddBreakpoint", req, listing_pb2.AddBreakpointResponse)
        return AddBreakpointResponse(updated=resp.updated)

    async def set_breakpoint_enabled(self, address: int, enabled: bool) -> SetBreakpointEnabledResponse:
        req = listing_pb2.SetBreakpointEnabledRequest(address=address, enabled=enabled)
        resp = await self._call_rpc("libghidra.ListingService/SetBreakpointEnabled", req, listing_pb2.SetBreakpointEnabledResponse)
        return SetBreakpointEnabledResponse(updated=resp.updated)

    async def set_breakpoint_kind(self, address: int, kind: str) -> SetBreakpointKindResponse:
        req = listing_pb2.SetBreakpointKindRequest(address=address, kind=kind)
        resp = await self._call_rpc("libghidra.ListingService/SetBreakpointKind", req, listing_pb2.SetBreakpointKindResponse)
        return SetBreakpointKindResponse(updated=resp.updated)

    async def set_breakpoint_size(self, address: int, size: int) -> SetBreakpointSizeResponse:
        req = listing_pb2.SetBreakpointSizeRequest(address=address, size=size)
        resp = await self._call_rpc("libghidra.ListingService/SetBreakpointSize", req, listing_pb2.SetBreakpointSizeResponse)
        return SetBreakpointSizeResponse(updated=resp.updated)

    async def set_breakpoint_condition(self, address: int, condition: str) -> SetBreakpointConditionResponse:
        req = listing_pb2.SetBreakpointConditionRequest(address=address, condition=condition)
        resp = await self._call_rpc("libghidra.ListingService/SetBreakpointCondition", req, listing_pb2.SetBreakpointConditionResponse)
        return SetBreakpointConditionResponse(updated=resp.updated)

    async def set_breakpoint_group(self, address: int, group: str) -> SetBreakpointGroupResponse:
        req = listing_pb2.SetBreakpointGroupRequest(address=address, group=group)
        resp = await self._call_rpc("libghidra.ListingService/SetBreakpointGroup", req, listing_pb2.SetBreakpointGroupResponse)
        return SetBreakpointGroupResponse(updated=resp.updated)

    async def delete_breakpoint(self, address: int) -> DeleteBreakpointResponse:
        req = listing_pb2.DeleteBreakpointRequest(address=address)
        resp = await self._call_rpc("libghidra.ListingService/DeleteBreakpoint", req, listing_pb2.DeleteBreakpointResponse)
        return DeleteBreakpointResponse(deleted=resp.deleted)

    async def list_defined_strings(self, range_start: int = 0, range_end: int = 0, limit: int = 0, offset: int = 0) -> ListDefinedStringsResponse:
        req = listing_pb2.ListDefinedStringsRequest(
            range=self._address_range(range_start, range_end), page=self._pagination(limit, offset),
        )
        resp = await self._call_rpc("libghidra.ListingService/ListDefinedStrings", req, listing_pb2.ListDefinedStringsResponse)
        return ListDefinedStringsResponse(strings=[
            DefinedStringRecord(address=s.address, value=s.value, length=s.length, data_type=s.data_type, encoding=s.encoding)
            for s in resp.strings
        ])
