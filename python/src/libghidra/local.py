# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""LocalClient: offline decompiler backend via native C++ extension.

Requires the _native extension module built from cpp/bindings/.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import ErrorCode, GhidraError
from .format_detect import UnsupportedFormatError, detect
from .models import (
    BasicBlockRecord,
    Capability,
    CFGEdgeRecord,
    DecompilationRecord,
    DecompileLocalKind,
    DecompileLocalRecord,
    DecompileTokenKind,
    DecompileTokenRecord,
    DefinedStringRecord,
    FunctionRecord,
    GetDecompilationResponse,
    GetFunctionResponse,
    GetSymbolResponse,
    HealthStatus,
    InstructionRecord,
    GetInstructionResponse,
    ListBasicBlocksResponse,
    ListCFGEdgesResponse,
    ListDecompilationsResponse,
    ListDefinedStringsResponse,
    ListFunctionsResponse,
    ListInstructionsResponse,
    ListMemoryBlocksResponse,
    ListSymbolsResponse,
    ListTypeMembersResponse,
    ListTypesResponse,
    ListXrefsResponse,
    MemoryBlockRecord,
    OpenProgramRequest,
    OpenProgramResponse,
    ReadBytesResponse,
    RenameFunctionResponse,
    RenameSymbolResponse,
    RevisionResponse,
    SymbolRecord,
    TypeMemberRecord,
    TypeRecord,
    XrefRecord,
)

try:
    from . import _libghidra as _native
except ImportError:
    _native = None  # type: ignore[assignment]


@dataclass
class LocalClientOptions:
    """Options for creating a LocalClient."""
    ghidra_root: str = ""
    state_path: str = ""
    default_arch: str = ""
    pool_size: int = 1


def detect_arch(filepath: str) -> str | None:
    """Compatibility wrapper returning only the detected Sleigh language ID."""
    try:
        return detect(filepath).language_id
    except (OSError, UnsupportedFormatError):
        return None
    return None


def _require_native():
    if _native is None:
        raise ImportError(
            "libghidra native extension (_libghidra) is not available.\n"
            "Build it with: cmake -B build -G 'Visual Studio 17 2022' "
            "-DLIBGHIDRA_WITH_LOCAL=ON -DLIBGHIDRA_BUILD_PYTHON=ON "
            "-DGHIDRA_SOURCE_DIR=<path/to/ghidra>\n"
            "Then: cmake --build build --config Release --target _libghidra"
        )


# ---------------------------------------------------------------------------
# Dict -> dataclass converters
# ---------------------------------------------------------------------------

def _to_function(d: dict) -> FunctionRecord:
    return FunctionRecord(**d)


def _to_symbol(d: dict) -> SymbolRecord:
    return SymbolRecord(**d)


def _to_decompile_local(d: dict) -> DecompileLocalRecord:
    d["kind"] = DecompileLocalKind(d.get("kind", 0))
    return DecompileLocalRecord(**d)


def _to_decompile_token(d: dict) -> DecompileTokenRecord:
    d["kind"] = DecompileTokenKind(d.get("kind", 0))
    return DecompileTokenRecord(**d)


def _to_decompilation(d: dict) -> DecompilationRecord:
    d["locals"] = [_to_decompile_local(l) for l in d.get("locals", [])]
    d["tokens"] = [_to_decompile_token(t) for t in d.get("tokens", [])]
    return DecompilationRecord(**d)


def _to_instruction(d: dict) -> InstructionRecord:
    return InstructionRecord(**d)


def _to_memory_block(d: dict) -> MemoryBlockRecord:
    return MemoryBlockRecord(**d)


def _to_xref(d: dict) -> XrefRecord:
    return XrefRecord(**d)


def _to_type(d: dict) -> TypeRecord:
    return TypeRecord(**d)


def _to_type_member(d: dict) -> TypeMemberRecord:
    return TypeMemberRecord(**d)


def _to_basic_block(d: dict) -> BasicBlockRecord:
    return BasicBlockRecord(**d)


def _to_cfg_edge(d: dict) -> CFGEdgeRecord:
    return CFGEdgeRecord(**d)


def _to_defined_string(d: dict) -> DefinedStringRecord:
    return DefinedStringRecord(**d)


# ---------------------------------------------------------------------------
# LocalClient
# ---------------------------------------------------------------------------

class LocalClient:
    """Offline decompiler client backed by the native C++ LocalClient.

    Provides the same API as GhidraClient but works without a running Ghidra JVM.
    """

    def __init__(self, options: LocalClientOptions | None = None):
        _require_native()
        opts = options or LocalClientOptions()
        self._opts = opts
        self._auto_detect = opts.default_arch in ("", "auto")
        self._client = _native.create_local_client(
            ghidra_root=opts.ghidra_root,
            state_path=opts.state_path,
            default_arch="" if self._auto_detect else opts.default_arch,
            pool_size=opts.pool_size,
        )

    def _call(self, method, *args, **kwargs):
        try:
            return method(*args, **kwargs)
        except ValueError as e:
            msg = str(e)
            if ":" in msg:
                code_str, _, message = msg.partition(": ")
                code = ErrorCode.from_rpc_code(code_str)
            else:
                code = ErrorCode.API_ERROR
                message = msg
            raise GhidraError(code, message)

    # --- Health ---

    def get_status(self) -> HealthStatus:
        d = self._call(self._client.get_status)
        return HealthStatus(**d)

    def get_capabilities(self) -> list[Capability]:
        items = self._call(self._client.get_capabilities)
        return [Capability(**d) for d in items]

    # --- Session ---

    def open_program(self, request: OpenProgramRequest | str) -> OpenProgramResponse:
        if isinstance(request, str):
            request = OpenProgramRequest(program_path=request)

        # Auto-detect architecture from binary headers when needed
        if self._auto_detect and request.program_path and not request.language_id:
            detected = detect(request.program_path)
            request.language_id = detected.language_id
            if not request.compiler_spec_id:
                request.compiler_spec_id = detected.compiler_spec_id

        d = self._call(
            self._client.open_program,
            program_path=request.program_path,
            analyze=request.analyze,
            read_only=request.read_only,
            project_path=request.project_path,
            project_name=request.project_name,
            language_id=request.language_id,
            compiler_spec_id=request.compiler_spec_id,
            format=request.format,
            base_address=request.base_address,
        )
        return OpenProgramResponse(**d)

    def close_program(self, policy: int = 0) -> bool:
        return self._call(self._client.close_program, policy)

    def save_program(self) -> bool:
        return self._call(self._client.save_program)

    def discard_program(self) -> bool:
        return self._call(self._client.discard_program)

    def get_revision(self) -> RevisionResponse:
        rev = self._call(self._client.get_revision)
        return RevisionResponse(revision=rev)

    # --- Functions ---

    def get_function(self, address: int) -> GetFunctionResponse:
        d = self._call(self._client.get_function, address)
        func = _to_function(d) if d is not None else None
        return GetFunctionResponse(function=func)

    def list_functions(self, range_start: int = 0, range_end: int = 0,
                       limit: int = 0, offset: int = 0) -> ListFunctionsResponse:
        items = self._call(self._client.list_functions, range_start, range_end, limit, offset)
        return ListFunctionsResponse(functions=[_to_function(d) for d in items])

    def rename_function(self, address: int, new_name: str) -> RenameFunctionResponse:
        d = self._call(self._client.rename_function, address, new_name)
        return RenameFunctionResponse(**d)

    def list_basic_blocks(self, range_start: int = 0, range_end: int = 0,
                          limit: int = 0, offset: int = 0) -> ListBasicBlocksResponse:
        items = self._call(self._client.list_basic_blocks, range_start, range_end, limit, offset)
        return ListBasicBlocksResponse(blocks=[_to_basic_block(d) for d in items])

    def list_cfg_edges(self, range_start: int = 0, range_end: int = 0,
                       limit: int = 0, offset: int = 0) -> ListCFGEdgesResponse:
        items = self._call(self._client.list_cfg_edges, range_start, range_end, limit, offset)
        return ListCFGEdgesResponse(edges=[_to_cfg_edge(d) for d in items])

    # --- Decompiler ---

    def get_decompilation(self, address: int, timeout_ms: int = 30000) -> GetDecompilationResponse:
        d = self._call(self._client.get_decompilation, address, timeout_ms)
        dec = _to_decompilation(d) if d is not None else None
        return GetDecompilationResponse(decompilation=dec)

    def list_decompilations(self, range_start: int = 0, range_end: int = 0,
                            limit: int = 0, offset: int = 0,
                            timeout_ms: int = 30000) -> ListDecompilationsResponse:
        items = self._call(self._client.list_decompilations,
                           range_start, range_end, limit, offset, timeout_ms)
        return ListDecompilationsResponse(decompilations=[_to_decompilation(d) for d in items])

    # --- Symbols ---

    def get_symbol(self, address: int) -> GetSymbolResponse:
        d = self._call(self._client.get_symbol, address)
        sym = _to_symbol(d) if d is not None else None
        return GetSymbolResponse(symbol=sym)

    def list_symbols(self, range_start: int = 0, range_end: int = 0,
                     limit: int = 0, offset: int = 0) -> ListSymbolsResponse:
        items = self._call(self._client.list_symbols, range_start, range_end, limit, offset)
        return ListSymbolsResponse(symbols=[_to_symbol(d) for d in items])

    def rename_symbol(self, address: int, new_name: str) -> RenameSymbolResponse:
        d = self._call(self._client.rename_symbol, address, new_name)
        return RenameSymbolResponse(**d)

    # --- Memory ---

    def read_bytes(self, address: int, length: int) -> ReadBytesResponse:
        data = self._call(self._client.read_bytes, address, length)
        return ReadBytesResponse(data=data)

    def list_memory_blocks(self, limit: int = 0, offset: int = 0) -> ListMemoryBlocksResponse:
        items = self._call(self._client.list_memory_blocks, limit, offset)
        return ListMemoryBlocksResponse(blocks=[_to_memory_block(d) for d in items])

    # --- Listing ---

    def get_instruction(self, address: int) -> GetInstructionResponse:
        d = self._call(self._client.get_instruction, address)
        insn = _to_instruction(d) if d is not None else None
        return GetInstructionResponse(instruction=insn)

    def list_instructions(self, range_start: int = 0, range_end: int = 0,
                          limit: int = 0, offset: int = 0) -> ListInstructionsResponse:
        items = self._call(self._client.list_instructions, range_start, range_end, limit, offset)
        return ListInstructionsResponse(instructions=[_to_instruction(d) for d in items])

    def list_defined_strings(self, range_start: int = 0, range_end: int = 0,
                             limit: int = 0, offset: int = 0) -> ListDefinedStringsResponse:
        items = self._call(self._client.list_defined_strings, range_start, range_end, limit, offset)
        return ListDefinedStringsResponse(strings=[_to_defined_string(d) for d in items])

    # --- Xrefs ---

    def list_xrefs(self, range_start: int = 0, range_end: int = 0,
                   limit: int = 0, offset: int = 0) -> ListXrefsResponse:
        items = self._call(self._client.list_xrefs, range_start, range_end, limit, offset)
        return ListXrefsResponse(xrefs=[_to_xref(d) for d in items])

    # --- Types ---

    def get_type(self, path: str):
        d = self._call(self._client.get_type, path)
        return _to_type(d) if d is not None else None

    def list_types(self, query: str = "", limit: int = 0, offset: int = 0) -> ListTypesResponse:
        items = self._call(self._client.list_types, query, limit, offset)
        return ListTypesResponse(types=[_to_type(d) for d in items])

    def list_type_members(self, type_id_or_path: str,
                          limit: int = 0, offset: int = 0) -> ListTypeMembersResponse:
        items = self._call(self._client.list_type_members, type_id_or_path, limit, offset)
        return ListTypeMembersResponse(members=[_to_type_member(d) for d in items])
