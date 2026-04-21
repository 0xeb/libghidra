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

import struct
from dataclasses import dataclass
from typing import Optional

from .errors import ErrorCode, GhidraError
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


# ---------------------------------------------------------------------------
# Architecture auto-detection (pure stdlib, no optional deps)
# ---------------------------------------------------------------------------

# PE Machine → Sleigh language ID
_PE_MACHINE_MAP = {
    0x14c:  "x86:LE:32:default",
    0x8664: "x86:LE:64:default",
    0xaa64: "AARCH64:LE:64:v8A",
    0x1c0:  "ARM:LE:32:v8",
    0x1c4:  "ARM:LE:32:v8",      # Thumb
}

# ELF e_machine → (base_lang, bits_from_class)
#   bits_from_class=True means 32/64 comes from EI_CLASS, not hardcoded
_ELF_MACHINE_MAP = {
    3:   ("x86",     True),    # EM_386
    62:  ("x86",     True),    # EM_X86_64
    40:  ("ARM",     False),   # EM_ARM (always 32)
    183: ("AARCH64", False),   # EM_AARCH64 (always 64)
    8:   ("MIPS",    True),    # EM_MIPS
    20:  ("PowerPC", True),    # EM_PPC
    243: ("RISCV",   True),    # EM_RISCV
}

_ELF_SLEIGH = {
    ("x86",     32, "LE"): "x86:LE:32:default",
    ("x86",     64, "LE"): "x86:LE:64:default",
    ("ARM",     32, "LE"): "ARM:LE:32:v8",
    ("ARM",     32, "BE"): "ARM:BE:32:v8",
    ("AARCH64", 64, "LE"): "AARCH64:LE:64:v8A",
    ("AARCH64", 64, "BE"): "AARCH64:BE:64:v8A",
    ("MIPS",    32, "BE"): "MIPS:BE:32:default",
    ("MIPS",    32, "LE"): "MIPS:LE:32:default",
    ("MIPS",    64, "BE"): "MIPS:BE:64:default",
    ("MIPS",    64, "LE"): "MIPS:LE:64:default",
    ("PowerPC", 32, "BE"): "PowerPC:BE:32:default",
    ("PowerPC", 64, "BE"): "PowerPC:BE:64:default",
    ("RISCV",   32, "LE"): "RISCV:LE:32:default",
    ("RISCV",   64, "LE"): "RISCV:LE:64:default",
}

# Mach-O cputype → Sleigh language ID
_MACHO_CPU_MAP = {
    7:          "x86:LE:32:default",       # CPU_TYPE_X86
    0x01000007: "x86:LE:64:default",       # CPU_TYPE_X86_64
    12:         "ARM:LE:32:v8",            # CPU_TYPE_ARM
    0x0100000c: "AARCH64:LE:64:v8A",      # CPU_TYPE_ARM64
}


def detect_arch(filepath: str) -> str | None:
    """Detect Sleigh language ID from binary file headers.

    Supports PE, ELF, and Mach-O formats. Uses pure stdlib (struct module).
    Returns None if the format is unrecognized.
    """
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return None

            # --- PE ---
            if magic[:2] == b"MZ":
                f.seek(0x3C)
                pe_off_bytes = f.read(4)
                if len(pe_off_bytes) < 4:
                    return None
                pe_offset = struct.unpack_from("<I", pe_off_bytes)[0]
                f.seek(pe_offset)
                pe_sig = f.read(4)
                if pe_sig != b"PE\x00\x00":
                    return None
                machine = struct.unpack_from("<H", f.read(2))[0]
                return _PE_MACHINE_MAP.get(machine)

            # --- ELF ---
            if magic == b"\x7fELF":
                ei_class = f.read(1)[0]  # 1=32-bit, 2=64-bit
                ei_data = f.read(1)[0]   # 1=LE, 2=BE
                bits = 32 if ei_class == 1 else 64
                endian = "LE" if ei_data == 1 else "BE"
                bo = "<" if ei_data == 1 else ">"
                f.seek(18)  # e_machine offset is the same for ELF32/ELF64
                e_machine = struct.unpack_from(f"{bo}H", f.read(2))[0]
                entry = _ELF_MACHINE_MAP.get(e_machine)
                if entry is None:
                    return None
                base_lang, uses_class_bits = entry
                if not uses_class_bits:
                    # Fixed bitness (ARM=32, AARCH64=64)
                    bits = 32 if base_lang == "ARM" else 64
                return _ELF_SLEIGH.get((base_lang, bits, endian))

            # --- Mach-O ---
            macho_le = magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
            macho_be = magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
            if macho_le or macho_be:
                bo = ">" if macho_le else "<"
                cputype = struct.unpack_from(f"{bo}I", f.read(4))[0]
                return _MACHO_CPU_MAP.get(cputype)

    except (OSError, struct.error):
        pass
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
        if self._auto_detect and request.program_path:
            arch = detect_arch(request.program_path)
            if arch:
                self._client = _native.create_local_client(
                    ghidra_root=self._opts.ghidra_root,
                    state_path=self._opts.state_path,
                    default_arch=arch,
                    pool_size=self._opts.pool_size,
                )

        d = self._call(
            self._client.open_program,
            program_path=request.program_path,
            analyze=request.analyze,
            read_only=request.read_only,
            project_path=request.project_path,
            project_name=request.project_name,
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
