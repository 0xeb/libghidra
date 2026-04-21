# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""libghidra Python client — typed RPC bindings for Ghidra."""

from .client import ClientOptions, GhidraClient
from .errors import ErrorCode, GhidraError
from .headless import HeadlessClient, HeadlessOptions, launch_headless

# Core type aliases (parity with C++ ghidra:: facade)
Client = GhidraClient
ConnectOptions = ClientOptions
from .models import (
    CommentKind,
    DecompileLocalKind,
    DecompileTokenKind,
    ShutdownPolicy,
    # Short aliases for commonly-used record types
    FunctionRecord as Function,
    SymbolRecord as Symbol,
    DecompilationRecord as Decompilation,
    DecompileLocalRecord as DecompileLocal,
    DecompileTokenRecord as DecompileToken,
    InstructionRecord as Instruction,
    XrefRecord as Xref,
    TypeRecord as Type,
    CommentRecord as Comment,
    MemoryBlockRecord as MemoryBlock,
    BasicBlockRecord as BasicBlock,
    CFGEdgeRecord as CFGEdge,
    DataItemRecord as DataItem,
    BookmarkRecord as Bookmark,
    BreakpointRecord as Breakpoint,
    ParameterRecord as Parameter,
    FunctionSignatureRecord as Signature,
    FunctionTagRecord as FunctionTag,
    FunctionTagMappingRecord as FunctionTagMapping,
    DefinedStringRecord as DefinedString,
    TypeMemberRecord as TypeMember,
    TypeEnumRecord as TypeEnum,
    TypeEnumMemberRecord as TypeEnumMember,
    TypeAliasRecord as TypeAlias,
    TypeUnionRecord as TypeUnion,
    SwitchTableRecord as SwitchTable,
    SwitchCaseRecord as SwitchCase,
    DominatorRecord as Dominator,
    PostDominatorRecord as PostDominator,
    LoopRecord as Loop,
    OpenProgramRequest as OpenRequest,
)


def connect(url: str = "http://127.0.0.1:18080") -> GhidraClient:
    """Create a client for a libghidra host at the given URL.

    >>> import libghidra as ghidra
    >>> client = ghidra.connect("http://127.0.0.1:18080")
    """
    return GhidraClient(ClientOptions(base_url=url))


# Local client (always importable; fails at init if _native extension not built)
from .local import LocalClient, LocalClientOptions as LocalOptions


def local(arch: str = "", state_path: str = "", pool_size: int = 1) -> LocalClient:
    """Create an offline LocalClient backed by the Ghidra decompiler engine.

    Requires the native extension (_native). Build with:
        python scripts/build-python-native.py --ghidra-source <path>

    >>> import libghidra as ghidra
    >>> client = ghidra.local(arch="x86:LE:64:default")
    >>> client.open_program("binary.exe")
    """
    return LocalClient(LocalOptions(default_arch=arch, state_path=state_path, pool_size=pool_size))


__all__ = [
    # Factory
    "connect",
    "local",
    "launch_headless",
    # Client + options
    "Client",
    "ConnectOptions",
    "ClientOptions",
    "GhidraClient",
    # Local (optional)
    "LocalClient",
    "LocalOptions",
    # Headless
    "HeadlessClient",
    "HeadlessOptions",
    # Errors
    "ErrorCode",
    "GhidraError",
    # Enums
    "CommentKind",
    "DecompileLocalKind",
    "ShutdownPolicy",
    # Short record aliases
    "Function",
    "Symbol",
    "Decompilation",
    "DecompileLocal",
    "DecompileToken",
    "Instruction",
    "Xref",
    "Type",
    "Comment",
    "MemoryBlock",
    "BasicBlock",
    "CFGEdge",
    "DataItem",
    "Bookmark",
    "Breakpoint",
    "Parameter",
    "Signature",
    "FunctionTag",
    "FunctionTagMapping",
    "DefinedString",
    "TypeMember",
    "TypeEnum",
    "TypeEnumMember",
    "TypeAlias",
    "TypeUnion",
    "SwitchTable",
    "SwitchCase",
    "Dominator",
    "PostDominator",
    "Loop",
    "DecompileTokenKind",
    "OpenRequest",
]
