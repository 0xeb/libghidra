# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Offline disassembly via capstone."""

from __future__ import annotations

import argparse
import os
import sys

from ._deps import require_capstone, try_import
from ._output import print_records


_ARCH_MAP: dict[str, tuple[int, int]] | None = None


def _get_arch_map() -> dict[str, tuple[int, int]]:
    global _ARCH_MAP
    if _ARCH_MAP is not None:
        return _ARCH_MAP
    cs = require_capstone()
    _ARCH_MAP = {
        "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
        "x64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
        "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
        "arm64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
        "thumb": (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB),
        "mips32": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32),
        "mips64": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS64),
        "ppc": (cs.CS_ARCH_PPC, cs.CS_MODE_32),
    }
    return _ARCH_MAP


def register(subparsers: argparse._SubParsersAction) -> None:
    from .cli import common_parser
    p = subparsers.add_parser("disasm", help="Disassemble binary at an offset", parents=[common_parser()])
    p.add_argument("binary", help="Path to binary file")
    p.add_argument("target", help="Offset: hex address, 'entry', or export name")
    p.add_argument("--count", "-c", type=int, default=20, help="Number of instructions (default: 20)")
    p.add_argument(
        "--arch", "-a",
        choices=["x86", "x64", "arm", "arm64", "thumb", "mips32", "mips64", "ppc"],
        default=None,
        help="Architecture (auto-detect from PE if omitted)",
    )
    p.add_argument("--bytes", "-b", type=int, default=256, help="Bytes to read for disassembly (default: 256)")
    p.set_defaults(func=run)


def _parse_offset(target: str, pe: object | None) -> int | None:
    """Resolve target to a file offset."""
    target_lower = target.lower()

    # 'entry' keyword
    if target_lower == "entry" and pe is not None:
        rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        return pe.get_offset_from_rva(rva)

    # Try hex address
    try:
        val = int(target, 16) if not target.startswith("0x") else int(target, 16)
        if pe is not None:
            # If it looks like a VA, convert to file offset
            image_base = pe.OPTIONAL_HEADER.ImageBase
            if val >= image_base:
                rva = val - image_base
                try:
                    return pe.get_offset_from_rva(rva)
                except Exception:
                    pass
            # Maybe it's already an RVA
            try:
                return pe.get_offset_from_rva(val)
            except Exception:
                pass
        return val
    except ValueError:
        pass

    # Try export name
    if pe is not None and hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.name and sym.name.decode("ascii", errors="replace") == target:
                return pe.get_offset_from_rva(sym.address)

    return None


def _detect_arch_from_pe(pe: object) -> str | None:
    machine = pe.FILE_HEADER.Machine
    return {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64", 0x1c0: "arm", 0x1c4: "thumb"}.get(machine)


def run(args: argparse.Namespace) -> int:
    cs_mod = require_capstone()

    path = args.binary
    if not os.path.isfile(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    # Try pefile for PE awareness (optional)
    pefile = try_import("pefile")
    pe = None
    if pefile:
        with open(path, "rb") as f:
            if f.read(2) == b"MZ":
                try:
                    pe = pefile.PE(path, fast_load=True)
                    pe.parse_data_directories(
                        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
                    )
                except Exception:
                    pe = None

    # Resolve architecture
    arch_name = args.arch
    if arch_name is None and pe is not None:
        arch_name = _detect_arch_from_pe(pe)
    if arch_name is None:
        arch_name = "x64"
        print(f"Warning: could not auto-detect architecture, defaulting to {arch_name}", file=sys.stderr)

    arch_map = _get_arch_map()
    cs_arch, cs_mode = arch_map[arch_name]

    # Resolve offset
    offset = _parse_offset(args.target, pe)
    if offset is None:
        print(f"Error: cannot resolve target '{args.target}'", file=sys.stderr)
        if pe:
            pe.close()
        return 1

    # Read bytes and disassemble
    with open(path, "rb") as f:
        f.seek(offset)
        code = f.read(args.bytes)

    # Use the VA for display if PE, otherwise use file offset
    base_addr = offset
    if pe is not None:
        try:
            rva = pe.get_rva_from_offset(offset)
            base_addr = pe.OPTIONAL_HEADER.ImageBase + rva
        except Exception:
            pass

    md = cs_mod.Cs(cs_arch, cs_mode)
    md.detail = False

    rows = []
    for i, insn in enumerate(md.disasm(code, base_addr)):
        if i >= args.count:
            break
        hex_bytes = " ".join(f"{b:02x}" for b in insn.bytes)
        rows.append({
            "address": insn.address,
            "bytes": hex_bytes,
            "mnemonic": insn.mnemonic,
            "operands": insn.op_str,
        })

    if not rows:
        print("No instructions decoded.", file=sys.stderr)
        if pe:
            pe.close()
        return 1

    print_records(rows, args.format, ["address", "bytes", "mnemonic", "operands"])

    if pe:
        pe.close()
    return 0
