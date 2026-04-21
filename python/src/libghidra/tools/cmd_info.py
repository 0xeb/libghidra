# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Offline binary info: PE/ELF headers, sections, imports, exports, hashes."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys

from ._deps import try_import
from ._output import print_kv, print_records

_MAGIC = {
    b"MZ": "PE",
    b"\x7fELF": "ELF",
    b"\xfe\xed\xfa\xce": "Mach-O (32-bit)",
    b"\xfe\xed\xfa\xcf": "Mach-O (64-bit)",
    b"\xce\xfa\xed\xfe": "Mach-O (32-bit, reversed)",
    b"\xcf\xfa\xed\xfe": "Mach-O (64-bit, reversed)",
}

_PE_MACHINES = {
    0x14c: "i386",
    0x8664: "AMD64",
    0xaa64: "AArch64",
    0x1c0: "ARM",
    0x1c4: "ARMv7 Thumb",
}


def register(subparsers: argparse._SubParsersAction) -> None:
    from .cli import common_parser
    p = subparsers.add_parser("info", help="Show binary file information", parents=[common_parser()])
    p.add_argument("binary", help="Path to binary file")
    p.add_argument("--sections", action="store_true", help="Show section details")
    p.add_argument("--imports", action="store_true", help="Show imported DLLs")
    p.add_argument("--exports", action="store_true", help="Show exported symbols")
    p.set_defaults(func=run)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_format(data: bytes) -> str:
    for magic, name in _MAGIC.items():
        if data[:len(magic)] == magic:
            return name
    return "Unknown"


def run(args: argparse.Namespace) -> int:
    path = args.binary
    if not os.path.isfile(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    size = os.path.getsize(path)
    sha = _sha256(path)
    with open(path, "rb") as f:
        header = f.read(4)
    fmt_name = _detect_format(header)

    info: list[tuple[str, object]] = [
        ("File", os.path.basename(path)),
        ("Size", f"{size:,} bytes"),
        ("Format", fmt_name),
        ("SHA-256", sha),
    ]

    pefile = try_import("pefile")
    pe = None
    if pefile and fmt_name == "PE":
        try:
            pe = pefile.PE(path, fast_load=True)
        except pefile.PEFormatError as e:
            info.append(("PE Parse Error", str(e)))

    if pe is not None:
        machine = _PE_MACHINES.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:x}")
        info.extend([
            ("Machine", machine),
            ("Image Base", f"0x{pe.OPTIONAL_HEADER.ImageBase:x}"),
            ("Entry Point", f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}"),
            ("Sections", str(len(pe.sections))),
        ])

        pe.parse_data_directories()

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            info.append(("Imports", f"{len(pe.DIRECTORY_ENTRY_IMPORT)} DLLs"))
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            info.append(("Exports", f"{len(pe.DIRECTORY_ENTRY_EXPORT.symbols)} symbols"))

    print_kv(info, args.format)

    if pe is not None and args.sections:
        print()
        rows = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            rows.append({
                "name": name,
                "vaddr": s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase,
                "vsize": s.Misc_VirtualSize,
                "rawsize": s.SizeOfRawData,
                "flags": f"0x{s.Characteristics:08x}",
            })
        print_records(rows, args.format, ["name", "vaddr", "vsize", "rawsize", "flags"])

    if pe is not None and args.imports and hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print()
        rows = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace")
            rows.append({"dll": dll, "functions": len(entry.imports)})
        print_records(rows, args.format, ["dll", "functions"])

    if pe is not None and args.exports and hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        print()
        rows = []
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = sym.name.decode("ascii", errors="replace") if sym.name else f"ordinal_{sym.ordinal}"
            rows.append({
                "name": name,
                "address": sym.address + pe.OPTIONAL_HEADER.ImageBase if sym.address else 0,
                "ordinal": sym.ordinal,
            })
        print_records(rows, args.format, ["name", "address", "ordinal"])

    if pe is not None:
        pe.close()

    return 0
