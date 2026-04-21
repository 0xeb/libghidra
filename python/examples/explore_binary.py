#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# explore_binary: Deep-dive analysis of a program open in LibGhidraHost.
#
# Demonstrates: functions, symbols, types, xrefs, memory blocks, instructions,
# comments, data items, defined strings, and bookmarks.
#
# Usage: python explore_binary.py [host_url]

import sys

import libghidra as ghidra


def section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def main() -> None:
    host_url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    client = ghidra.connect(host_url)

    try:
        status = client.get_status()
    except ghidra.GhidraError as e:
        print(f"Cannot reach host at {host_url}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Connected: {status.service_name} v{status.service_version}")

    # -- Memory blocks ---------------------------------------------------------
    section("Memory Blocks")
    blocks = client.list_memory_blocks()
    for b in blocks.blocks:
        perms = ("r" if b.is_read else "-") + ("w" if b.is_write else "-") + ("x" if b.is_execute else "-")
        print(f"  {b.name:20s}  0x{b.start_address:012x}-0x{b.end_address:012x}  {perms}  {b.size} bytes")

    # -- Functions -------------------------------------------------------------
    section("Functions (first 20)")
    funcs = client.list_functions(limit=20)
    for f in funcs.functions:
        thunk = " [thunk]" if f.is_thunk else ""
        print(f"  0x{f.entry_address:08x}  {f.name}{thunk}  ({f.parameter_count} params, {f.size} bytes)")

    # -- Symbols ---------------------------------------------------------------
    section("Symbols (first 20)")
    syms = client.list_symbols(limit=20)
    for s in syms.symbols:
        flags = []
        if s.is_primary:
            flags.append("primary")
        if s.is_external:
            flags.append("external")
        flag_str = f"  [{', '.join(flags)}]" if flags else ""
        print(f"  0x{s.address:08x}  {s.name}  ({s.type}){flag_str}")

    # -- Types -----------------------------------------------------------------
    section("Types (first 20)")
    types = client.list_types(limit=20)
    for t in types.types:
        print(f"  {t.name:30s}  kind={t.kind:12s}  size={t.length}")

    # -- Type aliases ----------------------------------------------------------
    section("Type Aliases (first 10)")
    aliases = client.list_type_aliases(limit=10)
    for a in aliases.aliases:
        print(f"  {a.name}  ->  {a.target_type}")

    # -- Enums -----------------------------------------------------------------
    section("Enums (first 10)")
    enums = client.list_type_enums(limit=10)
    for e in enums.enums:
        print(f"  {e.name}  (width={e.width}, signed={e.is_signed})")

    # -- Cross-references ------------------------------------------------------
    section("Cross-References (first 20)")
    xrefs = client.list_xrefs(limit=20)
    for x in xrefs.xrefs:
        flags = []
        if x.is_flow:
            flags.append("flow")
        if x.is_memory:
            flags.append("mem")
        flag_str = f"  [{', '.join(flags)}]" if flags else ""
        print(f"  0x{x.from_address:08x} -> 0x{x.to_address:08x}  {x.ref_type}{flag_str}")

    # -- Instructions ----------------------------------------------------------
    if funcs.functions:
        f = funcs.functions[0]
        section(f"Instructions in {f.name} (first 10)")
        instrs = client.list_instructions(f.start_address, f.end_address, limit=10)
        for i in instrs.instructions:
            print(f"  0x{i.address:08x}  {i.disassembly}")

    # -- Decompilation with signature ------------------------------------------
    if funcs.functions:
        f = funcs.functions[0]
        section(f"Function Signature: {f.name}")
        try:
            sig = client.get_function_signature(f.entry_address)
            if sig.signature:
                s = sig.signature
                print(f"  Prototype: {s.prototype}")
                print(f"  Return:    {s.return_type}")
                print(f"  Convention: {s.calling_convention}")
                print(f"  Varargs:   {s.has_var_args}")
                for p in s.parameters:
                    print(f"    param[{p.ordinal}]: {p.data_type} {p.name}")
        except ghidra.GhidraError as e:
            print(f"  (not available: {e})")

    # -- Defined strings -------------------------------------------------------
    section("Defined Strings (first 20)")
    strings = client.list_defined_strings(limit=20)
    for s in strings.strings:
        val = s.value[:60] + "..." if len(s.value) > 60 else s.value
        print(f"  0x{s.address:08x}  {val!r}  ({s.data_type})")

    # -- Data items ------------------------------------------------------------
    section("Data Items (first 20)")
    items = client.list_data_items(limit=20)
    for d in items.data_items:
        print(f"  0x{d.address:08x}  {d.name:30s}  {d.data_type}  ({d.size} bytes)")

    # -- Bookmarks -------------------------------------------------------------
    section("Bookmarks (first 10)")
    marks = client.list_bookmarks(limit=10)
    if marks.bookmarks:
        for b in marks.bookmarks:
            print(f"  0x{b.address:08x}  [{b.type}] {b.category}: {b.comment}")
    else:
        print("  (none)")

    # -- Capabilities ----------------------------------------------------------
    section("Backend Capabilities")
    caps = client.get_capabilities()
    for c in caps:
        note = f" ({c.note})" if c.note else ""
        print(f"  {c.id:20s}  {c.status}{note}")

    print()


if __name__ == "__main__":
    main()
