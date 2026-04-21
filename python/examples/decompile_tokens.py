#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# decompile_tokens: Structured analysis of decompilation token streams.
#
# Usage: python decompile_tokens.py [host_url]
#
# Demonstrates structured token-stream analysis: reconstructing source lines,
# finding function calls, mapping variables, listing type references, and
# performing token-level search directly from the decompilation output.

import sys
from collections import Counter, defaultdict

import libghidra as ghidra


def main() -> None:
    url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    client = ghidra.connect(url)

    # 1. Verify connection
    try:
        status = client.get_status()
    except ghidra.GhidraError as e:
        print(f"Cannot reach host at {url}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Connected: {status.service_name} v{status.service_version}")

    # 2. Find a non-trivial function (size > 64 bytes)
    try:
        funcs = client.list_functions(limit=50)
    except ghidra.GhidraError as e:
        print(f"list_functions failed: {e}", file=sys.stderr)
        sys.exit(1)

    target = next((f for f in funcs.functions if f.size > 64), None)
    if target is None:
        target = funcs.functions[0] if funcs.functions else None
    if target is None:
        print("No functions found.", file=sys.stderr)
        sys.exit(1)

    addr = target.entry_address
    print(f"Function: {target.name} at 0x{addr:x} ({target.size} bytes)")

    # 3. Decompile the function
    try:
        resp = client.get_decompilation(addr, timeout_ms=30000)
    except ghidra.GhidraError as e:
        print(f"get_decompilation failed: {e}", file=sys.stderr)
        sys.exit(1)

    if resp.decompilation is None:
        print("No decompilation result.", file=sys.stderr)
        sys.exit(1)

    d = resp.decompilation
    tokens = d.tokens
    locals_ = d.locals

    print(f"\nDecompiled {target.name}: {len(tokens)} tokens, {len(locals_)} locals")

    # ======================================================================
    # 4. Reconstruct source lines
    # ======================================================================
    print("\n=== Reconstructed source ===")
    lines: dict[int, str] = defaultdict(str)
    for tok in tokens:
        lines[tok.line_number] += tok.text

    for line_num in sorted(lines):
        print(f"{line_num:4d} | {lines[line_num]}")

    # ======================================================================
    # 5. Function calls (kind == FUNCTION) — ctree_v_calls equivalent
    # ======================================================================
    print("\n=== Function calls (ctree_v_calls equivalent) ===")
    call_tokens = [t for t in tokens if t.kind == ghidra.DecompileTokenKind.FUNCTION]
    call_counts = Counter(t.text for t in call_tokens)

    if not call_counts:
        print("  (no function call tokens)")
    for name, count in call_counts.most_common():
        print(f"  {name:<30s} {count} reference(s)")

    # ======================================================================
    # 6. Variable map (kind == VARIABLE | PARAMETER) — ctree_lvars equivalent
    # ======================================================================
    print("\n=== Variable map (ctree_lvars equivalent) ===")

    class VarInfo:
        def __init__(self):
            self.ref_count = 0
            self.var_type = ""
            self.var_storage = ""
            self.role = ""

    var_map: dict[str, VarInfo] = {}
    for tok in tokens:
        if tok.kind in (ghidra.DecompileTokenKind.VARIABLE,
                        ghidra.DecompileTokenKind.PARAMETER):
            name = tok.var_name or tok.text
            info = var_map.setdefault(name, VarInfo())
            info.ref_count += 1
            if tok.var_type:
                info.var_type = tok.var_type
            if tok.var_storage:
                info.var_storage = tok.var_storage
            info.role = tok.kind.name.lower()

    print(f"  {'NAME':<20s} {'REFS':<8s} {'ROLE':<10s} {'TYPE':<20s} STORAGE")
    print(f"  {'-' * 70}")
    for name, info in sorted(var_map.items()):
        print(f"  {name:<20s} {info.ref_count:<8d} {info.role:<10s} "
              f"{info.var_type or '-':<20s} {info.var_storage or '-'}")

    # Cross-reference with locals
    local_names = {local.name for local in locals_}
    print(f"\n  Locals from decompilation ({len(locals_)}):")
    for local in locals_:
        in_tokens = local.name in var_map
        tag = "[in tokens]" if in_tokens else "[not in tokens]"
        print(f"    {local.name:<18s} type={local.data_type:<16s} "
              f"storage={local.storage:<12s} {tag}")

    # ======================================================================
    # 7. Type references (kind == TYPE)
    # ======================================================================
    print("\n=== Type references ===")
    type_refs = sorted({t.text for t in tokens if t.kind == ghidra.DecompileTokenKind.TYPE})

    if not type_refs:
        print("  (no type tokens)")
    for t in type_refs:
        print(f"  {t}")

    # ======================================================================
    # 8. Token kind distribution
    # ======================================================================
    print("\n=== Token kind distribution ===")
    kind_counts = Counter(t.kind.name.lower() for t in tokens)
    for kind, count in kind_counts.most_common():
        print(f"  {kind:<14s} {count}")

    # ======================================================================
    # 9. Token search (search for first variable name with line context)
    # ======================================================================
    pattern = next(iter(var_map), "return")
    print(f'\n=== Token search for "{pattern}" ===')

    for tok in tokens:
        if pattern in tok.text:
            kind_str = tok.kind.name.lower()
            line_ctx = lines.get(tok.line_number, "")
            print(f"  line {tok.line_number:3d} col {tok.column_offset:3d}"
                  f"  [{kind_str:<10s}]  \"{tok.text}\""
                  f"  -->  {line_ctx}")

    # ======================================================================
    # Summary
    # ======================================================================
    print("\n=== Summary ===")
    print(f"  Function:       {target.name}")
    print(f"  Total tokens:   {len(tokens)}")
    print(f"  Source lines:   {len(lines)}")
    print(f"  Callees:        {len(call_counts)}")
    print(f"  Variables:      {len(var_map)}")
    print(f"  Types used:     {len(type_refs)}")
    print(f"  Locals:         {len(locals_)}")

    print("\nDone.")


if __name__ == "__main__":
    main()
