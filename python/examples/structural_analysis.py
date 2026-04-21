#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# structural_analysis: Analyze structural properties of functions.
#
# Usage: python structural_analysis.py [host_url]
#
# Finds a non-trivial function, queries its switch tables, dominator tree,
# post-dominator tree, and natural loops, then decompiles it and inspects
# the token stream.

import sys
from collections import Counter

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

    # 2. Find a non-trivial function (size > 0)
    print("\n--- Searching for a non-trivial function (size > 0) ---")
    try:
        funcs = client.list_functions(limit=100)
    except ghidra.GhidraError as e:
        print(f"ListFunctions failed: {e}", file=sys.stderr)
        sys.exit(1)

    target = None
    for f in funcs.functions:
        if f.size > 0:
            target = f
            break

    if target is None:
        print("No function with size > 0 found.", file=sys.stderr)
        sys.exit(1)

    addr = target.entry_address
    print(f"Selected: {target.name} at 0x{addr:x} ({target.size} bytes)")

    # 3. Switch tables
    print(f"\n--- Switch tables for {target.name} ---")
    try:
        sw_resp = client.list_switch_tables(range_start=addr, range_end=addr)
        switch_tables = sw_resp.switch_tables
    except ghidra.GhidraError as e:
        print(f"ListSwitchTables failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Total switch tables: {len(switch_tables)}")
    for st in switch_tables:
        print(f"  Switch at 0x{st.switch_address:x}  ({st.case_count} cases,"
              f" default=0x{st.default_address:x})")
        for case in st.cases:
            print(f"    case {case.value} -> 0x{case.target_address:x}")

    # 4. Dominator tree
    print(f"\n--- Dominators for {target.name} ---")
    try:
        dom_resp = client.list_dominators(range_start=addr, range_end=addr)
        dominators = dom_resp.dominators
    except ghidra.GhidraError as e:
        print(f"ListDominators failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Total dominator records: {len(dominators)}")
    for d in dominators:
        entry_marker = " (entry)" if d.is_entry else ""
        print(f"  0x{d.block_address:x}  idom=0x{d.idom_address:x}"
              f"  depth={d.depth}{entry_marker}")

    # 5. Post-dominator tree
    print(f"\n--- Post-dominators for {target.name} ---")
    try:
        pdom_resp = client.list_post_dominators(range_start=addr, range_end=addr)
        post_dominators = pdom_resp.post_dominators
    except ghidra.GhidraError as e:
        print(f"ListPostDominators failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Total post-dominator records: {len(post_dominators)}")
    for p in post_dominators:
        exit_marker = " (exit)" if p.is_exit else ""
        print(f"  0x{p.block_address:x}  ipdom=0x{p.ipdom_address:x}"
              f"  depth={p.depth}{exit_marker}")

    # 6. Natural loops
    print(f"\n--- Loops for {target.name} ---")
    try:
        loops_resp = client.list_loops(range_start=addr, range_end=addr)
        loops = loops_resp.loops
    except ghidra.GhidraError as e:
        print(f"ListLoops failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Total loops: {len(loops)}")
    for lp in loops:
        print(f"  header=0x{lp.header_address:x}  back_edge=0x{lp.back_edge_source:x}"
              f"  kind={lp.loop_kind}  blocks={lp.block_count}  depth={lp.depth}")

    # 7. Decompile and inspect tokens
    print(f"\n--- Decompilation tokens for {target.name} ---")
    try:
        decomp_resp = client.get_decompilation(address=addr)
    except ghidra.GhidraError as e:
        print(f"GetDecompilation failed: {e}", file=sys.stderr)
        sys.exit(1)

    decomp = decomp_resp.decompilation
    if decomp is None:
        print("No decompilation returned.")
    else:
        print(f"Function: {decomp.function_name}")
        print(f"Prototype: {decomp.prototype}")
        print(f"Completed: {decomp.completed}")
        if decomp.error_message:
            print(f"Error: {decomp.error_message}")

        tokens = decomp.tokens
        print(f"\nTotal tokens: {len(tokens)}")

        # Token kind distribution
        kind_counts = Counter(t.kind.name for t in tokens)
        print("\nToken kinds:")
        for kind, count in kind_counts.most_common():
            print(f"  {kind:12s}  {count}")

        # Show first 20 tokens with detail
        preview = tokens[:20]
        print(f"\nFirst {len(preview)} tokens:")
        for t in preview:
            parts = [f"kind={t.kind.name}"]
            if t.var_name:
                parts.append(f"var={t.var_name}")
            if t.var_type:
                parts.append(f"type={t.var_type}")
            if t.var_storage:
                parts.append(f"storage={t.var_storage}")
            detail = ", ".join(parts)
            print(f"  L{t.line_number}:{t.column_offset:<4d} {t.text!r:20s}  ({detail})")

    # 8. Summary
    print(f"\n--- Summary ---")
    print(f"  Function:       {target.name}")
    print(f"  Address:        0x{addr:x}")
    print(f"  Size:           {target.size} bytes")
    print(f"  Switch tables:  {len(switch_tables)}")
    print(f"  Dominators:     {len(dominators)}")
    print(f"  Post-dominators:{len(post_dominators)}")
    print(f"  Loops:          {len(loops)}")
    if decomp is not None:
        print(f"  Decomp tokens:  {len(decomp.tokens)}")
        print(f"  Decomp lines:   {decomp.pseudocode.count(chr(10)) + 1}")

    print("\nDone.")


if __name__ == "__main__":
    main()
