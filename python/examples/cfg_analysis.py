#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# cfg_analysis: Analyze control flow graphs (basic blocks and edges).
#
# Usage: python cfg_analysis.py [host_url]
#
# Finds a non-trivial function, lists its basic blocks and CFG edges,
# builds an adjacency list, and identifies entry/exit blocks.

import sys
from collections import defaultdict

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
    print("\n--- Searching for a non-trivial function (size > 64 bytes) ---")
    try:
        funcs = client.list_functions(limit=100)
    except ghidra.GhidraError as e:
        print(f"ListFunctions failed: {e}", file=sys.stderr)
        sys.exit(1)

    target = None
    for f in funcs.functions:
        if f.size > 64:
            target = f
            break

    if target is None:
        print("No function larger than 64 bytes found.", file=sys.stderr)
        sys.exit(1)

    addr = target.entry_address
    print(f"Selected: {target.name} at 0x{addr:x} ({target.size} bytes)")

    # 3. List basic blocks for the function
    print(f"\n--- Basic blocks for {target.name} ---")
    try:
        blocks_resp = client.list_basic_blocks(range_start=addr, range_end=addr)
        blocks = blocks_resp.blocks
    except ghidra.GhidraError as e:
        print(f"ListBasicBlocks failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Total blocks: {len(blocks)}")
    for b in blocks:
        size = b.end_address - b.start_address
        print(f"  0x{b.start_address:x} - 0x{b.end_address:x}"
              f"  ({size} bytes, in={b.in_degree}, out={b.out_degree})")

    # 4. List CFG edges for the function
    print(f"\n--- CFG edges for {target.name} ---")
    try:
        edges_resp = client.list_cfg_edges(range_start=addr, range_end=addr)
        edges = edges_resp.edges
    except ghidra.GhidraError as e:
        print(f"ListCFGEdges failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Total edges: {len(edges)}")
    for e in edges:
        print(f"  0x{e.src_block_start:x} -> 0x{e.dst_block_start:x}  (kind={e.edge_kind})")

    # 5. Build adjacency list
    print(f"\n--- Adjacency list ---")
    successors = defaultdict(list)
    predecessors = defaultdict(list)
    block_addrs = {b.start_address for b in blocks}

    for e in edges:
        successors[e.src_block_start].append(e.dst_block_start)
        predecessors[e.dst_block_start].append(e.src_block_start)

    for b_addr in sorted(block_addrs):
        succs = successors.get(b_addr, [])
        succs_str = ", ".join(f"0x{s:x}" for s in succs) if succs else "(none)"
        print(f"  0x{b_addr:x} -> [{succs_str}]")

    # 6. Identify entry and exit blocks
    print(f"\n--- Entry and exit blocks ---")
    entry_blocks = [b for b in blocks if b.in_degree == 0]
    exit_blocks = [b for b in blocks if b.out_degree == 0]

    print(f"Entry blocks ({len(entry_blocks)}):")
    for b in entry_blocks:
        print(f"  0x{b.start_address:x}")

    print(f"Exit blocks ({len(exit_blocks)}):")
    for b in exit_blocks:
        print(f"  0x{b.start_address:x}")

    # 7. Print summary
    print(f"\n--- Summary ---")
    print(f"  Function:     {target.name}")
    print(f"  Address:      0x{addr:x}")
    print(f"  Size:         {target.size} bytes")
    print(f"  Basic blocks: {len(blocks)}")
    print(f"  CFG edges:    {len(edges)}")
    print(f"  Entry blocks: {len(entry_blocks)}")
    print(f"  Exit blocks:  {len(exit_blocks)}")

    print("\nDone.")


if __name__ == "__main__":
    main()
