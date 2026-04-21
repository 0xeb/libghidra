#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# end_to_end: Launch headless Ghidra, analyze a binary, enumerate functions
# with basic blocks and decompilation, save the project, and shut down.
#
# Usage:
#   python end_to_end.py --ghidra /path/to/ghidra_dist --binary /path/to/target.exe
#
# Prerequisites:
#   - Ghidra distribution with the LibGhidraHost extension installed
#     (install via: gradle installExtension -PGHIDRA_INSTALL_DIR=<dist>)
#   - pip install -e libghidra/python

import argparse
import sys

import libghidra as ghidra


def analyze(client: ghidra.GhidraClient) -> None:
    """Enumerate every function with its basic blocks and decompilation."""
    funcs_resp = client.list_functions()
    functions = funcs_resp.functions
    print(f"\n{'=' * 70}")
    print(f"  {len(functions)} functions found")
    print(f"{'=' * 70}\n")

    for func in functions:
        addr = func.entry_address
        print(f"--- {func.name} @ 0x{addr:x}  ({func.size} bytes, {func.parameter_count} params) ---")

        # Basic blocks
        bb_resp = client.list_basic_blocks(
            range_start=func.start_address,
            range_end=func.end_address,
        )
        blocks = bb_resp.blocks
        if blocks:
            print(f"  Basic blocks ({len(blocks)}):")
            for b in blocks:
                print(f"    0x{b.start_address:x}..0x{b.end_address:x}"
                      f"  in_degree={b.in_degree}  out_degree={b.out_degree}")
        else:
            print("  Basic blocks: (none)")

        # CFG edges
        edge_resp = client.list_cfg_edges(
            range_start=func.start_address,
            range_end=func.end_address,
        )
        if edge_resp.edges:
            print(f"  CFG edges ({len(edge_resp.edges)}):")
            for e in edge_resp.edges:
                print(f"    0x{e.src_block_start:x} -> 0x{e.dst_block_start:x}  ({e.edge_kind})")

        # Decompilation
        try:
            dec_resp = client.get_decompilation(addr, timeout_ms=30000)
            if dec_resp.decompilation and dec_resp.decompilation.completed:
                code = dec_resp.decompilation.pseudocode
                lines = code.strip().splitlines()
                print(f"  Decompilation ({len(lines)} lines):")
                for line in lines:
                    print(f"    {line}")
            elif dec_resp.decompilation and dec_resp.decompilation.error_message:
                print(f"  Decompilation error: {dec_resp.decompilation.error_message}")
            else:
                print("  Decompilation: (empty)")
        except ghidra.GhidraError as e:
            print(f"  Decompilation failed: {e}")

        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="End-to-end: launch Ghidra, analyze a binary, enumerate "
                    "functions with basic blocks and decompilation, then save and exit.",
    )
    parser.add_argument(
        "--ghidra", required=True,
        help="Path to Ghidra distribution (e.g. C:/ghidra_dist/ghidra_12.1_DEV)",
    )
    parser.add_argument(
        "--binary", required=True,
        help="Path to the binary to analyze (PE, ELF, etc.)",
    )
    parser.add_argument("--port", type=int, default=18080, help="RPC port (default: 18080)")
    args = parser.parse_args()

    with ghidra.launch_headless(ghidra.HeadlessOptions(
        ghidra_dir=args.ghidra,
        binary=args.binary,
        port=args.port,
        on_output=lambda line: print(f"  [ghidra] {line}"),
    )) as h:
        status = h.get_status()
        print(f"\nConnected: {status.service_name} v{status.service_version} "
              f"(mode: {status.host_mode})\n")

        analyze(h.client)

        print("Saving project...")
        save_resp = h.save_program()
        print(f"  saved={save_resp.saved}")

    print("\nDone.")


if __name__ == "__main__":
    main()
