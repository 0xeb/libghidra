#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# disassemble: List functions, pick one, and show its disassembly.
#
# Usage: python disassemble.py [host_url]
#
# Defaults: http://127.0.0.1:18080, expects a program already open in Ghidra.

import sys

import libghidra as ghidra


def main() -> None:
    url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    client = ghidra.connect(url)

    # 1. List functions to find a target
    try:
        func_resp = client.list_functions(limit=20)
    except ghidra.GhidraError as e:
        print(f"list_functions failed: {e}", file=sys.stderr)
        sys.exit(1)

    functions = func_resp.functions
    if not functions:
        print("No functions found -- is a program open?", file=sys.stderr)
        sys.exit(1)

    print(f"Functions ({len(functions)} shown):")
    for f in functions:
        params = f"({f.parameter_count} params)" if f.parameter_count else ""
        thunk = " [thunk]" if f.is_thunk else ""
        print(f"  0x{f.entry_address:08x}  {f.name:<32}  {f.size:>6} bytes  {params}{thunk}")

    # 2. Pick the largest non-thunk function for interesting disassembly
    candidates = [f for f in functions if not f.is_thunk and f.size > 0]
    target = max(candidates, key=lambda f: f.size) if candidates else functions[0]

    print(f"\nTarget: {target.name} at 0x{target.entry_address:08x} ({target.size} bytes)")
    if target.prototype:
        print(f"Prototype: {target.prototype}")

    # 3. Get the single instruction at the entry point
    try:
        single = client.get_instruction(target.entry_address)
    except ghidra.GhidraError as e:
        print(f"get_instruction failed: {e}", file=sys.stderr)
        sys.exit(1)

    if single.instruction:
        insn = single.instruction
        print(f"\nEntry instruction:")
        print(f"  0x{insn.address:08x}  {insn.disassembly}  ({insn.length} bytes)")

    # 4. List all instructions in the function range
    try:
        insn_resp = client.list_instructions(
            range_start=target.start_address,
            range_end=target.end_address,
        )
    except ghidra.GhidraError as e:
        print(f"list_instructions failed: {e}", file=sys.stderr)
        sys.exit(1)

    instructions = insn_resp.instructions
    print(f"\nDisassembly of {target.name} ({len(instructions)} instructions):")
    print(f"  {'Address':<18}  {'Mnemonic':<12}  {'Operands':<32}  {'Len':>3}")
    print(f"  {'-' * 18}  {'-' * 12}  {'-' * 32}  {'-' * 3}")

    for insn in instructions:
        print(f"  0x{insn.address:08x}        {insn.mnemonic:<12}  {insn.operand_text:<32}  {insn.length:>3}")

    # 5. Summary
    total_bytes = sum(i.length for i in instructions)
    unique_mnemonics = len(set(i.mnemonic for i in instructions))
    print(f"\nSummary: {len(instructions)} instructions, {total_bytes} bytes, {unique_mnemonics} unique mnemonics")

    # Mnemonic frequency
    freq: dict[str, int] = {}
    for insn in instructions:
        freq[insn.mnemonic] = freq.get(insn.mnemonic, 0) + 1
    top = sorted(freq.items(), key=lambda kv: kv[1], reverse=True)[:5]
    print("Top mnemonics:")
    for mnem, count in top:
        print(f"  {mnem:<12}  {count}")

    print("\nDone.")


if __name__ == "__main__":
    main()
