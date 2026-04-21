#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# symbols: Symbol operations -- list, get, rename, restore, and delete symbols.
#
# Usage: python symbols.py [host_url]
#
# Defaults: http://127.0.0.1:18080, expects a program already open in Ghidra.

import sys

import libghidra as ghidra


def main() -> None:
    url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    client = ghidra.connect(url)

    # 1. List symbols (first page)
    try:
        sym_resp = client.list_symbols(limit=20)
    except ghidra.GhidraError as e:
        print(f"list_symbols failed: {e}", file=sys.stderr)
        sys.exit(1)

    symbols = sym_resp.symbols
    if not symbols:
        print("No symbols found -- is a program open?", file=sys.stderr)
        sys.exit(1)

    print(f"Symbols ({len(symbols)} shown):")
    for s in symbols:
        ns = f"  ns={s.namespace_name}" if s.namespace_name else ""
        flags = []
        if s.is_primary:
            flags.append("primary")
        if s.is_external:
            flags.append("external")
        if s.is_dynamic:
            flags.append("dynamic")
        flag_str = f"  [{', '.join(flags)}]" if flags else ""
        print(f"  0x{s.address:08x}  {s.name:<32}  type={s.type:<12}{ns}{flag_str}")

    # 2. Pick a function entry to work with
    try:
        func_resp = client.list_functions(limit=10)
    except ghidra.GhidraError as e:
        print(f"list_functions failed: {e}", file=sys.stderr)
        sys.exit(1)

    if not func_resp.functions:
        print("No functions found.", file=sys.stderr)
        sys.exit(1)

    target = func_resp.functions[0]
    addr = target.entry_address
    original_name = target.name
    print(f"\nTarget function: {original_name} at 0x{addr:08x}")

    # 3. Get the symbol at this address
    try:
        get_resp = client.get_symbol(addr)
    except ghidra.GhidraError as e:
        print(f"get_symbol failed: {e}", file=sys.stderr)
        sys.exit(1)

    if get_resp.symbol:
        s = get_resp.symbol
        print(f"  Symbol: id={s.symbol_id}  name={s.name}  full={s.full_name}  type={s.type}  source={s.source}")
    else:
        print("  No symbol at this address.")

    # 4. Rename the symbol
    new_name = "example_renamed_symbol"
    print(f"\nRenaming symbol at 0x{addr:08x} to '{new_name}'...")
    try:
        rename_resp = client.rename_symbol(addr, new_name)
        print(f"  renamed={rename_resp.renamed}  name={rename_resp.name}")
    except ghidra.GhidraError as e:
        print(f"  rename_symbol failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Verify
    verify = client.get_symbol(addr)
    if verify.symbol:
        print(f"  Verified: symbol name is now '{verify.symbol.name}'")

    # 5. Restore the original name
    print(f"\nRestoring original name '{original_name}'...")
    try:
        restore_resp = client.rename_symbol(addr, original_name)
        print(f"  renamed={restore_resp.renamed}  name={restore_resp.name}")
    except ghidra.GhidraError as e:
        print(f"  rename_symbol failed: {e}", file=sys.stderr)

    # Verify restoration
    restored = client.get_symbol(addr)
    if restored.symbol and restored.symbol.name == original_name:
        print(f"  Verified: name restored to '{original_name}'")

    # 6. Show symbol deletion (on a secondary symbol if possible)
    #    We create a temporary rename, then delete it to demonstrate the API.
    temp_name = "temp_delete_me"
    print(f"\nDemonstrating delete_symbol...")
    print(f"  Renaming to '{temp_name}' first...")
    client.rename_symbol(addr, temp_name)

    try:
        del_resp = client.delete_symbol(addr, name_filter=temp_name)
        print(f"  deleted={del_resp.deleted}  deleted_count={del_resp.deleted_count}")
    except ghidra.GhidraError as e:
        print(f"  delete_symbol failed: {e}", file=sys.stderr)
        # Restore if delete didn't work
        client.rename_symbol(addr, original_name)

    # Final state
    final = client.get_symbol(addr)
    if final.symbol:
        print(f"  Final symbol: {final.symbol.name}")
    else:
        print("  Symbol removed.")

    print("\nDone.")


if __name__ == "__main__":
    main()
