#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# data_items: Data item CRUD -- apply types, list, rename, and delete data items.
#
# Usage: python data_items.py [host_url]
#
# Defaults: http://127.0.0.1:18080, expects a program already open in Ghidra.

import sys

import libghidra as ghidra


def main() -> None:
    url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    client = ghidra.connect(url)

    # 1. Find an address in an initialized memory block to work with
    try:
        mem_resp = client.list_memory_blocks()
    except ghidra.GhidraError as e:
        print(f"list_memory_blocks failed: {e}", file=sys.stderr)
        sys.exit(1)

    blocks = mem_resp.blocks
    if not blocks:
        print("No memory blocks found -- is a program open?", file=sys.stderr)
        sys.exit(1)

    # Prefer a read-only initialized block (likely .rdata or .rodata)
    target_block = next(
        (b for b in blocks if b.is_initialized and b.is_read and not b.is_execute),
        next((b for b in blocks if b.is_initialized), blocks[0]),
    )

    # Use an address 16 bytes into the block to avoid header overlap
    addr = target_block.start_address + 16
    print(f"Working in block '{target_block.name}' at 0x{addr:08x}")

    # 2. Apply a data type at the chosen address
    type_name = "int"
    print(f"\nApplying data type '{type_name}' at 0x{addr:08x}...")
    try:
        apply_resp = client.apply_data_type(addr, type_name)
        print(f"  updated={apply_resp.updated}  data_type={apply_resp.data_type}")
    except ghidra.GhidraError as e:
        print(f"  apply_data_type failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. List data items in the surrounding range
    range_start = target_block.start_address
    range_end = min(target_block.end_address, range_start + 256)
    try:
        list_resp = client.list_data_items(range_start=range_start, range_end=range_end)
    except ghidra.GhidraError as e:
        print(f"list_data_items failed: {e}", file=sys.stderr)
        sys.exit(1)

    items = list_resp.data_items
    print(f"\nData items in 0x{range_start:08x}..0x{range_end:08x} ({len(items)} items):")
    for item in items:
        name_str = item.name if item.name else "(unnamed)"
        print(f"  0x{item.address:08x}  {item.data_type:<16}  {item.size:>4} bytes  {name_str}  val={item.value_repr}")

    # 4. Rename the data item we created
    new_name = "example_int_value"
    print(f"\nRenaming data item at 0x{addr:08x} to '{new_name}'...")
    try:
        rename_resp = client.rename_data_item(addr, new_name)
        print(f"  updated={rename_resp.updated}  name={rename_resp.name}")
    except ghidra.GhidraError as e:
        print(f"  rename_data_item failed: {e}", file=sys.stderr)

    # Verify the rename by listing again
    verify = client.list_data_items(range_start=addr, range_end=addr + 4)
    for item in verify.data_items:
        if item.address == addr:
            print(f"  Verified: name is now '{item.name}'")

    # 5. Delete the data item
    print(f"\nDeleting data item at 0x{addr:08x}...")
    try:
        del_resp = client.delete_data_item(addr)
        print(f"  deleted={del_resp.deleted}")
    except ghidra.GhidraError as e:
        print(f"  delete_data_item failed: {e}", file=sys.stderr)

    # Verify deletion
    after = client.list_data_items(range_start=addr, range_end=addr + 4)
    found = any(item.address == addr for item in after.data_items)
    if not found:
        print("  Verified: data item removed.")
    else:
        print("  WARNING: data item still present.")

    print("\nDone.")


if __name__ == "__main__":
    main()
