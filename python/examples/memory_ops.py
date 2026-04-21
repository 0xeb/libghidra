#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# memory_ops: Memory block inspection, byte reads, writes, and batch patches.
#
# Usage: python memory_ops.py [host_url]
#
# Defaults: http://127.0.0.1:18080, expects a program already open in Ghidra.

import sys

import libghidra as ghidra
from libghidra.models import BytePatch


def hex_dump(data: bytes, base_addr: int, width: int = 16) -> str:
    """Format raw bytes as a classic hex dump."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  0x{base_addr + i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def main() -> None:
    url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    client = ghidra.connect(url)

    # 1. List all memory blocks
    try:
        resp = client.list_memory_blocks()
    except ghidra.GhidraError as e:
        print(f"list_memory_blocks failed: {e}", file=sys.stderr)
        sys.exit(1)

    blocks = resp.blocks
    print(f"Memory blocks ({len(blocks)}):")
    for blk in blocks:
        perms = ("R" if blk.is_read else "-") + ("W" if blk.is_write else "-") + ("X" if blk.is_execute else "-")
        print(f"  {blk.name:<16} 0x{blk.start_address:08x}..0x{blk.end_address:08x}  {blk.size:>8} bytes  {perms}")

    if not blocks:
        print("No memory blocks found -- is a program open?", file=sys.stderr)
        sys.exit(1)

    # 2. Read 64 bytes from the start of the first initialized block
    target = next((b for b in blocks if b.is_initialized), blocks[0])
    read_len = min(64, target.size)
    addr = target.start_address

    try:
        read_resp = client.read_bytes(addr, read_len)
    except ghidra.GhidraError as e:
        print(f"read_bytes failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nRead {len(read_resp.data)} bytes from '{target.name}' at 0x{addr:08x}:")
    print(hex_dump(read_resp.data, addr))

    # Save original bytes for restoration
    original = read_resp.data[:4]

    # 3. Write 4 bytes at the same address
    patch_data = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    try:
        write_resp = client.write_bytes(addr, patch_data)
        print(f"\nWrote {write_resp.bytes_written} bytes at 0x{addr:08x}")
    except ghidra.GhidraError as e:
        print(f"write_bytes failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Verify the write
    verify = client.read_bytes(addr, 4)
    print(f"Verify: {verify.data.hex()}")

    # 4. Batch-patch two locations at once
    patches = [
        BytePatch(address=addr, data=original),
        BytePatch(address=addr + 2, data=bytes([0xCA, 0xFE])),
    ]
    try:
        batch_resp = client.patch_bytes_batch(patches)
        print(f"\nBatch patch: {batch_resp.patch_count} patches, {batch_resp.bytes_written} bytes written")
    except ghidra.GhidraError as e:
        print(f"patch_bytes_batch failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Final read to show result
    final = client.read_bytes(addr, 8)
    print(f"Final state at 0x{addr:08x}: {final.data.hex()}")

    # 5. Restore original bytes
    client.write_bytes(addr, original)
    restored = client.read_bytes(addr, 4)
    print(f"Restored: {restored.data.hex()}")

    print("\nDone.")


if __name__ == "__main__":
    main()
