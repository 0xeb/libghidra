#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# async_explore: Async client usage with AsyncGhidraClient.
#
# Usage: python async_explore.py [host_url]
#
# Demonstrates the async context manager, status check, function listing,
# and decompilation using asyncio.

import asyncio
import sys

from libghidra import ConnectOptions
from libghidra.async_client import AsyncGhidraClient


async def main() -> None:
    url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"

    async with AsyncGhidraClient(ConnectOptions(base_url=url)) as client:

        # 1. Check host status
        print("--- Host status (async) ---")
        status = await client.get_status()
        print(f"  Service:  {status.service_name} v{status.service_version}")
        print(f"  Mode:     {status.host_mode}")
        print(f"  OK:       {status.ok}")

        # 2. List functions
        print("\n--- Functions (first 10, async) ---")
        funcs = await client.list_functions(limit=10)
        print(f"  Total returned: {len(funcs.functions)}")
        for f in funcs.functions:
            print(f"  0x{f.entry_address:x}  {f.name}  ({f.size} bytes)")

        # 3. Decompile the first function
        if funcs.functions:
            target = funcs.functions[0]
            print(f"\n--- Decompiling {target.name} at 0x{target.entry_address:x} (async) ---")
            resp = await client.get_decompilation(target.entry_address, timeout_ms=30000)
            if resp.decompilation and resp.decompilation.pseudocode:
                lines = resp.decompilation.pseudocode.strip().splitlines()
                print(f"  Prototype: {resp.decompilation.prototype}")
                print(f"  Lines of pseudocode: {len(lines)}")
                # Show first 10 lines
                preview = lines[:10]
                for line in preview:
                    print(f"    {line}")
                if len(lines) > 10:
                    print(f"    ... ({len(lines) - 10} more lines)")
            else:
                print("  Decompilation returned empty pseudocode.", file=sys.stderr)

        # 4. Get capabilities
        print("\n--- Capabilities (async) ---")
        caps = await client.get_capabilities()
        for cap in caps:
            note = f" ({cap.note})" if cap.note else ""
            print(f"  {cap.id}: {cap.status}{note}")

    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
