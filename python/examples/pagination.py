#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""pagination: demonstrate fetching every page of a paginated list RPC.

Mirrors rust/examples/pagination.rs. The Python client doesn't ship a
dedicated Paginator class — the simple loop below is the idiomatic
equivalent.

Usage: python pagination.py [host_url]
"""

from __future__ import annotations

import sys

import libghidra as ghidra


def fetch_all(call, page_size: int = 100):
    """Collect every page from a paginated list RPC.

    `call(limit, offset)` should return the items vector for one page.
    """
    items: list = []
    offset = 0
    while True:
        page = call(page_size, offset)
        if not page:
            break
        items.extend(page)
        offset += len(page)
        if len(page) < page_size:
            break
    return items


def main() -> int:
    url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    client = ghidra.connect(url)

    print("=== fetch_all: all functions ===\n")
    all_funcs = fetch_all(
        lambda limit, offset: client.list_functions(
            range_start=0, range_end=2**64 - 1, limit=limit, offset=offset
        ).functions
    )
    print(f"Total functions: {len(all_funcs)}")
    for i, f in enumerate(all_funcs[:10]):
        print(f"  [{i:>3}] 0x{f.entry_address:x}  {f.name}  ({f.size} bytes)")
    if len(all_funcs) > 10:
        print(f"  ... and {len(all_funcs) - 10} more")

    print("\n=== page-by-page: symbols (page_size=25) ===\n")
    page_num = 0
    total_symbols = 0
    offset = 0
    while page_num < 5:
        items = client.list_symbols(
            range_start=0, range_end=2**64 - 1, limit=25, offset=offset
        ).symbols
        if not items:
            break
        page_num += 1
        total_symbols += len(items)
        first = items[0].name if items else "?"
        last = items[-1].name if items else "?"
        print(
            f"Page {page_num}: {len(items)} symbols "
            f"(first: '{first}', last: '{last}')"
        )
        offset += len(items)

    print("\n=== fetch_all: all function signatures ===\n")
    all_sigs = fetch_all(
        lambda limit, offset: client.list_function_signatures(
            range_start=0, range_end=2**64 - 1, limit=limit, offset=offset
        ).signatures
    )
    print(f"Total signatures: {len(all_sigs)}")
    for sig in all_sigs[:5]:
        print(
            f"  0x{sig.function_entry_address:x}  "
            f"{sig.function_name} -> {sig.prototype}"
        )
    if len(all_sigs) > 5:
        print(f"  ... and {len(all_sigs) - 5} more")

    print("\n=== Summary ===")
    print(f"  Functions:  {len(all_funcs)}")
    print(f"  Signatures: {len(all_sigs)}")
    print(f"  Symbols:    {total_symbols}+ (first {page_num} pages)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
