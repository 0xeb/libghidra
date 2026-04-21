#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# function_tags: Create tags, tag/untag functions, list mappings, clean up.
#
# Usage: python function_tags.py [host_url]
#
# Demonstrates full CRUD lifecycle for Ghidra function tags.

import sys

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

    # 2. Create two tags
    print("\n--- Creating tags ---")
    try:
        resp = client.create_function_tag("crypto", "Cryptographic routines")
        print(f"  Created 'crypto': created={resp.created}")
    except ghidra.GhidraError as e:
        print(f"  CreateFunctionTag 'crypto' failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        resp = client.create_function_tag("network", "Network I/O functions")
        print(f"  Created 'network': created={resp.created}")
    except ghidra.GhidraError as e:
        print(f"  CreateFunctionTag 'network' failed: {e}", file=sys.stderr)

    # 3. List all tags
    print("\n--- All function tags ---")
    try:
        resp = client.list_function_tags()
        for t in resp.tags:
            print(f"  name='{t.name}'  comment='{t.comment}'")
    except ghidra.GhidraError as e:
        print(f"ListFunctionTags failed: {e}", file=sys.stderr)

    # 4. Get first two functions and tag them
    print("\n--- Tagging functions ---")
    try:
        funcs = client.list_functions(limit=2)
    except ghidra.GhidraError as e:
        print(f"ListFunctions failed: {e}", file=sys.stderr)
        sys.exit(1)

    for f in funcs.functions:
        try:
            resp = client.tag_function(f.entry_address, "crypto")
            print(f"  Tagged {f.name} with 'crypto': updated={resp.updated}")
        except ghidra.GhidraError as e:
            print(f"  TagFunction failed: {e}", file=sys.stderr)

    # Also tag first function with 'network'
    if funcs.functions:
        first = funcs.functions[0]
        try:
            resp = client.tag_function(first.entry_address, "network")
            print(f"  Tagged {first.name} with 'network': updated={resp.updated}")
        except ghidra.GhidraError as e:
            print(f"  TagFunction failed: {e}", file=sys.stderr)

    # 5. List all mappings
    print("\n--- All tag mappings ---")
    try:
        resp = client.list_function_tag_mappings()
        for m in resp.mappings:
            print(f"  0x{m.function_entry:x} -> '{m.tag_name}'")
    except ghidra.GhidraError as e:
        print(f"ListFunctionTagMappings failed: {e}", file=sys.stderr)

    # 6. List mappings for first function only
    if funcs.functions:
        first = funcs.functions[0]
        print(f"\n--- Tags for {first.name} (0x{first.entry_address:x}) ---")
        try:
            resp = client.list_function_tag_mappings(first.entry_address)
            for m in resp.mappings:
                print(f"  '{m.tag_name}'")
        except ghidra.GhidraError as e:
            print(f"ListFunctionTagMappings failed: {e}", file=sys.stderr)

    # 7. Untag and clean up
    print("\n--- Cleanup ---")
    for f in funcs.functions:
        try:
            client.untag_function(f.entry_address, "crypto")
        except ghidra.GhidraError:
            pass
    if funcs.functions:
        try:
            client.untag_function(funcs.functions[0].entry_address, "network")
        except ghidra.GhidraError:
            pass
    print("  Untagged all functions")

    try:
        client.delete_function_tag("crypto")
        client.delete_function_tag("network")
        print("  Deleted both tags")
    except ghidra.GhidraError as e:
        print(f"  DeleteFunctionTag failed: {e}", file=sys.stderr)

    print("\nDone.")


if __name__ == "__main__":
    main()
