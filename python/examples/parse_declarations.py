#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# parse_declarations: Import C type declarations, verify, clean up.
#
# Usage: python parse_declarations.py [host_url]
#
# Demonstrates bulk C type import via Ghidra's CParser.

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

    # 2. Parse a block of C declarations
    decls = """\
typedef enum ExampleOpcode {
    OP_NONE = 0,
    OP_INIT = 1,
    OP_PROCESS = 2,
    OP_SHUTDOWN = 3
} ExampleOpcode;

typedef struct ExampleHeader {
    int magic;
    int version;
    int flags;
} ExampleHeader;

typedef struct ExamplePacket {
    ExampleHeader header;
    ExampleOpcode opcode;
    int payload_size;
} ExamplePacket;
"""

    print("\n--- Parsing C declarations ---")
    try:
        resp = client.parse_declarations(decls)
        print(f"Types created: {resp.types_created}")
        for name in resp.type_names:
            print(f"  + {name}")
        if resp.errors:
            print("Errors:")
            for err in resp.errors:
                print(f"  ! {err}")
    except ghidra.GhidraError as e:
        print(f"ParseDeclarations failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Verify the types exist in the type system
    print("\n--- Verifying types ---")
    check_names = ["/ExampleOpcode", "/ExampleHeader", "/ExamplePacket"]
    for name in check_names:
        try:
            resp = client.get_type(name)
            if resp.type:
                t = resp.type
                print(f"  {name}: kind={t.kind} length={t.length}")
            else:
                print(f"  {name}: NOT FOUND")
        except ghidra.GhidraError:
            print(f"  {name}: NOT FOUND")

    # 4. Clean up: delete the types we created
    print("\n--- Cleanup ---")
    for name in reversed(check_names):
        try:
            client.delete_type(name)
        except ghidra.GhidraError:
            pass
    print("  Deleted all example types")

    print("\nDone.")


if __name__ == "__main__":
    main()
