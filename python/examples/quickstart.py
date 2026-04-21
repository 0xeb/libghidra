#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# quickstart: Connect to a running LibGhidraHost, list functions, decompile one.
#
# Usage: python quickstart.py [host_url] [project_path] [program_path]
#
# Defaults: http://127.0.0.1:18080, expects a program already open in Ghidra.

import sys

import libghidra as ghidra


def main() -> None:
    host_url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"

    client = ghidra.connect(host_url)

    # 1. Check host health
    try:
        status = client.get_status()
    except ghidra.GhidraError as e:
        print(f"Cannot reach host at {host_url}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Connected: {status.service_name} v{status.service_version} (mode: {status.host_mode})")

    # 2. Open a program (if project path provided on command line)
    if len(sys.argv) >= 4:
        try:
            resp = client.open_program(ghidra.OpenRequest(
                project_path=sys.argv[2],
                program_path=sys.argv[3],
            ))
            print(f"Opened: {resp.program_name} (lang={resp.language_id}, base=0x{resp.image_base:x})")
        except ghidra.GhidraError as e:
            print(f"OpenProgram failed: {e}", file=sys.stderr)
            sys.exit(1)

    # 3. List the first 10 functions
    try:
        funcs = client.list_functions(limit=10)
    except ghidra.GhidraError as e:
        print(f"ListFunctions failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nFunctions ({len(funcs.functions)} shown):")
    for f in funcs.functions:
        print(f"  0x{f.entry_address:x}  {f.name}  ({f.size} bytes)")

    # 4. Decompile the first function
    if funcs.functions:
        f = funcs.functions[0]
        print(f"\nDecompiling {f.name} at 0x{f.entry_address:x}...")
        try:
            resp = client.get_decompilation(f.entry_address, timeout_ms=30000)
            if resp.decompilation and resp.decompilation.pseudocode:
                print(f"\n{resp.decompilation.pseudocode}")
            else:
                print("Decompilation returned empty pseudocode", file=sys.stderr)
        except ghidra.GhidraError as e:
            print(f"Decompilation failed: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
