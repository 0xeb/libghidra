#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# session_lifecycle: Session management, mutations, revisions, discard, and save.
#
# Usage: python session_lifecycle.py [host_url]
#
# Demonstrates status checks, capabilities, revision tracking,
# function renaming, discard (undo), and save.

import sys

import libghidra as ghidra


def main() -> None:
    url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    client = ghidra.connect(url)

    # 1. Check host status
    print("--- Host status ---")
    try:
        status = client.get_status()
    except ghidra.GhidraError as e:
        print(f"Cannot reach host at {url}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"  Service:  {status.service_name} v{status.service_version}")
    print(f"  Mode:     {status.host_mode}")
    print(f"  Revision: {status.program_revision}")
    print(f"  OK:       {status.ok}")
    if status.warnings:
        for w in status.warnings:
            print(f"  Warning:  {w}")

    # 2. List capabilities
    print("\n--- Capabilities ---")
    try:
        caps = client.get_capabilities()
        for cap in caps:
            note = f" ({cap.note})" if cap.note else ""
            print(f"  {cap.id}: {cap.status}{note}")
    except ghidra.GhidraError as e:
        print(f"GetCapabilities failed: {e}", file=sys.stderr)

    # 3. Get current revision
    print("\n--- Current revision ---")
    try:
        rev_resp = client.get_revision()
        rev_before = rev_resp.revision
        print(f"  Revision: {rev_before}")
    except ghidra.GhidraError as e:
        print(f"GetRevision failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Find a function to rename
    try:
        funcs = client.list_functions(limit=10)
    except ghidra.GhidraError as e:
        print(f"ListFunctions failed: {e}", file=sys.stderr)
        sys.exit(1)

    if not funcs.functions:
        print("No functions available.", file=sys.stderr)
        sys.exit(1)

    target = funcs.functions[0]
    addr = target.entry_address
    original_name = target.name

    # 5. Rename the function to create a mutation
    temp_name = "lifecycle_test_renamed"
    print(f"\n--- Renaming 0x{addr:x} '{original_name}' -> '{temp_name}' ---")
    try:
        resp = client.rename_function(addr, temp_name)
        print(f"  Renamed: {resp.renamed}, new name: {resp.name}")
    except ghidra.GhidraError as e:
        print(f"RenameFunction failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 6. Check revision after mutation
    print("\n--- Revision after mutation ---")
    try:
        rev_resp = client.get_revision()
        rev_after = rev_resp.revision
        print(f"  Revision before: {rev_before}")
        print(f"  Revision after:  {rev_after}")
        print(f"  Changed: {rev_after != rev_before}")
    except ghidra.GhidraError as e:
        print(f"GetRevision failed: {e}", file=sys.stderr)

    # 7. Discard changes (undo the rename)
    print("\n--- Discarding changes ---")
    try:
        resp = client.discard_program()
        print(f"  Discarded: {resp.discarded}")
    except ghidra.GhidraError as e:
        print(f"DiscardProgram failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 8. Verify the function name is restored
    print("\n--- Verifying name restored ---")
    try:
        funcs = client.list_functions(limit=10)
        restored = None
        for f in funcs.functions:
            if f.entry_address == addr:
                restored = f
                break
        if restored:
            print(f"  Address:  0x{addr:x}")
            print(f"  Name:     {restored.name}")
            print(f"  Restored: {restored.name == original_name}")
        else:
            print(f"  Function at 0x{addr:x} not found after discard.")
    except ghidra.GhidraError as e:
        print(f"ListFunctions failed: {e}", file=sys.stderr)

    # 9. Save program (commits current state to disk)
    print("\n--- Saving program ---")
    try:
        resp = client.save_program()
        print(f"  Saved: {resp.saved}")
    except ghidra.GhidraError as e:
        print(f"SaveProgram failed: {e}", file=sys.stderr)

    print("\nDone.")


if __name__ == "__main__":
    main()
