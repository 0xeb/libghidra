#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# annotate_and_export: Create types, rename functions, add comments, then
# decompile all functions and write the output to a file.
#
# Demonstrates mutation operations: CreateType, CreateTypeEnum, RenameFunction,
# SetComment, SetFunctionSignature, plus batch decompilation.
#
# Usage: python annotate_and_export.py [host_url] [output_file]

import sys

import libghidra as ghidra


def main() -> None:
    host_url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    output_file = sys.argv[2] if len(sys.argv) >= 3 else "decompiled.c"

    client = ghidra.connect(host_url)

    try:
        status = client.get_status()
    except ghidra.GhidraError as e:
        print(f"Cannot reach host at {host_url}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Connected: {status.service_name} v{status.service_version}")

    # -- Create types ----------------------------------------------------------
    print("\nCreating types...")

    try:
        client.create_type("context_t", "struct", 64)
        print("  Created struct context_t (64 bytes)")
    except ghidra.GhidraError as e:
        print(f"  CreateType(context_t): {e}")

    try:
        client.create_type_enum("error_code_t", width=4, is_signed=False)
        print("  Created enum error_code_t (4 bytes)")
    except ghidra.GhidraError as e:
        print(f"  CreateTypeEnum(error_code_t): {e}")

    try:
        client.add_type_enum_member("error_code_t", "ERR_NONE", 0)
        client.add_type_enum_member("error_code_t", "ERR_INVALID", 1)
        client.add_type_enum_member("error_code_t", "ERR_TIMEOUT", 2)
        print("  Added 3 enum members to error_code_t")
    except ghidra.GhidraError as e:
        print(f"  AddTypeEnumMember: {e}")

    try:
        client.add_type_member("context_t", "flags", "int", 4)
        client.add_type_member("context_t", "status", "error_code_t", 4)
        print("  Added 2 struct members to context_t")
    except ghidra.GhidraError as e:
        print(f"  AddTypeMember: {e}")

    # -- Rename functions and add comments -------------------------------------
    print("\nAnnotating functions...")

    funcs = client.list_functions(limit=5)
    renames = [
        ("entry", "program_entry"),
        ("init", "initialize_subsystems"),
        ("main", "application_main"),
    ]

    for f in funcs.functions:
        # Try renaming well-known function names
        for old, new in renames:
            if f.name.lower().startswith(old):
                try:
                    resp = client.rename_function(f.entry_address, new)
                    if resp.renamed:
                        print(f"  Renamed {f.name} -> {new}")
                except ghidra.GhidraError:
                    pass

        # Add a plate comment to every function
        try:
            client.set_comment(
                f.entry_address,
                ghidra.CommentKind.PLATE,
                f"Auto-analyzed by libghidra Python client\n"
                f"Original name: {f.name}\n"
                f"Size: {f.size} bytes, Params: {f.parameter_count}",
            )
        except ghidra.GhidraError:
            pass

    # -- Batch decompile -------------------------------------------------------
    print(f"\nDecompiling all functions...")

    all_funcs = client.list_functions()
    total = len(all_funcs.functions)

    results = client.list_decompilations(limit=total, timeout_ms=60000)
    succeeded = sum(1 for d in results.decompilations if d.completed)
    failed = total - succeeded

    print(f"  {succeeded}/{total} succeeded, {failed} failed")

    # -- Export to file --------------------------------------------------------
    print(f"\nWriting to {output_file}...")

    with open(output_file, "w") as out:
        out.write(f"// Decompiled output from {status.service_name}\n")
        out.write(f"// {succeeded} functions\n\n")

        for d in results.decompilations:
            if not d.completed or not d.pseudocode:
                continue
            out.write(f"// ========== {d.function_name} @ 0x{d.function_entry_address:x} ==========\n")
            out.write(d.pseudocode)
            out.write("\n\n")

    print(f"  Wrote {succeeded} functions to {output_file}")

    # -- Save ------------------------------------------------------------------
    try:
        client.save_program()
        print("\nProgram saved.")
    except ghidra.GhidraError as e:
        print(f"\nSave failed: {e}")

    print("Done.")


if __name__ == "__main__":
    main()
