#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# function_signatures: Inspect and modify function signatures and parameters.
#
# Usage: python function_signatures.py [host_url]
#
# Demonstrates signature inspection, parameter rename/retype, and prototype override.

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

    # 2. Find a function with parameters (scan first 50 functions)
    print("\n--- Searching for a function with parameters ---")
    try:
        funcs = client.list_functions(limit=50)
    except ghidra.GhidraError as e:
        print(f"ListFunctions failed: {e}", file=sys.stderr)
        sys.exit(1)

    target = None
    for f in funcs.functions:
        # Decompile to make signature available
        try:
            client.get_decompilation(f.entry_address, timeout_ms=30000)
        except ghidra.GhidraError:
            continue
        try:
            sig_resp = client.get_function_signature(f.entry_address)
            if sig_resp.signature and sig_resp.signature.parameters:
                target = sig_resp.signature
                break
        except ghidra.GhidraError:
            continue

    if target is None:
        print("No function with parameters found in the first 50 functions.", file=sys.stderr)
        sys.exit(1)

    addr = target.function_entry_address
    print(f"Found: {target.function_name} at 0x{addr:x}")

    # 3. Show full signature details
    print(f"\n--- Signature for {target.function_name} ---")
    print(f"  Prototype:    {target.prototype}")
    print(f"  Return type:  {target.return_type}")
    print(f"  Convention:   {target.calling_convention}")
    print(f"  Has varargs:  {target.has_var_args}")
    print(f"  Parameters ({len(target.parameters)}):")
    for p in target.parameters:
        print(f"    [{p.ordinal}] {p.data_type} {p.name}"
              f"  (auto={p.is_auto_parameter}, indirect={p.is_forced_indirect})")

    # 4. List multiple function signatures
    print("\n--- Listing signatures (first 5) ---")
    try:
        sigs_resp = client.list_function_signatures(limit=5)
        for s in sigs_resp.signatures:
            param_count = len(s.parameters) if s.parameters else 0
            print(f"  0x{s.function_entry_address:x}  {s.function_name}  ({param_count} params)")
    except ghidra.GhidraError as e:
        print(f"ListFunctionSignatures failed: {e}", file=sys.stderr)

    # 5. Rename the first parameter
    if target.parameters:
        first_param = target.parameters[0]
        new_name = "renamed_param"
        print(f"\n--- Renaming parameter [{first_param.ordinal}] '{first_param.name}' -> '{new_name}' ---")
        try:
            resp = client.rename_function_parameter(addr, first_param.ordinal, new_name)
            print(f"Renamed: updated={resp.updated}, name={resp.name}")
        except ghidra.GhidraError as e:
            print(f"RenameFunctionParameter failed: {e}", file=sys.stderr)

    # 6. Change the first parameter's type
    if target.parameters:
        new_type = "void *"
        print(f"\n--- Changing parameter [{first_param.ordinal}] type to '{new_type}' ---")
        try:
            resp = client.set_function_parameter_type(addr, first_param.ordinal, new_type)
            print(f"Retyped: updated={resp.updated}, data_type={resp.data_type}")
        except ghidra.GhidraError as e:
            print(f"SetFunctionParameterType failed: {e}", file=sys.stderr)

    # 7. Set a new prototype on the function
    new_proto = f"int {target.function_name}(int a, int b)"
    print(f"\n--- Setting prototype: '{new_proto}' ---")
    try:
        resp = client.set_function_signature(addr, new_proto)
        print(f"Set: updated={resp.updated}")
        print(f"  Name:      {resp.function_name}")
        print(f"  Prototype: {resp.prototype}")
    except ghidra.GhidraError as e:
        print(f"SetFunctionSignature failed: {e}", file=sys.stderr)

    # 8. Verify the new signature
    print("\n--- Verifying updated signature ---")
    try:
        sig_resp = client.get_function_signature(addr)
        if sig_resp.signature:
            s = sig_resp.signature
            print(f"  Prototype:   {s.prototype}")
            print(f"  Return type: {s.return_type}")
            print(f"  Parameters ({len(s.parameters)}):")
            for p in s.parameters:
                print(f"    [{p.ordinal}] {p.data_type} {p.name}")
    except ghidra.GhidraError as e:
        print(f"GetFunctionSignature failed: {e}", file=sys.stderr)

    print("\nDone.")


if __name__ == "__main__":
    main()
