#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# type_system: Type system overview -- structs, aliases, enums, and full lifecycle.
#
# Usage: python type_system.py [host_url]
#
# Defaults: http://127.0.0.1:18080, expects a program already open in Ghidra.

import sys

import libghidra as ghidra


def main() -> None:
    url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    client = ghidra.connect(url)

    # 1. List existing types
    try:
        types_resp = client.list_types(limit=10)
    except ghidra.GhidraError as e:
        print(f"list_types failed: {e}", file=sys.stderr)
        sys.exit(1)

    types = types_resp.types
    print(f"Existing types ({len(types)} shown):")
    for t in types:
        defined = "" if not t.is_not_yet_defined else "  [undefined]"
        print(f"  {t.name:<28}  kind={t.kind:<10}  size={t.length:>4}{defined}")

    # 2. Get details on a specific type
    if types:
        sample = types[0]
        print(f"\nDetails for '{sample.name}':")
        try:
            detail = client.get_type(sample.path_name)
            if detail.type:
                t = detail.type
                print(f"  id={t.type_id}  path={t.path_name}  category={t.category_path}")
                print(f"  display={t.display_name}  kind={t.kind}  length={t.length}")
                if t.source_archive:
                    print(f"  source_archive={t.source_archive}")
        except ghidra.GhidraError as e:
            print(f"  get_type failed: {e}", file=sys.stderr)

    # 3. Create a struct type
    struct_name = "ExampleStruct"
    print(f"\nCreating struct '{struct_name}' (size=16)...")
    try:
        create_resp = client.create_type(struct_name, "struct", 16)
        print(f"  updated={create_resp.updated}")
    except ghidra.GhidraError as e:
        print(f"  create_type failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Verify creation
    verify = client.get_type(f"/{struct_name}")
    if verify.type:
        print(f"  Verified: {verify.type.name} (kind={verify.type.kind}, size={verify.type.length})")

    # 4. Create a type alias pointing to our struct
    alias_name = "ExampleAlias"
    print(f"\nCreating alias '{alias_name}' -> '{struct_name}'...")
    try:
        alias_resp = client.create_type_alias(alias_name, struct_name)
        print(f"  updated={alias_resp.updated}")
    except ghidra.GhidraError as e:
        print(f"  create_type_alias failed: {e}", file=sys.stderr)

    # 5. Create an enum type
    enum_name = "ExampleEnum"
    print(f"\nCreating enum '{enum_name}' (width=4)...")
    try:
        enum_resp = client.create_type_enum(enum_name, width=4, is_signed=False)
        print(f"  updated={enum_resp.updated}")
    except ghidra.GhidraError as e:
        print(f"  create_type_enum failed: {e}", file=sys.stderr)

    # 6. Rename the struct type
    renamed = "ExampleStructRenamed"
    print(f"\nRenaming '{struct_name}' -> '{renamed}'...")
    try:
        ren_resp = client.rename_type(f"/{struct_name}", renamed)
        print(f"  updated={ren_resp.updated}  name={ren_resp.name}")
    except ghidra.GhidraError as e:
        print(f"  rename_type failed: {e}", file=sys.stderr)
        renamed = struct_name  # fall back for cleanup

    # 7. List aliases, unions, and enums
    print("\nType aliases:")
    try:
        aliases = client.list_type_aliases(limit=10)
        for a in aliases.aliases:
            print(f"  {a.name}")
        if not aliases.aliases:
            print("  (none)")
    except ghidra.GhidraError as e:
        print(f"  list_type_aliases failed: {e}", file=sys.stderr)

    print("\nType unions:")
    try:
        unions = client.list_type_unions(limit=10)
        for u in unions.unions:
            print(f"  {u.name}")
        if not unions.unions:
            print("  (none)")
    except ghidra.GhidraError as e:
        print(f"  list_type_unions failed: {e}", file=sys.stderr)

    print("\nType enums:")
    try:
        enums = client.list_type_enums(limit=10)
        for en in enums.enums:
            print(f"  {en.name}")
        if not enums.enums:
            print("  (none)")
    except ghidra.GhidraError as e:
        print(f"  list_type_enums failed: {e}", file=sys.stderr)

    # 8. Clean up -- delete all created types (reverse order of dependencies)
    print("\nCleaning up...")

    # Delete alias first (depends on struct)
    try:
        client.delete_type_alias(f"/{alias_name}")
        print(f"  Deleted alias '{alias_name}'")
    except ghidra.GhidraError as e:
        print(f"  delete alias failed: {e}", file=sys.stderr)

    # Delete enum
    try:
        client.delete_type_enum(f"/{enum_name}")
        print(f"  Deleted enum '{enum_name}'")
    except ghidra.GhidraError as e:
        print(f"  delete enum failed: {e}", file=sys.stderr)

    # Delete struct (renamed)
    try:
        client.delete_type(f"/{renamed}")
        print(f"  Deleted struct '{renamed}'")
    except ghidra.GhidraError as e:
        print(f"  delete struct failed: {e}", file=sys.stderr)

    print("\nDone.")


if __name__ == "__main__":
    main()
