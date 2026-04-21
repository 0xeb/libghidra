#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# struct_builder: Create a struct, add/rename/retype/delete members, clean up.
#
# Usage: python struct_builder.py [host_url]
#
# Demonstrates full CRUD lifecycle for struct types and their members.

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

    struct_name = "/example_config_t"

    # 2. Create a struct type
    print(f"\n--- Creating struct '{struct_name}' ---")
    try:
        resp = client.create_type(struct_name, "struct", 0)
        print(f"Created: updated={resp.updated}")
    except ghidra.GhidraError as e:
        print(f"CreateType failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Add three fields
    print("\n--- Adding members ---")
    fields = [
        ("flags", "int", 4),
        ("status", "short", 2),
        ("name", "char[32]", 32),
    ]
    for field_name, field_type, field_size in fields:
        try:
            resp = client.add_type_member(struct_name, field_name, field_type, field_size)
            print(f"  Added '{field_name}' ({field_type}, {field_size} bytes): updated={resp.updated}")
        except ghidra.GhidraError as e:
            print(f"  AddTypeMember '{field_name}' failed: {e}", file=sys.stderr)

    # 4. List members and show details
    print("\n--- Listing members ---")
    try:
        resp = client.list_type_members(struct_name)
        for m in resp.members:
            print(f"  ordinal={m.ordinal}  offset={m.offset}  type={m.member_type}"
                  f"  size={m.size}  name={m.name}")
    except ghidra.GhidraError as e:
        print(f"ListTypeMembers failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 5. Rename the first member: flags -> config_flags
    print("\n--- Renaming member ordinal=0 to 'config_flags' ---")
    try:
        resp = client.rename_type_member(struct_name, 0, "config_flags")
        print(f"Renamed: updated={resp.updated}")
    except ghidra.GhidraError as e:
        print(f"RenameTypeMember failed: {e}", file=sys.stderr)

    # 6. Retype the second member: short -> ushort
    print("\n--- Retyping member ordinal=1 to 'ushort' ---")
    try:
        resp = client.set_type_member_type(struct_name, 1, "ushort")
        print(f"Retyped: updated={resp.updated}")
    except ghidra.GhidraError as e:
        print(f"SetTypeMemberType failed: {e}", file=sys.stderr)

    # 7. Show updated layout
    print("\n--- Updated layout ---")
    try:
        resp = client.list_type_members(struct_name)
        for m in resp.members:
            print(f"  ordinal={m.ordinal}  offset={m.offset}  type={m.member_type}"
                  f"  size={m.size}  name={m.name}")
    except ghidra.GhidraError as e:
        print(f"ListTypeMembers failed: {e}", file=sys.stderr)

    # 8. Delete the last member (ordinal=2, the name field)
    print("\n--- Deleting member ordinal=2 ---")
    try:
        resp = client.delete_type_member(struct_name, 2)
        print(f"Deleted: deleted={resp.deleted}")
    except ghidra.GhidraError as e:
        print(f"DeleteTypeMember failed: {e}", file=sys.stderr)

    # 9. Final layout
    print("\n--- Final layout ---")
    try:
        resp = client.list_type_members(struct_name)
        for m in resp.members:
            print(f"  ordinal={m.ordinal}  offset={m.offset}  type={m.member_type}"
                  f"  size={m.size}  name={m.name}")
    except ghidra.GhidraError as e:
        print(f"ListTypeMembers failed: {e}", file=sys.stderr)

    # 10. Clean up: delete the struct
    print(f"\n--- Deleting struct '{struct_name}' ---")
    try:
        resp = client.delete_type(struct_name)
        print(f"Deleted: deleted={resp.deleted}")
    except ghidra.GhidraError as e:
        print(f"DeleteType failed: {e}", file=sys.stderr)

    print("\nDone.")


if __name__ == "__main__":
    main()
