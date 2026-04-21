#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# enum_builder: Create an enum, add/rename/retype/delete members, clean up.
#
# Usage: python enum_builder.py [host_url]
#
# Demonstrates full CRUD lifecycle for enum types and their members.

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

    enum_name = "/example_status_e"

    # 2. Create a 4-byte unsigned enum
    print(f"\n--- Creating enum '{enum_name}' (4 bytes, unsigned) ---")
    try:
        resp = client.create_type_enum(enum_name, 4, is_signed=False)
        print(f"Created: updated={resp.updated}")
    except ghidra.GhidraError as e:
        print(f"CreateTypeEnum failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Add four members
    print("\n--- Adding enum members ---")
    entries = [
        ("OK", 0),
        ("ERROR", 1),
        ("TIMEOUT", 2),
        ("BUSY", 3),
    ]
    for name, value in entries:
        try:
            resp = client.add_type_enum_member(enum_name, name, value)
            print(f"  Added {name}={value}: updated={resp.updated}")
        except ghidra.GhidraError as e:
            print(f"  AddTypeEnumMember '{name}' failed: {e}", file=sys.stderr)

    # 4. List members and show details
    print("\n--- Listing enum members ---")
    try:
        resp = client.list_type_enum_members(enum_name)
        for m in resp.members:
            print(f"  ordinal={m.ordinal}  name={m.name}  value={m.value}")
    except ghidra.GhidraError as e:
        print(f"ListTypeEnumMembers failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 5. Rename ERROR -> FAILURE
    print("\n--- Renaming ordinal=1 from 'ERROR' to 'FAILURE' ---")
    try:
        resp = client.rename_type_enum_member(enum_name, 1, "FAILURE")
        print(f"Renamed: updated={resp.updated}")
    except ghidra.GhidraError as e:
        print(f"RenameTypeEnumMember failed: {e}", file=sys.stderr)

    # 6. Change TIMEOUT value from 2 to 255
    print("\n--- Changing ordinal=2 value to 255 ---")
    try:
        resp = client.set_type_enum_member_value(enum_name, 2, 255)
        print(f"Updated value: updated={resp.updated}")
    except ghidra.GhidraError as e:
        print(f"SetTypeEnumMemberValue failed: {e}", file=sys.stderr)

    # 7. Show updated members
    print("\n--- Updated enum members ---")
    try:
        resp = client.list_type_enum_members(enum_name)
        for m in resp.members:
            print(f"  ordinal={m.ordinal}  name={m.name}  value={m.value}")
    except ghidra.GhidraError as e:
        print(f"ListTypeEnumMembers failed: {e}", file=sys.stderr)

    # 8. Delete the BUSY member (ordinal=3)
    print("\n--- Deleting ordinal=3 (BUSY) ---")
    try:
        resp = client.delete_type_enum_member(enum_name, 3)
        print(f"Deleted: deleted={resp.deleted}")
    except ghidra.GhidraError as e:
        print(f"DeleteTypeEnumMember failed: {e}", file=sys.stderr)

    # 9. Final state
    print("\n--- Final enum members ---")
    try:
        resp = client.list_type_enum_members(enum_name)
        for m in resp.members:
            print(f"  ordinal={m.ordinal}  name={m.name}  value={m.value}")
    except ghidra.GhidraError as e:
        print(f"ListTypeEnumMembers failed: {e}", file=sys.stderr)

    # 10. Clean up: delete the enum
    print(f"\n--- Deleting enum '{enum_name}' ---")
    try:
        resp = client.delete_type_enum(enum_name)
        print(f"Deleted: deleted={resp.deleted}")
    except ghidra.GhidraError as e:
        print(f"DeleteTypeEnum failed: {e}", file=sys.stderr)

    print("\nDone.")


if __name__ == "__main__":
    main()
