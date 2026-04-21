#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# comments: Comment CRUD -- set, get, and delete comments on a function entry.
#
# Usage: python comments.py [host_url]
#
# Defaults: http://127.0.0.1:18080, expects a program already open in Ghidra.

import sys

import libghidra as ghidra


ALL_KINDS = [
    ghidra.CommentKind.EOL,
    ghidra.CommentKind.PRE,
    ghidra.CommentKind.POST,
    ghidra.CommentKind.PLATE,
    ghidra.CommentKind.REPEATABLE,
]


def main() -> None:
    url = sys.argv[1] if len(sys.argv) >= 2 else "http://127.0.0.1:18080"
    client = ghidra.connect(url)

    # 1. Find a function to annotate
    try:
        func_resp = client.list_functions(limit=5)
    except ghidra.GhidraError as e:
        print(f"list_functions failed: {e}", file=sys.stderr)
        sys.exit(1)

    if not func_resp.functions:
        print("No functions found -- is a program open?", file=sys.stderr)
        sys.exit(1)

    target = func_resp.functions[0]
    addr = target.entry_address
    print(f"Target: {target.name} at 0x{addr:08x}")

    # 2. Set all five comment kinds at the entry point
    labels = {
        ghidra.CommentKind.EOL: "End-of-line comment (example)",
        ghidra.CommentKind.PRE: "Pre-comment: context before instruction",
        ghidra.CommentKind.POST: "Post-comment: notes after instruction",
        ghidra.CommentKind.PLATE: "===== Plate comment: function header =====",
        ghidra.CommentKind.REPEATABLE: "Repeatable: shows at referencing sites",
    }

    print(f"\nSetting {len(labels)} comments at 0x{addr:08x}...")
    for kind, text in labels.items():
        try:
            resp = client.set_comment(addr, kind, text)
            print(f"  {kind.name:<12}  updated={resp.updated}")
        except ghidra.GhidraError as e:
            print(f"  {kind.name:<12}  FAILED: {e}", file=sys.stderr)

    # 3. Retrieve comments and verify all kinds are present
    try:
        get_resp = client.get_comments(range_start=addr, range_end=addr + 1)
    except ghidra.GhidraError as e:
        print(f"get_comments failed: {e}", file=sys.stderr)
        sys.exit(1)

    comments = get_resp.comments
    print(f"\nRetrieved {len(comments)} comments at 0x{addr:08x}:")
    found_kinds = set()
    for c in comments:
        found_kinds.add(c.kind)
        preview = c.text[:60] + "..." if len(c.text) > 60 else c.text
        print(f"  0x{c.address:08x}  {c.kind:<12}  {preview}")

    missing = set(ALL_KINDS) - found_kinds
    if missing:
        print(f"  WARNING: missing kinds: {[k.name for k in missing]}")
    else:
        print("  All 5 comment kinds present.")

    # 4. Delete the POST comment and verify removal
    print(f"\nDeleting POST comment at 0x{addr:08x}...")
    try:
        del_resp = client.delete_comment(addr, ghidra.CommentKind.POST)
        print(f"  deleted={del_resp.deleted}")
    except ghidra.GhidraError as e:
        print(f"  delete_comment failed: {e}", file=sys.stderr)

    after = client.get_comments(range_start=addr, range_end=addr + 1)
    after_kinds = {c.kind for c in after.comments}
    if ghidra.CommentKind.POST not in after_kinds:
        print("  Verified: POST comment removed.")
    else:
        print("  WARNING: POST comment still present.")

    print(f"  Remaining: {len(after.comments)} comments")

    # 5. Clean up -- delete the remaining comments
    print("\nCleaning up remaining comments...")
    for kind in ALL_KINDS:
        if kind == ghidra.CommentKind.POST:
            continue
        try:
            client.delete_comment(addr, kind)
        except ghidra.GhidraError:
            pass

    final = client.get_comments(range_start=addr, range_end=addr + 1)
    print(f"  Final comment count at 0x{addr:08x}: {len(final.comments)}")

    print("\nDone.")


if __name__ == "__main__":
    main()
