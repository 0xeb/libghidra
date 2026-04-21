# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Offline string extraction from binary files."""

from __future__ import annotations

import argparse
import os
import sys

from ._output import print_records


def register(subparsers: argparse._SubParsersAction) -> None:
    from .cli import common_parser
    p = subparsers.add_parser("strings", help="Extract strings from a binary", parents=[common_parser()])
    p.add_argument("binary", help="Path to binary file")
    p.add_argument("--min-length", "-n", type=int, default=4, help="Minimum string length (default: 4)")
    p.add_argument(
        "--encoding", "-e",
        choices=["ascii", "utf16", "both"],
        default="both",
        help="Encoding to scan for (default: both)",
    )
    p.set_defaults(func=run)


def _extract_ascii(data: bytes, min_len: int) -> list[dict]:
    results = []
    start = None
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7f:
            if start is None:
                start = i
        else:
            if start is not None and (i - start) >= min_len:
                results.append({
                    "offset": start,
                    "encoding": "ascii",
                    "length": i - start,
                    "value": data[start:i].decode("ascii"),
                })
            start = None
    if start is not None and (len(data) - start) >= min_len:
        results.append({
            "offset": start,
            "encoding": "ascii",
            "length": len(data) - start,
            "value": data[start:].decode("ascii"),
        })
    return results


def _extract_utf16(data: bytes, min_len: int) -> list[dict]:
    results = []
    start = None
    i = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 0x20 <= lo < 0x7f:
            if start is None:
                start = i
            i += 2
        else:
            if start is not None:
                char_count = (i - start) // 2
                if char_count >= min_len:
                    value = data[start:i].decode("utf-16-le", errors="replace")
                    results.append({
                        "offset": start,
                        "encoding": "utf-16",
                        "length": char_count,
                        "value": value,
                    })
            start = None
            i += 2
    if start is not None:
        char_count = (i - start) // 2
        if char_count >= min_len:
            value = data[start:i].decode("utf-16-le", errors="replace")
            results.append({
                "offset": start,
                "encoding": "utf-16",
                "length": char_count,
                "value": value,
            })
    return results


def run(args: argparse.Namespace) -> int:
    path = args.binary
    if not os.path.isfile(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    with open(path, "rb") as f:
        data = f.read()

    results: list[dict] = []
    if args.encoding in ("ascii", "both"):
        results.extend(_extract_ascii(data, args.min_length))
    if args.encoding in ("utf16", "both"):
        results.extend(_extract_utf16(data, args.min_length))

    results.sort(key=lambda r: r["offset"])

    # Truncate long values for table display
    if args.format == "table":
        for r in results:
            if len(r["value"]) > 80:
                r["value"] = r["value"][:77] + "..."

    print_records(results, args.format, ["offset", "encoding", "length", "value"])
    return 0
