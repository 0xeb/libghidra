# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Shared output formatting: table, json, csv."""

from __future__ import annotations

import csv
import io
import json
import sys
from typing import Any


def _fmt_value(v: Any) -> str:
    """Format a single value for display."""
    if isinstance(v, int) and not isinstance(v, bool):
        # Heuristic: if it looks like an address (>= 0x1000), format as hex
        if v >= 0x1000:
            return f"0x{v:x}"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if v is None:
        return ""
    return str(v)


def _json_value(v: Any) -> Any:
    """Convert a value for JSON output (addresses as hex strings)."""
    if isinstance(v, int) and not isinstance(v, bool) and v >= 0x1000:
        return f"0x{v:x}"
    if isinstance(v, bytes):
        return v.hex()
    return v


def print_table(records: list[dict], columns: list[str] | None = None) -> None:
    """Print records as a column-aligned table."""
    if not records:
        return
    if columns is None:
        columns = list(records[0].keys())

    # Compute column widths
    rows = [[_fmt_value(r.get(c, "")) for c in columns] for r in records]
    widths = [max(len(c), *(len(row[i]) for row in rows)) for i, c in enumerate(columns)]

    # Header
    header = "  ".join(c.ljust(w) for c, w in zip(columns, widths))
    print(header)
    print("  ".join("-" * w for w in widths))

    # Rows
    for row in rows:
        print("  ".join(val.ljust(w) for val, w in zip(row, widths)))


def print_json(records: list[dict], columns: list[str] | None = None) -> None:
    """Print records as JSON array."""
    if columns is not None:
        records = [{c: _json_value(r.get(c)) for c in columns} for r in records]
    else:
        records = [{k: _json_value(v) for k, v in r.items()} for r in records]
    json.dump(records, sys.stdout, indent=2)
    print()


def print_csv(records: list[dict], columns: list[str] | None = None) -> None:
    """Print records as CSV."""
    if not records:
        return
    if columns is None:
        columns = list(records[0].keys())
    writer = csv.writer(sys.stdout)
    writer.writerow(columns)
    for r in records:
        writer.writerow([_fmt_value(r.get(c, "")) for c in columns])


def print_records(records: list[dict], fmt: str, columns: list[str] | None = None) -> None:
    """Print records in the specified format."""
    if fmt == "json":
        print_json(records, columns)
    elif fmt == "csv":
        print_csv(records, columns)
    else:
        print_table(records, columns)


def print_kv(pairs: list[tuple[str, Any]], fmt: str) -> None:
    """Print key-value pairs."""
    if fmt == "json":
        json.dump({k: _json_value(v) for k, v in pairs}, sys.stdout, indent=2)
        print()
    elif fmt == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(["key", "value"])
        for k, v in pairs:
            writer.writerow([k, _fmt_value(v)])
    else:
        width = max(len(k) for k, _ in pairs) if pairs else 0
        for k, v in pairs:
            print(f"  {k:<{width}}  {_fmt_value(v)}")
