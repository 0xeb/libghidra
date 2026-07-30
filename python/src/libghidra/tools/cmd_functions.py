# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.

"""List and search functions (connected or local)."""

from __future__ import annotations

import argparse
import sys

from ._output import print_records


def register(subparsers: argparse._SubParsersAction) -> None:
    from .cli import common_parser
    p = subparsers.add_parser("functions", help="List functions", parents=[common_parser()])
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", help="LibGhidraHost URL")
    g.add_argument("--local", metavar="BINARY", help="Analyze binary offline (no Ghidra needed)")
    p.add_argument("--arch", default="", help="Architecture hint for --local (e.g. x86:LE:64:default)")
    p.add_argument("--limit", type=int, default=0, help="Maximum number of results (0=all)")
    p.add_argument("--offset", type=int, default=0, help="Skip first N results")
    p.add_argument("--name", default=None, help="Filter by name substring (case-insensitive)")
    p.add_argument(
        "--sort",
        choices=["address", "name", "size"],
        default="address",
        help="Sort order (default: address)",
    )
    p.set_defaults(func=run)


def _get_client(args):
    if args.local:
        from libghidra import local
        client = local(arch=args.arch)
        client.open_program(args.local)
        return client
    else:
        from libghidra import connect
        return connect(args.url)


def run(args: argparse.Namespace) -> int:
    from libghidra import GhidraError

    try:
        client = _get_client(args)
    except (ImportError, GhidraError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        target = args.local or args.url
        print(f"Error: cannot connect to {target}: {e}", file=sys.stderr)
        return 1

    try:
        resp = client.list_functions(limit=args.limit, offset=args.offset)
    except GhidraError as e:
        print(f"Error: list_functions failed: {e}", file=sys.stderr)
        return 1

    funcs = resp.functions

    # Client-side name filter
    if args.name:
        pattern = args.name.lower()
        funcs = [f for f in funcs if pattern in f.name.lower()]

    # Sort
    if args.sort == "name":
        funcs.sort(key=lambda f: f.name.lower())
    elif args.sort == "size":
        funcs.sort(key=lambda f: f.size, reverse=True)

    rows = [
        {
            "address": f.entry_address,
            "name": f.name,
            "size": f.size,
            "params": f.parameter_count,
            "thunk": f.is_thunk,
        }
        for f in funcs
    ]

    if not rows:
        print("No functions found.", file=sys.stderr)
        return 0

    print_records(rows, args.format, ["address", "name", "size", "params", "thunk"])
    print(f"\n{len(rows)} function(s)", file=sys.stderr)
    return 0
