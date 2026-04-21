# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Connected command: health check and capability listing."""

from __future__ import annotations

import argparse
import sys

from ._output import print_kv, print_records


def register(subparsers: argparse._SubParsersAction) -> None:
    from .cli import common_parser
    p = subparsers.add_parser("status", help="Check host health and capabilities", parents=[common_parser()])
    p.add_argument("--url", required=True, help="LibGhidraHost URL (e.g. http://127.0.0.1:18080)")
    p.set_defaults(func=run)


def _get_client(url: str):
    from libghidra import connect, GhidraError
    try:
        client = connect(url)
        return client
    except Exception as e:
        print(f"Error: cannot reach host at {url}: {e}", file=sys.stderr)
        sys.exit(1)


def run(args: argparse.Namespace) -> int:
    from libghidra import GhidraError

    client = _get_client(args.url)

    try:
        status = client.get_status()
    except GhidraError as e:
        print(f"Error: get_status failed: {e}", file=sys.stderr)
        return 1

    info = [
        ("OK", status.ok),
        ("Service", status.service_name),
        ("Version", status.service_version),
        ("Host Mode", status.host_mode),
        ("Revision", status.program_revision),
    ]
    if status.warnings:
        for i, w in enumerate(status.warnings):
            info.append((f"Warning[{i}]", w))

    print_kv(info, args.format)

    try:
        caps = client.get_capabilities()
    except GhidraError:
        return 0

    if caps:
        print()
        rows = [{"id": c.id, "status": c.status, "note": c.note or ""} for c in caps]
        print_records(rows, args.format, ["id", "status", "note"])

    return 0
