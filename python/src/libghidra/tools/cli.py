# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Main CLI entry point for the libghidra swiss-army-knife."""

from __future__ import annotations

import argparse
import sys
import traceback

from . import cmd_info, cmd_strings, cmd_disasm, cmd_status, cmd_functions, cmd_decompile

# Shared parent parser so --format / --debug work both before and after COMMAND
_common = argparse.ArgumentParser(add_help=False)
_common.add_argument(
    "--format", "-f",
    choices=["table", "json", "csv"],
    default="table",
    help="Output format (default: table)",
)
_common.add_argument(
    "--debug",
    action="store_true",
    help="Show full tracebacks on error",
)


def common_parser() -> argparse.ArgumentParser:
    """Return the shared parent parser for subcommands."""
    return _common


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="libghidra",
        description="Swiss-army-knife CLI for reverse engineering with libghidra.",
        parents=[_common],
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # Register all subcommands
    cmd_info.register(sub)
    cmd_strings.register(sub)
    cmd_disasm.register(sub)
    cmd_status.register(sub)
    cmd_functions.register(sub)
    cmd_decompile.register(sub)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    try:
        rc = args.func(args)
        sys.exit(rc or 0)
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:
        if args.debug:
            traceback.print_exc()
        else:
            print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
