# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.

"""Main CLI entry point for the libghidra swiss-army-knife."""

from __future__ import annotations

import argparse
import sys
import traceback

from . import cmd_info, cmd_strings, cmd_disasm, cmd_status, cmd_functions, cmd_decompile

# Shared parent parser so --format / --debug work both before and after COMMAND.
#
# These options MUST NOT carry a default here. This parser is a parent of both
# the top-level parser and every subparser, and argparse applies a subparser's
# defaults to the namespace *after* the parent has parsed. A default set here is
# therefore re-applied by the subparser and silently overwrites the value the
# user passed before COMMAND -- `libghidra --format json info` came out as
# table. SUPPRESS leaves the attribute absent unless the user actually supplied
# it, so whichever position it appears in survives; the real defaults are
# applied once in main() via _apply_common_defaults.
_COMMON_DEFAULTS = {"format": "table", "debug": False}

_common = argparse.ArgumentParser(add_help=False)
_common.add_argument(
    "--format", "-f",
    choices=["table", "json", "csv"],
    default=argparse.SUPPRESS,
    help="Output format (default: table)",
)
_common.add_argument(
    "--debug",
    action="store_true",
    default=argparse.SUPPRESS,
    help="Show full tracebacks on error",
)


def _apply_common_defaults(args: argparse.Namespace) -> None:
    """Fill in shared-option defaults that SUPPRESS deliberately left unset."""
    for name, value in _COMMON_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, value)


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
    _apply_common_defaults(args)

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
