# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.

"""Decompile functions (connected or local)."""

from __future__ import annotations

import argparse
import os
import sys

from ._output import print_records


def register(subparsers: argparse._SubParsersAction) -> None:
    from .cli import common_parser
    p = subparsers.add_parser("decompile", help="Decompile one or all functions", parents=[common_parser()])
    p.add_argument("target", nargs="?", default=None, help="Address (hex) or function name")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", help="LibGhidraHost URL")
    g.add_argument("--local", metavar="BINARY", help="Analyze binary offline (no Ghidra needed)")
    p.add_argument("--arch", default="", help="Architecture hint for --local (e.g. x86:LE:64:default)")
    p.add_argument("--all", action="store_true", dest="decompile_all", help="Decompile all functions")
    p.add_argument("--output-dir", "-o", default=None, help="Write .c files to this directory (with --all)")
    p.add_argument("--timeout", type=int, default=30000, help="Decompile timeout in ms (default: 30000)")
    p.add_argument("--limit", type=int, default=0, help="Max functions to decompile with --all (0=all)")
    p.add_argument(
        "--require-exact",
        action="store_true",
        help="Fail instead of accepting incomplete or synthetic fallback pseudocode",
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


def _parse_address(target: str) -> int | None:
    """Try to parse target as a hex address."""
    try:
        return int(target, 16)
    except ValueError:
        if target.startswith("0x") or target.startswith("0X"):
            try:
                return int(target, 16)
            except ValueError:
                pass
    return None


def _resolve_function(client, name: str) -> int | None:
    """Find a function by name, return its entry address."""
    resp = client.list_functions()
    for f in resp.functions:
        if f.name == name or f.name.lower() == name.lower():
            return f.entry_address
    return None


def _decompilation_status(dec) -> str:
    if dec.completed and not dec.is_fallback:
        return "ok"
    if dec.is_fallback:
        return "fallback"
    return "incomplete"


def _decompile_single(
    client, target: str, timeout_ms: int, fmt: str, require_exact: bool = False
) -> int:
    from libghidra import GhidraError

    addr = _parse_address(target)
    if addr is None:
        addr = _resolve_function(client, target)
        if addr is None:
            print(f"Error: cannot resolve '{target}' as address or function name", file=sys.stderr)
            return 1

    try:
        resp = client.get_decompilation(addr, timeout_ms=timeout_ms)
    except GhidraError as e:
        print(f"Error: decompilation at 0x{addr:x} failed: {e}", file=sys.stderr)
        return 1

    dec = resp.decompilation
    status = _decompilation_status(dec)
    exact = status == "ok"

    if fmt == "json":
        import json
        obj = {
            "address": f"0x{dec.function_entry_address:x}",
            "name": dec.function_name,
            "prototype": dec.prototype,
            "pseudocode": dec.pseudocode,
            "completed": dec.completed,
            "is_fallback": dec.is_fallback,
            "status": status,
        }
        if dec.error_message:
            obj["error"] = dec.error_message
        json.dump(obj, sys.stdout, indent=2)
        print()
    elif exact or not require_exact:
        if dec.prototype:
            print(f"// {dec.function_name} @ 0x{dec.function_entry_address:x}")
            print(f"// {dec.prototype}")
            print()
        if dec.pseudocode:
            print(dec.pseudocode)
        elif dec.error_message:
            print(f"// Decompilation error: {dec.error_message}", file=sys.stderr)
    else:
        reason = dec.error_message or "native decompilation did not complete exactly"
        print(f"Error: decompilation at 0x{addr:x} is {status}: {reason}", file=sys.stderr)

    return 0 if exact or not require_exact else 1


def _decompile_all(
    client,
    timeout_ms: int,
    output_dir: str | None,
    fmt: str,
    limit: int,
    require_exact: bool = False,
) -> int:
    from libghidra import GhidraError

    try:
        resp = client.list_functions(limit=limit)
    except GhidraError as e:
        print(f"Error: list_functions failed: {e}", file=sys.stderr)
        return 1

    funcs = resp.functions
    if not funcs:
        print("No functions found.", file=sys.stderr)
        return 0

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    succeeded = 0
    non_exact = 0
    failed = 0
    results = []

    for i, f in enumerate(funcs):
        print(f"\r[{i+1}/{len(funcs)}] {f.name}...", end="", file=sys.stderr, flush=True)
        try:
            dec_resp = client.get_decompilation(f.entry_address, timeout_ms=timeout_ms)
            dec = dec_resp.decompilation
            status = _decompilation_status(dec)
            exact = status == "ok"
            accepted = exact or (not require_exact and bool(dec.pseudocode))
            if accepted:
                if exact:
                    succeeded += 1
                else:
                    non_exact += 1
                if output_dir:
                    safe_name = f.name.replace("/", "_").replace("\\", "_").replace(":", "_")
                    filepath = os.path.join(output_dir, f"{safe_name}_0x{f.entry_address:x}.c")
                    with open(filepath, "w", encoding="utf-8") as out:
                        if dec.prototype:
                            out.write(f"// {dec.prototype}\n\n")
                        out.write(dec.pseudocode)
                        out.write("\n")
                if fmt == "json":
                    results.append({
                        "address": f"0x{f.entry_address:x}",
                        "name": f.name,
                        "lines": dec.pseudocode.count("\n") + 1,
                        "status": status,
                        "completed": dec.completed,
                        "is_fallback": dec.is_fallback,
                    })
            else:
                failed += 1
                if fmt == "json":
                    results.append({
                        "address": f"0x{f.entry_address:x}",
                        "name": f.name,
                        "status": status if dec.pseudocode else "empty",
                        "completed": dec.completed,
                        "is_fallback": dec.is_fallback,
                        "error": dec.error_message or "",
                    })
        except GhidraError as e:
            failed += 1
            if fmt == "json":
                results.append({
                    "address": f"0x{f.entry_address:x}",
                    "name": f.name,
                    "status": "error",
                    "error": str(e),
                })

    print(file=sys.stderr)  # clear progress line

    if fmt == "json":
        import json
        json.dump(results, sys.stdout, indent=2)
        print()
    else:
        print(
            f"\nExact {succeeded}/{len(funcs)} functions "
            f"({non_exact} non-exact accepted, {failed} failed)",
            file=sys.stderr,
        )
        if output_dir:
            print(f"Output written to: {output_dir}", file=sys.stderr)

    return 1 if require_exact and failed else 0


def run(args: argparse.Namespace) -> int:
    from libghidra import GhidraError

    if not args.decompile_all and not args.target:
        print("Error: provide a target address/name, or use --all", file=sys.stderr)
        return 1

    try:
        client = _get_client(args)
    except (ImportError, GhidraError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        target = args.local or args.url
        print(f"Error: cannot connect to {target}: {e}", file=sys.stderr)
        return 1

    if args.decompile_all:
        return _decompile_all(
            client,
            args.timeout,
            args.output_dir,
            args.format,
            args.limit,
            args.require_exact,
        )
    else:
        return _decompile_single(
            client, args.target, args.timeout, args.format, args.require_exact
        )
