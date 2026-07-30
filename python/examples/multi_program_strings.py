#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# multi_program_strings: launch one live Ghidra headless project, import and
# analyze one or more binaries, count defined strings for each active program,
# save the project, and shut down.
#
# Usage:
#   python multi_program_strings.py <ghidra_dir> <project_dir> <project_name> <binary> [binary...]

from __future__ import annotations

import argparse
import sys

import libghidra as ghidra


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ghidra_dir")
    parser.add_argument("project_dir")
    parser.add_argument("project_name")
    parser.add_argument("binaries", nargs="+")
    args = parser.parse_args()

    host: ghidra.HeadlessClient | None = None
    try:
        host = ghidra.launch_headless_project(ghidra.HeadlessProjectOptions(
            ghidra_dir=args.ghidra_dir,
            project_dir=args.project_dir,
            project_name=args.project_name,
            port=0,
            shutdown="save",
            bind_attempts=5,
            startup_timeout=600.0,
            read_timeout=300.0,
        ))

        for binary in args.binaries:
            imported = host.import_program(ghidra.ImportProgramRequest(
                source_path=binary,
                overwrite=True,
                analyze=True,
            ))
            program_path = imported.primary_program_path
            if not program_path:
                print(f"ImportProgram returned no primary program path for {binary}", file=sys.stderr)
                return 1

            print(f"imported  {program_path}  source={binary}")

            opened = host.open_program(ghidra.OpenProgramRequest(
                program_path=program_path,
                analyze=False,
                read_only=False,
            ))
            strings = host.list_defined_strings().strings
            print(
                f"strings   {program_path}  "
                f"program={opened.program_name}  count={len(strings)}"
            )

            closed = host.close_program(ghidra.ShutdownPolicy.SAVE)
            if not closed.closed:
                print(f"CloseProgram did not close {program_path}", file=sys.stderr)
                return 1

        exit_code = host.close(save=True)
        host = None
        if exit_code != 0:
            print(f"Ghidra exited with code {exit_code}", file=sys.stderr)
            return 1

        print(f"saved     project={args.project_name}")
        return 0

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    finally:
        if host is not None:
            host.close(save=True)


if __name__ == "__main__":
    sys.exit(main())
