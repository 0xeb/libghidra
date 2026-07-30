#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# project_files: launch a managed headless host, list project programs, then
# switch the active program with close/open.
#
# Usage:
#   python project_files.py <ghidra_dir> <project_dir> <project_name> <binary> [binary...]

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

    opts = ghidra.HeadlessProjectOptions(
        ghidra_dir=args.ghidra_dir,
        project_dir=args.project_dir,
        project_name=args.project_name,
        port=0,
        shutdown="save",
    )

    with ghidra.launch_headless_project(opts) as host:
        for binary in args.binaries:
            host.import_program(ghidra.ImportProgramRequest(
                source_path=binary,
                overwrite=True,
                analyze=True,
            ))
        listing = host.list_project_files(
            ghidra.ListProjectFilesRequest(include_folders=True)
        )
        programs = [f for f in listing.files if f.is_program]
        for item in listing.files:
            kind = "program" if item.is_program else "folder" if item.is_folder else "file"
            print(f"{kind:7} {item.path}")

        if len(programs) < 2:
            return 0

        host.close_program(ghidra.ShutdownPolicy.SAVE)
        opened = host.open_program(
            ghidra.OpenProgramRequest(
                project_path=args.project_dir,
                project_name=args.project_name,
                program_path=programs[1].path,
            )
        )
        print(f"active  {programs[1].path} -> {opened.program_name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
