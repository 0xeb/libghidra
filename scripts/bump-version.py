#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Bump the libghidra version across all build systems.

The repo-root VERSION file is the canonical version source.
Python packaging bundles python/VERSION for sdist/wheel builds, CMake reads
the repo-root version directly, and Rust Cargo.toml is patched by this script.

Usage:
    python scripts/bump-version.py 0.1.0       # set explicit version
    python scripts/bump-version.py --patch      # 0.0.1 -> 0.0.2
    python scripts/bump-version.py --minor      # 0.0.1 -> 0.1.0
    python scripts/bump-version.py --major      # 0.0.1 -> 1.0.0
    python scripts/bump-version.py --show       # print current version
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path


def read_version(version_file: Path) -> str:
    return version_file.read_text().strip()


def bump(current: str, part: str) -> str:
    parts = [int(x) for x in current.split(".")]
    while len(parts) < 3:
        parts.append(0)
    if part == "major":
        parts[0] += 1
        parts[1] = 0
        parts[2] = 0
    elif part == "minor":
        parts[1] += 1
        parts[2] = 0
    elif part == "patch":
        parts[2] += 1
    return ".".join(str(p) for p in parts)


def update_cargo_toml(cargo_path: Path, new_version: str) -> None:
    text = cargo_path.read_text()
    text = re.sub(
        r'^(version\s*=\s*)"[^"]+"',
        f'\\1"{new_version}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    cargo_path.write_text(text)


def main():
    parser = argparse.ArgumentParser(description="Bump libghidra version")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("version", nargs="?", default=None, help="Explicit version (e.g., 0.1.0)")
    group.add_argument("--patch", action="store_true", help="Bump patch: x.y.Z+1")
    group.add_argument("--minor", action="store_true", help="Bump minor: x.Y+1.0")
    group.add_argument("--major", action="store_true", help="Bump major: X+1.0.0")
    group.add_argument("--show", action="store_true", help="Show current version and exit")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    version_file = repo_root / "VERSION"
    python_version_file = repo_root / "python" / "VERSION"
    cargo_toml = repo_root / "rust" / "Cargo.toml"

    current = read_version(version_file)

    if args.show:
        print(current)
        return

    # Determine new version
    if args.version:
        new_version = args.version
    elif args.patch:
        new_version = bump(current, "patch")
    elif args.minor:
        new_version = bump(current, "minor")
    elif args.major:
        new_version = bump(current, "major")

    # Validate format
    if not re.match(r"^\d+\.\d+\.\d+$", new_version):
        print(f"Error: invalid version format: {new_version}", file=sys.stderr)
        sys.exit(1)

    if new_version == current:
        print(f"Version is already {current}")
        return

    print(f"Bumping: {current} -> {new_version}")

    # 1. Update the canonical repo-root version file
    version_file.write_text(new_version + "\n")
    print(f"  Updated: VERSION")

    # 2. Keep the packaged Python VERSION file in sync for sdist/wheel builds
    python_version_file.write_text(new_version + "\n")
    print(f"  Updated: python/VERSION")

    # 3. Update Cargo.toml (Rust can't read external files)
    if cargo_toml.exists():
        update_cargo_toml(cargo_toml, new_version)
        print(f"  Updated: rust/Cargo.toml")

        # Update Cargo.lock
        cargo_lock = repo_root / "rust" / "Cargo.lock"
        if cargo_lock.exists():
            subprocess.run(
                ["cargo", "generate-lockfile"],
                cwd=repo_root / "rust",
                capture_output=True,
            )
            print(f"  Updated: rust/Cargo.lock")

    print(f"\nVersion is now {new_version}")
    print(f"  Python packaging reads from python/VERSION (kept in sync here)")
    print(f"  CMake (CMakeLists.txt) reads from VERSION automatically")
    print(f"  Rust (Cargo.toml) was patched by this script")


if __name__ == "__main__":
    main()
