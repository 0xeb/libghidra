#!/usr/bin/env python3
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""
Regenerate all protobuf stubs from proto source files.

Regenerates C++, Java, Rust, and Python stubs from the proto contracts in
libghidra/proto/libghidra/. Generated files go into language-specific
`generated/` directories; hand-written source code is never touched.

Usage:
    python regen.py --protoc /path/to/protoc --wkt-include /path/to/protobuf/src
    python regen.py --protoc /path/to/protoc --languages cpp java rust python
    python regen.py --protoc /path/to/protoc --languages rust

Requires:
    - protoc binary (pass via --protoc or set PROTOC env var)
    - WKT include path (pass via --wkt-include or set PROTOC_INCLUDE env var)
      This is the directory containing google/protobuf/any.proto etc.
    - For Rust: cargo (prost-build codegen crate)
    - For Python: protoc with built-in python_out (no extra plugin)

Output directories (relative to libghidra/):
    C++:    cpp/generated/libghidra/*.pb.{h,cc}
    Java:   ghidra-extension/src/main/generated/
    Rust:   rust/generated/libghidra.rs
    Python: python/src/libghidra/*_pb2.py
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Resolve libghidra root (two levels up from this script)
SCRIPT_DIR = Path(__file__).resolve().parent
PROTO_ROOT = SCRIPT_DIR.parent  # libghidra/proto
LIBGHIDRA_ROOT = PROTO_ROOT.parent  # libghidra/

PROTO_DIR = PROTO_ROOT / "libghidra"

# Output directories
CPP_OUT = LIBGHIDRA_ROOT / "cpp" / "generated"
JAVA_OUT = (
    LIBGHIDRA_ROOT
    / "ghidra-extension"
    / "src"
    / "main"
    / "generated"
)
RUST_CRATE_DIR = LIBGHIDRA_ROOT / "rust"
RUST_GENERATED = RUST_CRATE_DIR / "generated" / "libghidra.rs"
PYTHON_OUT = LIBGHIDRA_ROOT / "python" / "src"

ALL_LANGUAGES = ["cpp", "java", "rust", "python"]


def find_protoc(args_protoc: str | None) -> Path:
    """Resolve protoc binary from --protoc arg, PROTOC env, or PATH."""
    if args_protoc:
        p = Path(args_protoc)
        if p.is_file():
            return p
        raise FileNotFoundError(f"protoc not found at: {args_protoc}")

    env_protoc = os.environ.get("PROTOC")
    if env_protoc:
        p = Path(env_protoc)
        if p.is_file():
            return p
        raise FileNotFoundError(f"PROTOC env points to missing file: {env_protoc}")

    which = shutil.which("protoc")
    if which:
        return Path(which)

    raise FileNotFoundError(
        "protoc not found. Pass --protoc, set PROTOC env var, or add protoc to PATH."
    )


def find_wkt_include(args_wkt: str | None) -> Path | None:
    """Resolve WKT include directory from --wkt-include arg or PROTOC_INCLUDE env."""
    if args_wkt:
        p = Path(args_wkt)
        if (p / "google" / "protobuf" / "any.proto").is_file():
            return p
        raise FileNotFoundError(
            f"WKT include path invalid (no google/protobuf/any.proto): {args_wkt}"
        )

    env_include = os.environ.get("PROTOC_INCLUDE")
    if env_include:
        p = Path(env_include)
        if (p / "google" / "protobuf" / "any.proto").is_file():
            return p
        raise FileNotFoundError(
            f"PROTOC_INCLUDE env path invalid (no google/protobuf/any.proto): {env_include}"
        )

    return None


def collect_protos() -> list[Path]:
    """Collect all .proto files from the proto directory."""
    protos = sorted(PROTO_DIR.glob("*.proto"))
    if not protos:
        raise FileNotFoundError(f"No .proto files found in {PROTO_DIR}")
    return protos


def regen_cpp(protoc: Path, protos: list[Path], wkt: Path | None) -> None:
    """Regenerate C++ protobuf stubs."""
    print(f"\n[cpp] output: {CPP_OUT}")
    CPP_OUT.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(protoc),
        f"--proto_path={PROTO_ROOT}",
    ]
    if wkt:
        cmd.append(f"--proto_path={wkt}")
    cmd += [f"--cpp_out={CPP_OUT}", *[str(p) for p in protos]]
    print(f"[cpp] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print("[cpp] done")


def regen_java(protoc: Path, protos: list[Path], wkt: Path | None) -> None:
    """Regenerate Java protobuf stubs."""
    print(f"\n[java] output: {JAVA_OUT}")
    JAVA_OUT.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(protoc),
        f"--proto_path={PROTO_ROOT}",
    ]
    if wkt:
        cmd.append(f"--proto_path={wkt}")
    cmd += [f"--java_out={JAVA_OUT}", *[str(p) for p in protos]]
    print(f"[java] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print("[java] done")


def regen_rust(protoc: Path, wkt: Path | None) -> None:
    """Regenerate Rust protobuf stubs via the Rust crate build script."""
    print(f"\n[rust] crate: {RUST_CRATE_DIR}")

    if not RUST_CRATE_DIR.is_dir():
        raise FileNotFoundError(
            f"Rust crate not found at {RUST_CRATE_DIR}. "
            "Expected libghidra/rust/ with a Cargo.toml."
        )

    cargo = shutil.which("cargo")
    if not cargo:
        raise FileNotFoundError("cargo not found in PATH (required for Rust codegen)")

    env = os.environ.copy()
    env["PROTOC"] = str(protoc)
    if wkt:
        env["PROTOC_INCLUDE"] = str(wkt)

    cmd = [cargo, "build"]
    print(f"[rust] PROTOC={protoc} cargo build (in {RUST_CRATE_DIR})")
    subprocess.run(cmd, cwd=str(RUST_CRATE_DIR), env=env, check=True)

    target_build_dir = RUST_CRATE_DIR / "target" / "debug" / "build"
    candidates = sorted(
        target_build_dir.glob("*/out/libghidra.rs"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise FileNotFoundError(
            f"Rust build completed but no generated libghidra.rs found under "
            f"{target_build_dir}"
        )

    RUST_GENERATED.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(candidates[0], RUST_GENERATED)
    print(f"[rust] copied {candidates[0]} -> {RUST_GENERATED}")
    print("[rust] done")


def regen_python(protoc: Path, protos: list[Path], wkt: Path | None) -> None:
    """Regenerate Python protobuf stubs."""
    print(f"\n[python] output: {PYTHON_OUT / 'libghidra'}")
    PYTHON_OUT.mkdir(parents=True, exist_ok=True)

    # Create the Python package root inside src/libghidra.
    libghidra_pkg = PYTHON_OUT / "libghidra"
    libghidra_pkg.mkdir(exist_ok=True)
    (libghidra_pkg / "__init__.py").touch()

    cmd = [
        str(protoc),
        f"--proto_path={PROTO_ROOT}",
    ]
    if wkt:
        cmd.append(f"--proto_path={wkt}")
    cmd += [f"--python_out={PYTHON_OUT}", *[str(p) for p in protos]]
    print(f"[python] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print("[python] done")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Regenerate protobuf stubs for all languages."
    )
    parser.add_argument(
        "--protoc",
        help="Path to protoc binary (or set PROTOC env var)",
    )
    parser.add_argument(
        "--wkt-include",
        help="Path to protobuf WKT include dir containing google/protobuf/*.proto "
        "(or set PROTOC_INCLUDE env var)",
    )
    parser.add_argument(
        "--languages",
        nargs="+",
        choices=ALL_LANGUAGES,
        default=ALL_LANGUAGES,
        help=f"Languages to regenerate (default: all). Choices: {ALL_LANGUAGES}",
    )
    args = parser.parse_args()

    protoc = find_protoc(args.protoc)
    print(f"protoc: {protoc}")

    wkt = find_wkt_include(args.wkt_include)
    if wkt:
        print(f"WKT include: {wkt}")
    else:
        print("WKT include: (not specified, relying on protoc bundled includes)")

    protos = collect_protos()
    print(f"proto files: {len(protos)} in {PROTO_DIR}")
    for p in protos:
        print(f"  {p.name}")

    generators = {
        "cpp": lambda: regen_cpp(protoc, protos, wkt),
        "java": lambda: regen_java(protoc, protos, wkt),
        "rust": lambda: regen_rust(protoc, wkt),
        "python": lambda: regen_python(protoc, protos, wkt),
    }

    failed = []
    for lang in args.languages:
        try:
            generators[lang]()
        except Exception as e:
            print(f"\n[{lang}] FAILED: {e}", file=sys.stderr)
            failed.append(lang)

    print()
    if failed:
        print(f"FAILED: {', '.join(failed)}")
        sys.exit(1)
    else:
        print(f"All done: {', '.join(args.languages)}")


if __name__ == "__main__":
    main()
