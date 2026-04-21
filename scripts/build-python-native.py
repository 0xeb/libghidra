#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Build the libghidra Python native extension (_native.pyd / _native.so).

This compiles the nanobind bindings for the C++ LocalClient and places the
resulting extension module into python/src/libghidra/ so it can be imported.

Usage:
    # 64-bit (default, auto-detect Python)
    python scripts/build-python-native.py

    # 32-bit for pyhiew
    python scripts/build-python-native.py --arch Win32 --python-dir C:/Python312-32

    # Custom Ghidra source
    python scripts/build-python-native.py --ghidra-source ../ghidra

    # Linux / macOS (auto-detects generator)
    python scripts/build-python-native.py --ghidra-source /path/to/ghidra
"""

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path


def detect_generator() -> list[str]:
    """Return CMake generator flags for the current platform."""
    if sys.platform == "win32":
        return ["-G", "Visual Studio 17 2022"]
    # Linux/macOS: let CMake pick (Makefiles or Ninja)
    return []


def build_dir_suffix(arch: str | None) -> str:
    """Return a build directory suffix based on target arch."""
    if arch and arch.lower() == "win32":
        return "-x86"
    return ""


def main():
    parser = argparse.ArgumentParser(description="Build libghidra Python native extension")
    parser.add_argument(
        "--ghidra-source",
        default=None,
        help="Path to Ghidra source tree (default: auto-detect ../ghidra)",
    )
    parser.add_argument(
        "--arch",
        default=None,
        help="Target architecture: Win32, x64 (Windows only; Linux/Mac use host arch)",
    )
    parser.add_argument(
        "--python-dir",
        default=None,
        help="Python root directory (e.g., C:/Python312-32 for 32-bit)",
    )
    parser.add_argument(
        "--build-dir",
        default=None,
        help="Build directory (default: cpp/build-python[-x86])",
    )
    parser.add_argument(
        "--config",
        default="Release",
        choices=["Debug", "Release", "RelWithDebInfo"],
        help="Build configuration (default: Release)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove build directory before building",
    )
    args = parser.parse_args()

    # Resolve paths
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    cpp_dir = repo_root / "cpp"

    if args.ghidra_source:
        ghidra_source = Path(args.ghidra_source).resolve()
    else:
        ghidra_source = repo_root.parent / "ghidra"
        if not ghidra_source.exists():
            print(f"Error: cannot find Ghidra source at {ghidra_source}", file=sys.stderr)
            print("Specify with --ghidra-source", file=sys.stderr)
            sys.exit(1)

    suffix = build_dir_suffix(args.arch)
    build_dir = Path(args.build_dir) if args.build_dir else cpp_dir / f"build-python{suffix}"

    if args.clean and build_dir.exists():
        import shutil
        shutil.rmtree(build_dir)

    # Configure
    cmake_args = [
        "cmake",
        "-S", str(cpp_dir),
        "-B", str(build_dir),
        *detect_generator(),
        "-DLIBGHIDRA_WITH_LOCAL=ON",
        "-DLIBGHIDRA_BUILD_PYTHON=ON",
        f"-DGHIDRA_SOURCE_DIR={ghidra_source}",
    ]

    # Note: nanobind requires dynamic CRT (/MD), do NOT set static /MT here

    # Architecture (Windows multi-arch via -A flag)
    if args.arch and sys.platform == "win32":
        cmake_args.extend(["-A", args.arch])

    # Python directory override — set ROOT_DIR and EXECUTABLE for both
    # FindPython (nanobind) and FindPython3 (legacy) module names
    if args.python_dir:
        python_dir = Path(args.python_dir).resolve()
        py_exe = python_dir / ("python.exe" if sys.platform == "win32" else "python3")
        cmake_args.append(f"-DPython_ROOT_DIR={python_dir}")
        cmake_args.append(f"-DPython3_ROOT_DIR={python_dir}")
        if py_exe.exists():
            cmake_args.append(f"-DPython_EXECUTABLE={py_exe}")
            cmake_args.append(f"-DPython3_EXECUTABLE={py_exe}")
            cmake_args.append(f"-DPYTHON_EXECUTABLE={py_exe}")

    print(f"Configuring: {' '.join(cmake_args)}")
    result = subprocess.run(cmake_args)
    if result.returncode != 0:
        print("CMake configure failed", file=sys.stderr)
        sys.exit(1)

    # Build
    build_args = [
        "cmake",
        "--build", str(build_dir),
        "--config", args.config,
        "--target", "_libghidra",
    ]

    print(f"\nBuilding: {' '.join(build_args)}")
    result = subprocess.run(build_args)
    if result.returncode != 0:
        print("Build failed", file=sys.stderr)
        sys.exit(1)

    # Verify output
    pkg_dir = repo_root / "python" / "src" / "libghidra"
    ext = ".pyd" if sys.platform == "win32" else ".so"
    candidates = sorted(pkg_dir.glob(f"_libghidra*{ext}"), key=lambda p: p.stat().st_mtime, reverse=True)

    if candidates:
        built = candidates[0]
        size_mb = built.stat().st_size / (1024 * 1024)
        print(f"\nSuccess: {built.name} ({size_mb:.1f} MB)")

        # Show test command using the matching Python
        if args.python_dir:
            py = Path(args.python_dir) / ("python.exe" if sys.platform == "win32" else "python3")
        else:
            py = "python"
        print(f"\nTest with:\n  {py} -c \"from libghidra._native import create_local_client; print('OK')\"")
    else:
        print(f"\nWarning: no _native*{ext} found in {pkg_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
