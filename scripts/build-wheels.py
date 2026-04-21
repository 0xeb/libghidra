#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Build distributable wheels for libghidra with the native extension.

Workflow:
  1. Builds the _native.pyd/.so for the target platform
  2. Creates a wheel containing the native extension
  3. Re-tags the wheel with the correct platform tag

Usage:
    # Build wheel for the current Python (64-bit)
    python scripts/build-wheels.py

    # Build 32-bit wheel for pyhiew
    python scripts/build-wheels.py --arch Win32 --python-dir C:/Python312-32

    # Build both 32-bit and 64-bit
    python scripts/build-wheels.py --all
"""

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path


def run(cmd: list[str], desc: str, **kwargs) -> subprocess.CompletedProcess:
    print(f"\n--- {desc}")
    print(f"    {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        print(f"FAILED: {desc}", file=sys.stderr)
        sys.exit(1)
    return result


def get_python_tag(py: Path) -> tuple[str, str]:
    """Get the cpXXX and platform tag from a Python interpreter."""
    script = (
        "import sys, struct, platform as P; "
        "bits = struct.calcsize('P') * 8; "
        "v = f'cp{sys.version_info.major}{sys.version_info.minor}'; "
        "plat = 'win32' if bits == 32 and sys.platform == 'win32' "
        "else 'win_amd64' if bits == 64 and sys.platform == 'win32' "
        "else f'linux_{P.machine()}' if sys.platform == 'linux' "
        "else f'macosx_{\"_\".join(P.mac_ver()[0].split(\".\")[:2])}_{P.machine()}' "
        "if sys.platform == 'darwin' else 'unknown'; "
        "print(f'{v} {plat}')"
    )
    result = subprocess.run([str(py), "-c", script], capture_output=True, text=True)
    parts = result.stdout.strip().split()
    return parts[0], parts[1]  # e.g. ("cp312", "win32")


def retag_wheel(wheel_path: Path, py_tag: str, platform_tag: str) -> Path:
    """Rename a py3-none-any wheel to a platform-specific wheel.

    Also fixes the WHEEL metadata and strips .pyd/.so files that don't
    match the target platform (prevents cross-contamination).
    """
    # Use abi3 tag for stable ABI wheels (works with any Python >= py_tag)
    new_name = f"libghidra-{_get_version(wheel_path)}-{py_tag}-abi3-{platform_tag}.whl"
    new_path = wheel_path.parent / new_name

    # Determine which .pyd files to keep.
    # Stable ABI produces "_libghidra.pyd" (no platform tag).
    # Version-specific produces "_libghidra.cp312-win32.pyd" etc.
    # Keep: files matching our platform OR stable ABI (no tag).
    keep_platform = platform_tag  # e.g., "win32" or "win_amd64"

    tmp_path = wheel_path.with_suffix(".tmp.whl")
    with zipfile.ZipFile(wheel_path, "r") as zin, zipfile.ZipFile(tmp_path, "w") as zout:
        for item in zin.infolist():
            if item.filename.endswith((".pyd", ".so")) and ("_libghidra" in item.filename or "_native" in item.filename):
                basename = os.path.basename(item.filename)
                # Strip old _native files entirely
                if "_native" in basename:
                    print(f"  Stripping from wheel: {basename}")
                    continue
                # Keep only the stable ABI .pyd (no version/platform tag)
                is_stable_abi = basename in ("_libghidra.pyd", "_libghidra.so", "_libghidra.abi3.so")
                if not is_stable_abi:
                    print(f"  Stripping from wheel: {basename}")
                    continue

            data = zin.read(item.filename)
            if item.filename.endswith("/WHEEL"):
                text = data.decode("utf-8")
                text = re.sub(r"Tag: .*", f"Tag: {py_tag}-abi3-{platform_tag}", text)
                text = text.replace("Root-Is-Purelib: true", "Root-Is-Purelib: false")
                data = text.encode("utf-8")
            # Regenerate RECORD after filtering (pip will regenerate on install anyway)
            if item.filename.endswith("/RECORD"):
                continue
            zout.writestr(item, data)

    wheel_path.unlink()
    tmp_path.rename(new_path)
    return new_path


def _get_version(wheel_path: Path) -> str:
    """Extract version from wheel filename."""
    match = re.match(r"libghidra-([^-]+)-", wheel_path.name)
    return match.group(1) if match else "0.1.0"


def verify_pyd_deps(pyd_data: bytes, name: str) -> bool:
    """Parse PE imports and verify only expected DLL dependencies (Windows only)."""
    if sys.platform != "win32":
        return True

    try:
        pe_off = struct.unpack_from("<I", pyd_data, 0x3C)[0]
        pe_magic = struct.unpack_from("<H", pyd_data, pe_off + 24)[0]
        if pe_magic == 0x10b:  # PE32
            import_rva = struct.unpack_from("<I", pyd_data, pe_off + 24 + 104)[0]
        elif pe_magic == 0x20b:  # PE32+
            import_rva = struct.unpack_from("<I", pyd_data, pe_off + 24 + 120)[0]
        else:
            return True

        if import_rva == 0:
            return True

        # Find section containing import RVA
        num_sections = struct.unpack_from("<H", pyd_data, pe_off + 6)[0]
        opt_size = struct.unpack_from("<H", pyd_data, pe_off + 20)[0]
        sec_off = pe_off + 24 + opt_size

        for i in range(num_sections):
            s = sec_off + i * 40
            s_va = struct.unpack_from("<I", pyd_data, s + 12)[0]
            s_vs = struct.unpack_from("<I", pyd_data, s + 8)[0]
            s_raw = struct.unpack_from("<I", pyd_data, s + 20)[0]
            if s_va <= import_rva < s_va + s_vs:
                file_off = import_rva - s_va + s_raw
                dlls = []
                pos = file_off
                while True:
                    fields = struct.unpack_from("<IIIII", pyd_data, pos)
                    if fields[3] == 0:  # name RVA
                        break
                    name_off = fields[3] - s_va + s_raw
                    dll_name = b""
                    while pyd_data[name_off] != 0:
                        dll_name += bytes([pyd_data[name_off]])
                        name_off += 1
                    dlls.append(dll_name.decode("ascii"))
                    pos += 20

                # Classify
                allowed = {"KERNEL32.dll", "python3.dll"}
                crt_dlls = {"MSVCP140.dll", "VCRUNTIME140.dll", "VCRUNTIME140_1.dll"}
                crt_apis = {d for d in dlls if d.startswith("api-ms-win-crt-")}
                python_versioned = {d for d in dlls if re.match(r"python3\d+\.dll", d)}

                clean = set(dlls) - allowed - crt_dlls - crt_apis - python_versioned
                has_stable_abi = "python3.dll" in dlls
                has_static_crt = not (set(dlls) & (crt_dlls | crt_apis))

                print(f"  DLL deps for {name}:")
                for d in sorted(dlls):
                    tag = ""
                    if d == "python3.dll":
                        tag = " (stable ABI)"
                    elif d in python_versioned:
                        tag = " (version-specific)"
                    elif d in crt_dlls or d in crt_apis:
                        tag = " (CRT)"
                    print(f"    {d}{tag}")

                if has_stable_abi and has_static_crt:
                    print(f"  -> CLEAN: only KERNEL32.dll + python3.dll")
                else:
                    if not has_stable_abi:
                        print(f"  -> NOTE: using version-specific Python (not stable ABI)")
                    if not has_static_crt:
                        print(f"  -> NOTE: dynamic CRT linked (MSVC runtime required)")

                if clean:
                    print(f"  -> WARNING: unexpected deps: {clean}")
                    return False
                return True

    except (struct.error, IndexError):
        print(f"  Warning: could not parse PE imports for {name}")
    return True


def clean_natives(pkg_dir: Path) -> None:
    """Remove all native extension files from the package directory."""
    for pattern in ("_libghidra*", "_native*"):
        for f in pkg_dir.glob(pattern):
            if f.suffix in (".pyd", ".so", ".dylib"):
                print(f"  Removing: {f.name}")
                f.unlink()


def main():
    parser = argparse.ArgumentParser(description="Build libghidra wheels with native extension")
    parser.add_argument("--ghidra-source", default=None,
                        help="Path to Ghidra source tree (default: auto-detect ../ghidra)")
    parser.add_argument("--arch", default=None,
                        help="Target architecture: Win32 or x64 (Windows only)")
    parser.add_argument("--python-dir", default=None,
                        help="Python root directory (e.g., C:/Python312-32)")
    parser.add_argument("--all", action="store_true",
                        help="Build for all known local Python installations")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory for wheels (default: python/dist)")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    native_script = script_dir / "build-python-native.py"
    python_pkg = repo_root / "python"
    pkg_dir = python_pkg / "src" / "libghidra"
    dist_dir = Path(args.output_dir).resolve() if args.output_dir else python_pkg / "dist"

    # Resolve Ghidra source
    if args.ghidra_source:
        ghidra_source = Path(args.ghidra_source).resolve()
    else:
        ghidra_source = repo_root.parent / "ghidra"
        if not ghidra_source.exists():
            print(f"Error: Ghidra source not found at {ghidra_source}", file=sys.stderr)
            sys.exit(1)

    # Determine targets
    if args.all:
        targets: list[tuple[str | None, str | None]] = [(None, None)]  # default 64-bit
        if sys.platform == "win32":
            for p in ["C:/Python312-32", "C:/Python313-32", "C:/Python311-32", "C:/Python310-32"]:
                if Path(p).exists():
                    targets.append(("Win32", p))
                    break
    else:
        targets = [(args.arch, args.python_dir)]

    dist_dir.mkdir(parents=True, exist_ok=True)
    wheels_built: list[Path] = []

    # Clean ALL native extensions upfront to prevent cross-contamination
    print("Cleaning old native extensions...")
    clean_natives(pkg_dir)

    for arch, python_dir in targets:
        tag = f"arch={arch or 'default'}, python={python_dir or 'default'}"
        print(f"\n{'#' * 60}")
        print(f"# Building: {tag}")
        print(f"{'#' * 60}")

        # 1. Clean old .pyd files
        clean_natives(pkg_dir)

        # 2. Build native extension
        cmd = [sys.executable, str(native_script), "--ghidra-source", str(ghidra_source)]
        if arch:
            cmd.extend(["--arch", arch])
        if python_dir:
            cmd.extend(["--python-dir", python_dir])
        run(cmd, f"Build native ({tag})")

        # Verify .pyd was produced
        ext = ".pyd" if sys.platform == "win32" else ".so"
        natives = list(pkg_dir.glob(f"_libghidra*{ext}"))
        if not natives:
            print(f"Warning: no _native built for {tag}, skipping", file=sys.stderr)
            continue

        pyd = natives[0]
        print(f"  Built: {pyd.name} ({pyd.stat().st_size / 1024 / 1024:.1f} MB)")

        # 3. Determine Python interpreter for this target
        if python_dir:
            py = Path(python_dir) / ("python.exe" if sys.platform == "win32" else "python3")
        else:
            py = Path(sys.executable)

        # Ensure build tool is installed
        subprocess.run([str(py), "-m", "pip", "install", "--quiet", "build", "setuptools"],
                       capture_output=True)

        # 4. Build the wheel (comes out as py3-none-any since setuptools doesn't know about .pyd)
        run([str(py), "-m", "build", str(python_pkg), "--wheel", "--outdir", str(dist_dir)],
            "Build wheel")

        # 5. Re-tag the wheel with correct platform tag
        generic_wheels = sorted(dist_dir.glob("libghidra-*-py3-none-any.whl"),
                                key=lambda p: p.stat().st_mtime, reverse=True)
        if not generic_wheels:
            print("Warning: no wheel produced", file=sys.stderr)
            continue

        py_tag, plat_tag = get_python_tag(py)
        final_wheel = retag_wheel(generic_wheels[0], py_tag, plat_tag)
        wheels_built.append(final_wheel)
        print(f"  Wheel: {final_wheel.name} ({final_wheel.stat().st_size / 1024 / 1024:.1f} MB)")

        # 5b. Verify DLL dependencies of the .pyd inside the wheel
        if sys.platform == "win32":
            with zipfile.ZipFile(final_wheel, "r") as whl:
                for entry in whl.namelist():
                    if entry.endswith(".pyd") and "_libghidra" in entry:
                        verify_pyd_deps(whl.read(entry), os.path.basename(entry))

    # 6. Clean up .pyd from source (they're in the wheels now)
    clean_natives(pkg_dir)

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  Built {len(wheels_built)} wheel(s) in {dist_dir}")
    print(f"{'=' * 60}")
    for w in wheels_built:
        size = w.stat().st_size / (1024 * 1024)
        print(f"  {w.name}  ({size:.1f} MB)")
    print(f"\nInstall with:")
    for w in wheels_built:
        print(f"  pip install {w}")


if __name__ == "__main__":
    main()
