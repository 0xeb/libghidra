# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Local binary format and Ghidra language auto-detection."""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

from .known_languages import LANGUAGE_IDS
from .models import OpenProgramRequest


class FormatDetectError(Exception):
    """Base class for binary format detection failures."""


class UnsupportedFormatError(FormatDetectError):
    """Raised when the binary format or architecture is unsupported."""


class MissingOptionalDependencyError(FormatDetectError):
    """Raised when an optional parser dependency is required but unavailable."""


@dataclass(frozen=True)
class DetectedBinary:
    """Result of local binary format detection."""

    format: str
    language_id: str
    compiler_spec_id: str = ""
    bits: int = 0
    endian: str = ""
    machine: str = ""
    base_address: int | None = None
    warnings: list[str] = field(default_factory=list)


_RAW_LANGUAGE_ID = "DATA:LE:64:default"
_RAW_COMPILER_SPEC_ID = "pointer64"

_PE_MACHINE_MAP = {
    0x014C: ("x86:LE:32:default", "windows", "x86"),
    0x8664: ("x86:LE:64:default", "windows", "x86_64"),
    0x01C0: ("ARM:LE:32:v8", "windows", "ARM"),
    0x01C4: ("ARM:LE:32:v8", "windows", "ARMNT"),
    0xAA64: ("AARCH64:LE:64:v8A", "windows", "ARM64"),
}

_ELF_MACHINE_MAP = {
    3: ("x86", True, "Intel 80386"),
    8: ("MIPS", True, "MIPS"),
    20: ("PowerPC", True, "PowerPC"),
    40: ("ARM", False, "ARM"),
    62: ("x86", True, "AMD x86-64"),
    183: ("AARCH64", False, "AArch64"),
    243: ("RISCV", True, "RISC-V"),
}

_ELF_SLEIGH = {
    ("x86", 32, "LE"): ("x86:LE:32:default", "gcc"),
    ("x86", 64, "LE"): ("x86:LE:64:default", "gcc"),
    ("ARM", 32, "LE"): ("ARM:LE:32:v8", "default"),
    ("ARM", 32, "BE"): ("ARM:BE:32:v8", "default"),
    ("AARCH64", 64, "LE"): ("AARCH64:LE:64:v8A", "default"),
    ("AARCH64", 64, "BE"): ("AARCH64:BE:64:v8A", "default"),
    ("MIPS", 32, "BE"): ("MIPS:BE:32:default", "default"),
    ("MIPS", 32, "LE"): ("MIPS:LE:32:default", "default"),
    ("MIPS", 64, "BE"): ("MIPS:BE:64:default", "default"),
    ("MIPS", 64, "LE"): ("MIPS:LE:64:default", "default"),
    ("PowerPC", 32, "BE"): ("PowerPC:BE:32:default", "default"),
    ("PowerPC", 64, "BE"): ("PowerPC:BE:64:default", "default"),
    ("PowerPC", 64, "LE"): ("PowerPC:LE:64:default", "default"),
    ("RISCV", 32, "LE"): ("RISCV:LE:32:default", "default"),
    ("RISCV", 64, "LE"): ("RISCV:LE:64:default", "default"),
}

_MACHO_CPU_MAP = {
    7: ("x86:LE:32:default", "default", "x86"),
    12: ("ARM:LE:32:v8", "default", "ARM"),
    0x01000007: ("x86:LE:64:default", "default", "x86_64"),
    0x0100000C: ("AARCH64:LE:64:v8A", "default", "ARM64"),
}

_FAT_MAGIC = {
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


def detect(path: str | Path) -> DetectedBinary:
    """Detect binary format and Ghidra language ID from a file path."""

    p = Path(path)
    with p.open("rb") as f:
        return _detect_stream(f)


def detect_bytes(data: bytes | bytearray | memoryview) -> DetectedBinary:
    """Detect binary format and Ghidra language ID from bytes."""

    return _detect_buffer(bytes(data))


def detect_and_open(
    client,
    path: str | Path,
    *,
    compiler_spec_id: str | None = None,
) -> DetectedBinary:
    """Detect a local binary, open it with a LocalClient-like object, and return the detection."""

    detected = detect(path)
    compiler = compiler_spec_id if compiler_spec_id is not None else detected.compiler_spec_id
    request = OpenProgramRequest(
        program_path=str(path),
        language_id=detected.language_id,
        compiler_spec_id=compiler,
    )
    client.open_program(request)
    if compiler == detected.compiler_spec_id:
        return detected
    return DetectedBinary(
        format=detected.format,
        language_id=detected.language_id,
        compiler_spec_id=compiler,
        bits=detected.bits,
        endian=detected.endian,
        machine=detected.machine,
        base_address=detected.base_address,
        warnings=list(detected.warnings),
    )


def _detect_stream(f: BinaryIO) -> DetectedBinary:
    head = f.read(4096)
    return _detect_buffer(head, reader=f)


def _detect_buffer(data: bytes, reader: BinaryIO | None = None) -> DetectedBinary:
    if len(data) < 4:
        raise UnsupportedFormatError("file is too small to identify a binary format")

    if data.startswith(b"MZ"):
        return _detect_pe(data, reader)
    if data.startswith(b"\x7fELF"):
        return _detect_elf(data)
    if data[:4] in _FAT_MAGIC:
        return _detect_fat_macho(data, reader)
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return _detect_macho(data, reader)

    return _validated(
        DetectedBinary(
            format="raw",
            language_id=_RAW_LANGUAGE_ID,
            compiler_spec_id=_RAW_COMPILER_SPEC_ID,
            bits=64,
            endian="LE",
            machine="raw-data",
        )
    )


def _detect_pe(data: bytes, reader: BinaryIO | None) -> DetectedBinary:
    pefile = _require_extra("pefile", "PE")
    if reader is not None:
        reader.seek(0)
        data = reader.read()
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception as e:
        raise UnsupportedFormatError(f"unsupported PE file: {e}") from e
    machine = pe.FILE_HEADER.Machine
    entry = _PE_MACHINE_MAP.get(machine)
    if entry is None:
        raise UnsupportedFormatError(f"unsupported PE machine 0x{machine:04x}")
    language_id, compiler, machine_name = entry
    return _validated(
        DetectedBinary(
            format="pe",
            language_id=language_id,
            compiler_spec_id=compiler,
            bits=_bits_from_language(language_id),
            endian="LE",
            machine=machine_name,
            base_address=getattr(getattr(pe, "OPTIONAL_HEADER", None), "ImageBase", None),
        )
    )


def _detect_elf(data: bytes) -> DetectedBinary:
    elffile_module = _require_extra("elftools.elf.elffile", "ELF")
    try:
        elf = elffile_module.ELFFile(BytesIO(data))
    except Exception as e:
        raise UnsupportedFormatError(f"unsupported ELF file: {e}") from e

    bits = elf.elfclass
    endian = "LE" if elf.little_endian else "BE"
    e_machine_raw = elf.header["e_machine"]
    e_machine = _elf_machine_number(e_machine_raw)
    entry = _ELF_MACHINE_MAP.get(e_machine)
    if entry is None:
        raise UnsupportedFormatError(f"unsupported ELF e_machine {e_machine_raw}")

    base_lang, uses_class_bits, machine = entry
    if not uses_class_bits:
        bits = 32 if base_lang == "ARM" else 64
    mapped = _ELF_SLEIGH.get((base_lang, bits, endian))
    if mapped is None:
        raise UnsupportedFormatError(
            f"unsupported ELF architecture {machine} {bits}-bit {endian}"
        )
    language_id, compiler = mapped
    return _validated(
        DetectedBinary(
            format="elf",
            language_id=language_id,
            compiler_spec_id=compiler,
            bits=bits,
            endian=endian,
            machine=machine,
        )
    )


def _detect_macho(data: bytes, reader: BinaryIO | None) -> DetectedBinary:
    if reader is not None:
        reader.seek(0)
        data = reader.read()
    return _detect_macho_header(data, format_name="macho")


def _detect_fat_macho(data: bytes, reader: BinaryIO | None) -> DetectedBinary:
    if reader is not None:
        reader.seek(0)
        data = reader.read()
    return _detect_fat_macho_header(data)


def _detect_macho_header(data: bytes, *, format_name: str) -> DetectedBinary:
    if len(data) < 8:
        raise UnsupportedFormatError("unsupported Mach-O file: truncated header")

    magic = data[:4]
    byteorder = "little" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else "big"
    cputype = int.from_bytes(data[4:8], byteorder)
    entry = _MACHO_CPU_MAP.get(cputype)
    if entry is None:
        raise UnsupportedFormatError(f"unsupported Mach-O cputype 0x{cputype:08x}")

    return _detected_macho_entry(entry, format_name=format_name)


def _detect_fat_macho_header(data: bytes) -> DetectedBinary:
    if len(data) < 8:
        raise UnsupportedFormatError("unsupported Mach-O file: truncated fat header")

    magic = data[:4]
    byteorder = "big" if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "little"
    stride = 32 if magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca") else 20
    nfat_arch = int.from_bytes(data[4:8], byteorder)
    skipped: list[str] = []
    offset = 8
    for _ in range(nfat_arch):
        if len(data) < offset + 4:
            raise UnsupportedFormatError("unsupported Mach-O file: truncated fat arch")
        cputype = int.from_bytes(data[offset : offset + 4], byteorder)
        offset += stride
        entry = _MACHO_CPU_MAP.get(cputype)
        if entry is None:
            skipped.append(f"0x{cputype:08x}")
            continue
        message = ""
        if skipped:
            message = f"skipped unsupported Mach-O fat slice(s): {', '.join(skipped)}"
            warnings.warn(message, RuntimeWarning, stacklevel=2)
        return _detected_macho_entry(
            entry,
            format_name="macho-fat",
            warnings_list=[message] if message else [],
        )
    raise UnsupportedFormatError(
        "unsupported Mach-O binary: no supported architecture slices"
    )


def _detected_macho_entry(
    entry: tuple[str, str, str],
    *,
    format_name: str,
    warnings_list: list[str] | None = None,
) -> DetectedBinary:
    language_id, compiler, machine = entry
    return _validated(
        DetectedBinary(
            format=format_name,
            language_id=language_id,
            compiler_spec_id=compiler,
            bits=_bits_from_language(language_id),
            endian="LE" if ":LE:" in language_id else "BE",
            machine=machine,
            warnings=warnings_list or [],
        )
    )


def _require_extra(module_name: str, format_name: str):
    try:
        return __import__(module_name, fromlist=["*"])
    except ImportError as e:
        raise MissingOptionalDependencyError(
            f"{format_name} detection requires the libghidra local extra; "
            "install with: pip install 'libghidra[local]'"
        ) from e


def _elf_machine_number(value: int | str) -> int:
    if isinstance(value, int):
        return value
    names = {
        "EM_386": 3,
        "EM_MIPS": 8,
        "EM_PPC": 20,
        "EM_ARM": 40,
        "EM_X86_64": 62,
        "EM_AARCH64": 183,
        "EM_RISCV": 243,
    }
    if value in names:
        return names[value]
    raise UnsupportedFormatError(f"unsupported ELF e_machine {value}")



def _validated(detected: DetectedBinary) -> DetectedBinary:
    if detected.language_id not in LANGUAGE_IDS:
        raise UnsupportedFormatError(
            f"detected language ID {detected.language_id!r} is not embedded"
        )
    return detected


def _bits_from_language(language_id: str) -> int:
    try:
        return int(language_id.split(":")[2])
    except (IndexError, ValueError):
        return 0
