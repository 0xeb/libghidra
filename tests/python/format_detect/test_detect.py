# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import struct
import warnings

import pytest

from libghidra.format_detect import (
    DetectedBinary,
    UnsupportedFormatError,
    detect,
    detect_and_open,
    detect_bytes,
)
from libghidra.known_languages import LANGUAGE_IDS
from libghidra.local import detect_arch
from libghidra.models import OpenProgramRequest


def pe_header(machine: int) -> bytes:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xF0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<Q", data, 0xB0, 0x140000000)
    return bytes(data)


def elf_header(ei_class: int, ei_data: int, e_machine: int) -> bytes:
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4] = ei_class
    data[5] = ei_data
    data[6] = 1
    bo = "<" if ei_data == 1 else ">"
    struct.pack_into(f"{bo}H", data, 16, 2)
    struct.pack_into(f"{bo}H", data, 18, e_machine)
    struct.pack_into(f"{bo}I", data, 20, 1)
    struct.pack_into(f"{bo}H", data, 52 if ei_class == 2 else 40, 64 if ei_class == 2 else 52)
    return bytes(data)


def macho_header(magic: bytes, cputype: int) -> bytes:
    bo = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
    return magic + struct.pack(f"{bo}I", cputype) + b"\0" * 24


def fat_macho_header(*cputypes: int) -> bytes:
    data = bytearray(b"\xca\xfe\xba\xbe" + struct.pack(">I", len(cputypes)))
    for cputype in cputypes:
        data += struct.pack(">IIIII", cputype, 0, 0, 0, 0)
    return bytes(data)


@pytest.mark.parametrize(
    ("data", "format_name", "language_id", "compiler"),
    [
        (pe_header(0x014C), "pe", "x86:LE:32:default", "windows"),
        (pe_header(0x8664), "pe", "x86:LE:64:default", "windows"),
        (pe_header(0x01C0), "pe", "ARM:LE:32:v8", "windows"),
        (pe_header(0xAA64), "pe", "AARCH64:LE:64:v8A", "windows"),
        (elf_header(1, 1, 3), "elf", "x86:LE:32:default", "gcc"),
        (elf_header(2, 1, 62), "elf", "x86:LE:64:default", "gcc"),
        (elf_header(1, 2, 40), "elf", "ARM:BE:32:v8", "default"),
        (elf_header(2, 2, 183), "elf", "AARCH64:BE:64:v8A", "default"),
        (elf_header(1, 1, 243), "elf", "RISCV:LE:32:default", "default"),
        (elf_header(2, 1, 243), "elf", "RISCV:LE:64:default", "default"),
        (macho_header(b"\xce\xfa\xed\xfe", 7), "macho", "x86:LE:32:default", "default"),
        (macho_header(b"\xcf\xfa\xed\xfe", 0x01000007), "macho", "x86:LE:64:default", "default"),
        (macho_header(b"\xcf\xfa\xed\xfe", 0x0100000C), "macho", "AARCH64:LE:64:v8A", "default"),
    ],
)
def test_detect_bytes_maps_supported_headers(data, format_name, language_id, compiler):
    detected = detect_bytes(data)
    assert detected.format == format_name
    assert detected.language_id == language_id
    assert detected.compiler_spec_id == compiler
    assert detected.language_id in LANGUAGE_IDS


def test_detect_path_and_compat_detect_arch(tmp_path):
    path = tmp_path / "tiny.exe"
    path.write_bytes(pe_header(0x8664))

    assert detect(path).language_id == "x86:LE:64:default"
    assert detect_arch(str(path)) == "x86:LE:64:default"


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\x7fELF", "unsupported ELF file"),
        (b"MZ" + b"\0" * 8, "unsupported PE file"),
        (macho_header(b"\xcf\xfa\xed\xfe", 0xFFFFFFFF), "unsupported Mach-O cputype"),
        (elf_header(2, 1, 0xFFFF), "unsupported ELF e_machine"),
        (pe_header(0xFFFF), "unsupported PE machine"),
    ],
)
def test_unsupported_and_truncated_headers(data, message):
    with pytest.raises(UnsupportedFormatError, match=message):
        detect_bytes(data)


def test_unknown_nonempty_bytes_are_raw_data():
    detected = detect_bytes(b"\x90\x90\xcc\x00")
    assert detected == DetectedBinary(
        format="raw",
        language_id="DATA:LE:64:default",
        compiler_spec_id="pointer64",
        bits=64,
        endian="LE",
        machine="raw-data",
    )


def test_fat_macho_uses_first_supported_slice_and_warns():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        detected = detect_bytes(fat_macho_header(0xFFFFFFFF, 0x0100000C))

    assert detected.format == "macho-fat"
    assert detected.language_id == "AARCH64:LE:64:v8A"
    assert detected.warnings == ["skipped unsupported Mach-O fat slice(s): 0xffffffff"]
    assert str(caught[0].message) == detected.warnings[0]


def test_detect_and_open_passes_language_and_compiler(tmp_path):
    path = tmp_path / "tiny.elf"
    path.write_bytes(elf_header(2, 1, 62))

    class FakeClient:
        request: OpenProgramRequest | None = None

        def open_program(self, request: OpenProgramRequest):
            self.request = request

    client = FakeClient()
    detected = detect_and_open(client, path, compiler_spec_id="custom")

    assert detected.language_id == "x86:LE:64:default"
    assert detected.compiler_spec_id == "custom"
    assert client.request == OpenProgramRequest(
        program_path=str(path),
        language_id="x86:LE:64:default",
        compiler_spec_id="custom",
        format="elf",
    )
