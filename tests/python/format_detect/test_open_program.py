# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import os
from pathlib import Path

import pytest

from libghidra.format_detect import detect_and_open
from libghidra.local import LocalClient, LocalClientOptions


def test_detect_and_open_native_smoke():
    """End-to-end smoke: load a real binary in LocalClient, decompile a known address.

    LocalClient is address-driven (see cpp/README.md "Out of scope" section);
    the IClient enumeration methods (list_functions, list_basic_blocks, etc.)
    always return empty in local mode by design, so this test relies on the
    caller pointing at an explicit code address inside the fixture.
    """
    pytest.importorskip("libghidra._libghidra")

    fixture = os.environ.get("LIBGHIDRA_TEST_BINARY")
    if not fixture:
        pytest.skip("set LIBGHIDRA_TEST_BINARY to a real ELF/PE/Mach-O fixture")

    path = Path(fixture)
    if not path.is_file():
        pytest.skip(f"LIBGHIDRA_TEST_BINARY does not exist: {path}")

    addr_str = os.environ.get("LIBGHIDRA_TEST_ADDRESS")
    if not addr_str:
        pytest.skip("set LIBGHIDRA_TEST_ADDRESS=0x... to a code address in the fixture")
    test_address = int(addr_str, 0)

    client = LocalClient(LocalClientOptions(default_arch="auto"))
    detected = detect_and_open(client, path)
    assert detected.language_id

    decomp = client.get_decompilation(test_address).decompilation
    assert decomp is not None
    assert decomp.pseudocode
