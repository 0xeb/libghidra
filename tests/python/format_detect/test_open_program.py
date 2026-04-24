# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import os
from pathlib import Path

import pytest

from libghidra.format_detect import detect_and_open
from libghidra.local import LocalClient, LocalClientOptions


def test_detect_and_open_native_smoke():
    pytest.importorskip("libghidra._libghidra")

    fixture = os.environ.get("LIBGHIDRA_TEST_BINARY")
    if not fixture:
        pytest.skip("set LIBGHIDRA_TEST_BINARY to a real ELF/PE/Mach-O fixture")

    path = Path(fixture)
    if not path.is_file():
        pytest.skip(f"LIBGHIDRA_TEST_BINARY does not exist: {path}")

    client = LocalClient(LocalClientOptions(default_arch="auto"))
    detected = detect_and_open(client, path)

    functions = client.list_functions(limit=1).functions
    assert detected.language_id
    assert functions

    decomp = client.get_decompilation(functions[0].entry_address).decompilation
    assert decomp is not None
    assert decomp.pseudocode
