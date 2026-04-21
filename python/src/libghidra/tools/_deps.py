# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Lazy optional dependency imports with clear install hints."""

from __future__ import annotations

import sys
from types import ModuleType


def require_pefile() -> ModuleType:
    """Import and return pefile, or exit with an install hint."""
    try:
        import pefile
        return pefile
    except ImportError:
        print(
            "Error: pefile is required for this command.\n"
            "Install it with: pip install libghidra[cli]",
            file=sys.stderr,
        )
        sys.exit(2)


def require_capstone() -> ModuleType:
    """Import and return capstone, or exit with an install hint."""
    try:
        import capstone
        return capstone
    except ImportError:
        print(
            "Error: capstone is required for this command.\n"
            "Install it with: pip install libghidra[cli]",
            file=sys.stderr,
        )
        sys.exit(2)


def try_import(name: str) -> ModuleType | None:
    """Try to import a module, return it or None."""
    try:
        import importlib
        return importlib.import_module(name)
    except ImportError:
        return None
