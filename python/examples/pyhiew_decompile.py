# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.

"""
Decompile - Offline decompilation via libghidra for PyHiew

Decompiles at the current cursor position using libghidra's offline
Sleigh decompiler engine. No Ghidra JVM required.

Features:
- Auto-detects architecture from PE/ELF/Mach-O headers
- Decompiles at cursor offset
- Displays pseudocode in a scrollable Hiew window
- Caches the LocalClient across invocations for speed
- F2: copy pseudocode to clipboard

Requirements:
    pip install libghidra       (the wheel includes the native decompiler)
    pip install pyperclip       (optional, for clipboard support)
"""
from __future__ import annotations

import hiew


class Decompiler:
    """Persistent decompiler state across Hiew invocations."""

    def __init__(self):
        self._client = None
        self._opened_file: str | None = None
        self._last_pseudocode: str = ""
        self._window = hiew.Window()

    def _ensure_client(self, filepath: str) -> bool:
        """Open the binary in LocalClient, reusing if same file."""
        if self._client is not None and self._opened_file == filepath:
            return True

        try:
            import libghidra
        except ImportError:
            hiew.Message("Decompile", "libghidra not installed.\npip install libghidra")
            return False

        # Close previous if different file
        if self._client is not None:
            try:
                self._client.close_program()
            except Exception:
                pass
            self._client = None
            self._opened_file = None

        try:
            client = libghidra.local()
            client.open_program(filepath)
            self._client = client
            self._opened_file = filepath
            return True
        except ImportError:
            hiew.Message(
                "Decompile",
                "Native extension not available.\n\n"
                "Install the libghidra wheel:\n"
                "  pip install libghidra-0.0.3-cp312-abi3-win_amd64.whl"
            )
            return False
        except Exception as e:
            hiew.Message("Decompile", f"Failed to open binary:\n{e}")
            return False

    def _decompile(self, address: int) -> str | None:
        """Decompile at address, return pseudocode or error string."""
        if self._client is None:
            return None
        try:
            resp = self._client.get_decompilation(address)
            if resp.decompilation and resp.decompilation.pseudocode:
                return resp.decompilation.pseudocode
            elif resp.decompilation and resp.decompilation.error_message:
                return f"// Error: {resp.decompilation.error_message}"
            return "// No decompilation result"
        except Exception as e:
            return f"// Decompilation failed: {e}"

    def _copy_to_clipboard(self) -> None:
        """Copy last pseudocode to clipboard."""
        if not self._last_pseudocode:
            return
        try:
            import pyperclip
            pyperclip.copy(self._last_pseudocode)
            hiew.Message("Decompile", "Copied to clipboard.")
        except ImportError:
            hiew.Message("Decompile", "pyperclip not installed.\npip install pyperclip")

    def run(self) -> None:
        """Main plugin entry — called each time user invokes the script."""
        data = hiew.GetData()
        filepath = data.filename
        offset = data.offsetCurrent

        if not self._ensure_client(filepath):
            return

        pseudocode = self._decompile(offset)
        if pseudocode is None:
            hiew.Message("Decompile", "Decompilation returned no result.")
            return

        self._last_pseudocode = pseudocode

        # Display in a window
        lines = pseudocode.split("\n")
        title = f"Decompile @ 0x{offset:X}"
        width = min(max(max((len(line) for line in lines), default=40) + 4, 40), 120)

        self._window.Create(
            title=title,
            lines=lines,
            width=width,
            main_keys={2: "Copy"},
        )

        while True:
            _, key = self._window.Show()
            if key == hiew.HEM_FNKEY_F2:
                self._copy_to_clipboard()
                continue
            break


# ---------------------------------------------------------------------------
# Module-level instance (persists across invocations in same Hiew session)
_decompiler: Decompiler | None = None


def DecompileMain() -> None:
    global _decompiler
    if _decompiler is None:
        _decompiler = Decompiler()
    _decompiler.run()


try:
    DecompileMain()
except SystemExit:
    pass
except Exception:
    import traceback
    hiew.Window.FromString("Decompile Error", traceback.format_exc(), width=80)
