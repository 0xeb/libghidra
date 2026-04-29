# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""local_quickstart: open a binary in offline mode and decompile a function.

Mirrors rust/examples/local_quickstart.rs.

Usage:
    python local_quickstart.py <BINARY> <0xADDR>
"""

from __future__ import annotations

import sys

from libghidra import LocalClient, LocalClientOptions
from libghidra.format_detect import detect_and_open


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: local_quickstart.py <BINARY> <0xADDR>", file=sys.stderr)
        return 2

    binary = sys.argv[1]
    address = int(sys.argv[2], 0)

    client = LocalClient(LocalClientOptions(default_arch="auto"))

    detected = detect_and_open(client, binary)
    print(
        f"Loaded {binary} ({detected.format}, {detected.bits}-bit {detected.endian}, "
        f"language={detected.language_id})"
    )

    resp = client.get_decompilation(address)
    if resp.decompilation is None:
        print(f"no decompilation returned for 0x{address:x}", file=sys.stderr)
        return 1

    d = resp.decompilation
    print(f"\n--- {d.function_name} @ 0x{d.function_entry_address:x} ---")
    if not d.pseudocode:
        print(f"(empty pseudocode; error_message: {d.error_message})", file=sys.stderr)
        return 1
    print(d.pseudocode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
