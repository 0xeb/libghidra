# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Auto-read version from the repo-root VERSION file.
# This module is referenced by pyproject.toml via [tool.setuptools.dynamic].

from pathlib import Path

_VERSION_CANDIDATES = [
    Path(__file__).resolve().parent.parent.parent / "VERSION",
    Path(__file__).resolve().parent.parent.parent.parent / "VERSION",
]

for _version_file in _VERSION_CANDIDATES:
    if _version_file.exists():
        __version__ = _version_file.read_text().strip()
        break
else:
    __version__ = "0.0.0"
