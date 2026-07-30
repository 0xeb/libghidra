# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
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
    # Installed wheel: the source-tree VERSION file is not shipped, so fall back
    # to the distribution metadata (setuptools records it from this same attr at
    # build time, when the VERSION file above IS found). Only if the distribution
    # metadata is missing too do we report the 0.0.0 sentinel.
    #
    # NOTE: keep every `__version__` assignment inside this for/else (never a bare
    # top-level `__version__ = ...` literal): setuptools resolves the packaging
    # version by statically parsing this module, and a top-level literal would be
    # picked up verbatim (recording e.g. an empty/0.0.0 version) instead of
    # letting it import-and-evaluate the real lookup below.
    try:
        from importlib.metadata import PackageNotFoundError
        from importlib.metadata import version as _dist_version

        __version__ = _dist_version("libghidra")
    except (ImportError, PackageNotFoundError):
        __version__ = "0.0.0"
