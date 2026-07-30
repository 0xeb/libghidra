// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once
#include <string>

namespace ghidra_embedded {

/// Thread-safe, ref-counted manager for embedded spec files.
/// The first Decompiler instance extracts all embedded .sla/.pspec/.cspec/.ldefs
/// files (zlib-compressed) to a persistent cache in ~/.ghidracpp/cache/sleigh/.
/// Subsequent instances — even across process restarts — reuse the same cache.
/// The cache is invalidated automatically when the exe/dll is rebuilt.
class EmbeddedSpecManager {
public:
    /// Increment ref count and extract specs to cache if not already present.
    /// Returns the path to the cache directory containing the extracted specs.
    static std::string acquire();

    /// Decrement ref count. The cache persists on disk across runs.
    static void release();

    EmbeddedSpecManager() = delete;
};

} // namespace ghidra_embedded
