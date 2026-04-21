// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
