// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <string>

#include "libghidra/api.hpp"

namespace libghidra::client {

struct LocalClientOptions {
  /// Path to Ghidra source tree (for .sla/.pspec/.cspec files).
  /// If empty, uses embedded specs (requires linking ghidra_cpp with embedded resources).
  std::string ghidra_root;

  /// Path for auto-save/load of analysis state (XML).
  /// If empty, state persistence is disabled.
  std::string state_path;

  /// Sleigh language ID hint (e.g. "x86:LE:64:default").
  /// If empty, auto-detect from binary format.
  std::string default_arch;

  /// Number of decompiler engine instances for parallel decompilation.
  /// Each slot independently loads the binary for thread-safe concurrent work.
  /// 1 = single-threaded (default, backward compatible).
  /// >1 = parallel decompilation in ListDecompilations/ListXrefs.
  int pool_size = 1;
};

/// Create a LocalClient backed by the standalone Ghidra C++ decompiler.
/// The returned IClient supports offline analysis without a running Ghidra JVM.
std::unique_ptr<IClient> CreateLocalClient(LocalClientOptions options);

}  // namespace libghidra::client
