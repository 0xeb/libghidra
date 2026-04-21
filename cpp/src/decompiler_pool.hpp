// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

// Thread-safe pool of Ghidra C++ decompiler instances for parallel decompilation.
// Each pool slot owns an independent Decompiler + ArchAdapter pair.  Slot 0 is
// the "primary" instance used for mutations; any slot may be leased for
// read-only decompilation work.

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "libghidra/models.hpp"
#include "local_arch_adapter.hpp"

namespace ghidra_standalone {
class Decompiler;
}

namespace libghidra::client::detail {

/// RAII lease that auto-releases a pool slot on destruction.
class PoolLease {
 public:
  PoolLease() = default;

  ghidra_standalone::Decompiler& decomp() const { return *decomp_; }
  ArchAdapter& adapter() const { return *adapter_; }
  std::size_t index() const { return index_; }

  ~PoolLease();

  // Non-copyable, movable
  PoolLease(const PoolLease&) = delete;
  PoolLease& operator=(const PoolLease&) = delete;
  PoolLease(PoolLease&& other) noexcept;
  PoolLease& operator=(PoolLease&& other) noexcept;

 private:
  friend class DecompilerPool;
  PoolLease(ghidra_standalone::Decompiler* d, ArchAdapter* a, std::size_t idx,
            std::function<void(std::size_t)> release_fn);

  ghidra_standalone::Decompiler* decomp_ = nullptr;
  ArchAdapter* adapter_ = nullptr;
  std::size_t index_ = 0;
  std::function<void(std::size_t)> release_fn_;
};

/// Pool of N independent decompiler instances for parallel decompilation.
class DecompilerPool {
 public:
  /// Construct a pool with \p pool_size slots.  Each slot creates its own
  /// Decompiler instance using \p ghidra_root (empty = embedded specs).
  explicit DecompilerPool(std::size_t pool_size, const std::string& ghidra_root);
  ~DecompilerPool();

  /// Number of slots in the pool.
  std::size_t size() const { return slots_.size(); }

  /// Load a binary into ALL pool slots.  Returns false on first failure.
  bool loadBinary(const std::string& path, const std::string& arch);

  /// Load a Ghidra project into ALL pool slots.
  bool loadProject(const std::string& project_path,
                   const std::string& program_path);

  /// Load persisted state (XML) into the primary instance only.
  void loadState(const std::string& state_path);

  /// Save state from the primary instance.
  bool saveState(const std::string& state_path);

  /// Get error message from the primary instance.
  std::string getError() const;

  /// Reset all adapters (e.g., after CloseProgram).
  void resetAdapters();

  /// Rebuild all adapters from their respective decompiler instances.
  void rebuildAdapters();

  // -- Primary instance access (for mutations) --------------------------------

  /// Direct access to the primary (slot 0) decompiler.
  ghidra_standalone::Decompiler& primary();

  /// Direct access to the primary adapter.
  ArchAdapter& primaryAdapter();

  // -- Pool leasing (for parallel decompilation) ------------------------------

  /// Acquire a pool slot (blocks if all slots are busy).
  /// Returns an RAII lease that auto-releases on destruction.
  PoolLease acquire();

  /// Decompile a batch of addresses in parallel across pool slots.
  /// Returns one DecompilationRecord per address, in the same order.
  std::vector<DecompilationRecord> decompileMany(
      const std::vector<std::uint64_t>& addresses,
      const std::vector<std::string>& names);

 private:
  void release(std::size_t index);

  struct Slot {
    std::unique_ptr<ghidra_standalone::Decompiler> decomp;
    std::unique_ptr<ArchAdapter> adapter;
    bool available = true;
  };

  std::vector<Slot> slots_;
  std::mutex mu_;
  std::condition_variable cv_;
};

}  // namespace libghidra::client::detail
