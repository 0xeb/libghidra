// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
#ifdef LIBGHIDRA_POOL_TEST_ACCESS
  // Test-only seam: lets the private pool-guard regression test drive the
  // otherwise-private applyToAllSlots() so it can verify the RAII slot release
  // recovers from a throwing apply(). Compiled ONLY when the test defines this
  // macro; it is invisible to every production build.
  friend struct ::DecompilerPoolTestAccess;
#endif

  /// Construct a pool with \p pool_size slots.  Each slot creates its own
  /// Decompiler instance using \p ghidra_root (empty = embedded specs).
  explicit DecompilerPool(std::size_t pool_size, const std::string& ghidra_root);
  ~DecompilerPool();

  /// Number of slots in the pool.
  std::size_t size() const { return slots_.size(); }

  /// Load a binary into ALL pool slots.  Returns false on first failure.
  bool loadBinary(const std::string& path, const std::string& arch,
                  std::uint64_t base_address = 0,
                  const std::string& format = "");

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
  //
  // Slot 0 is always constructed (see the pool ctor), so these never return a
  // dangling reference. They are NOT gated by the pool's availability latch —
  // callers MUST hold the client-level request mutex (LocalClient::req_mu_) so a
  // primary-slot read cannot race a concurrent applyToAllSlots scope mutation on
  // the shared Architecture.

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

  // -- Local-variable mutations (applied to ALL slots) ------------------------
  //
  // A rename/retype must land on every slot so both the primary read path
  // (GetDecompilation) and the leased batch path (decompileMany) reflect it.
  // These wait until every slot is idle, reserve them all, apply, then release.
  // Returns kOk only if every slot applied the mutation; otherwise returns the
  // first non-OK status observed in slot order.

  /// Rename a function-local across all slots.
  LocalMutationStatus applyLocalRenameAllSlots(std::uint64_t func_entry,
                                               const std::string& local_id,
                                               const std::string& new_name);

  /// Retype a function-local across all slots.
  LocalMutationStatus applyLocalRetypeAllSlots(std::uint64_t func_entry,
                                               const std::string& local_id,
                                               const std::string& new_type);

  /// Broadcast an arbitrary adapter mutation to EVERY slot, keeping pooled workers
  /// coherent (Ghidra gives each Architecture its own symbol/type state, so a
  /// slot-0-only mutation is invisible to fan-out reads on worker slots). Returns
  /// true only if every slot's mutation succeeded. Use for every write endpoint
  /// (comments, type aliases/members, data-item rename/delete, symbol/type delete),
  /// exactly like applyLocalRename/RetypeAllSlots.
  bool applyMutationAllSlots(const std::function<bool(ArchAdapter&)>& apply) {
    return applyToAllSlots(apply);
  }

  /// Broadcast a decompiler-level mutation to EVERY slot. Some mutations live on
  /// the Decompiler (nameFunction/nameGlobal/setPrototype/defineStruct/defineEnum/
  /// writeBytes) rather than on ArchAdapter; they must still land on every slot so
  /// fan-out reads (ListDecompilations/ListXrefs on leased worker slots) stay
  /// coherent -- a slot-0-only write is invisible to them. Returns true only if
  /// every slot's mutation succeeded.
  bool applyDecompilerMutationAllSlots(
      const std::function<bool(ghidra_standalone::Decompiler&)>& apply) {
    return applyDecompilerToAllSlots(apply);
  }

 private:
  void release(std::size_t index);

  /// Reserve all slots, run \p apply on each adapter, release. Returns true only
  /// if every slot returns true.
  bool applyToAllSlots(const std::function<bool(ArchAdapter&)>& apply);

  /// Reserve all slots, run \p apply on each slot's decompiler, release. Returns
  /// true only if every slot returns true.
  bool applyDecompilerToAllSlots(
      const std::function<bool(ghidra_standalone::Decompiler&)>& apply);

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
