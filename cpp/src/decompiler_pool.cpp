// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "decompiler_pool.hpp"

#include <algorithm>
#include <future>
#include <thread>
#include <utility>

#include "ghidra_decompiler.h"

namespace libghidra::client::detail {

// -- PoolLease ----------------------------------------------------------------

PoolLease::PoolLease(ghidra_standalone::Decompiler* d, ArchAdapter* a,
                     std::size_t idx,
                     std::function<void(std::size_t)> release_fn)
    : decomp_(d), adapter_(a), index_(idx), release_fn_(std::move(release_fn)) {}

PoolLease::~PoolLease() {
  if (release_fn_) release_fn_(index_);
}

PoolLease::PoolLease(PoolLease&& other) noexcept
    : decomp_(other.decomp_),
      adapter_(other.adapter_),
      index_(other.index_),
      release_fn_(std::move(other.release_fn_)) {
  other.release_fn_ = nullptr;
}

PoolLease& PoolLease::operator=(PoolLease&& other) noexcept {
  if (this != &other) {
    if (release_fn_) release_fn_(index_);
    decomp_ = other.decomp_;
    adapter_ = other.adapter_;
    index_ = other.index_;
    release_fn_ = std::move(other.release_fn_);
    other.release_fn_ = nullptr;
  }
  return *this;
}

// -- DecompilerPool -----------------------------------------------------------

DecompilerPool::DecompilerPool(std::size_t pool_size,
                               const std::string& ghidra_root) {
  std::size_t n = std::max<std::size_t>(pool_size, 1);
  slots_.resize(n);
  for (std::size_t i = 0; i < n; i++) {
    if (ghidra_root.empty()) {
      slots_[i].decomp = std::make_unique<ghidra_standalone::Decompiler>();
    } else {
      slots_[i].decomp =
          std::make_unique<ghidra_standalone::Decompiler>(ghidra_root);
    }
  }
}

DecompilerPool::~DecompilerPool() = default;

bool DecompilerPool::loadBinary(const std::string& path,
                                const std::string& arch,
                                std::uint64_t base_address,
                                const std::string& format) {
  for (auto& slot : slots_) {
    if (!slot.decomp->loadBinary(path, arch, base_address, format)) return false;
  }
  rebuildAdapters();
  return true;
}

bool DecompilerPool::loadProject(const std::string& project_path,
                                 const std::string& program_path) {
  for (auto& slot : slots_) {
    if (!slot.decomp->loadProject(project_path, program_path)) return false;
  }
  rebuildAdapters();
  return true;
}

void DecompilerPool::loadState(const std::string& state_path) {
  // State only applies to primary — workers decompile from raw binary.
  slots_[0].decomp->loadState(state_path);
  slots_[0].adapter =
      std::make_unique<ArchAdapter>(slots_[0].decomp->getArchitecturePointer());
}

bool DecompilerPool::saveState(const std::string& state_path) {
  return slots_[0].decomp->saveState(state_path);
}

std::string DecompilerPool::getError() const {
  return slots_[0].decomp->getError();
}

void DecompilerPool::resetAdapters() {
  for (auto& slot : slots_) {
    slot.adapter.reset();
  }
}

void DecompilerPool::rebuildAdapters() {
  for (auto& slot : slots_) {
    slot.adapter =
        std::make_unique<ArchAdapter>(slot.decomp->getArchitecturePointer());
  }
}

ghidra_standalone::Decompiler& DecompilerPool::primary() {
  return *slots_[0].decomp;
}

ArchAdapter& DecompilerPool::primaryAdapter() { return *slots_[0].adapter; }

PoolLease DecompilerPool::acquire() {
  std::unique_lock lock(mu_);
  cv_.wait(lock, [this] {
    return std::any_of(slots_.begin(), slots_.end(),
                       [](const Slot& s) { return s.available; });
  });

  for (std::size_t i = 0; i < slots_.size(); i++) {
    if (slots_[i].available) {
      slots_[i].available = false;
      return PoolLease(slots_[i].decomp.get(), slots_[i].adapter.get(), i,
                       [this](std::size_t idx) { release(idx); });
    }
  }

  // Should never reach here — cv_.wait guarantees availability
  return {};
}

void DecompilerPool::release(std::size_t index) {
  {
    std::lock_guard lock(mu_);
    slots_[index].available = true;
  }
  cv_.notify_one();
}

std::vector<DecompilationRecord> DecompilerPool::decompileMany(
    const std::vector<std::uint64_t>& addresses,
    const std::vector<std::string>& names) {
  std::vector<DecompilationRecord> results(addresses.size());

  if (slots_.size() <= 1) {
    // Single slot — decompile sequentially (no threading overhead)
    for (std::size_t i = 0; i < addresses.size(); i++) {
      auto dl = slots_[0].adapter->decompileWithLocals(addresses[i]);
      results[i].function_entry_address = addresses[i];
      if (i < names.size()) results[i].function_name = names[i];
      if (dl.ok) {
        results[i].pseudocode = std::move(dl.pseudocode);
        results[i].locals = std::move(dl.locals);
        results[i].completed = true;
      } else {
        results[i].completed = false;
        // Offline decompile bypasses Decompiler::decompileAt, so its getError()
        // is stale/empty — carry the accurate reason from the result itself.
        results[i].error_message = dl.error;
      }
    }
    return results;
  }

  // Multi-slot — dispatch work items across pool using async tasks.
  // Each task acquires a lease, decompiles, and writes into the results vector.
  std::vector<std::future<void>> futures;
  futures.reserve(addresses.size());

  for (std::size_t i = 0; i < addresses.size(); i++) {
    futures.push_back(std::async(std::launch::async, [&, i] {
      auto lease = acquire();
      auto dl = lease.adapter().decompileWithLocals(addresses[i]);

      results[i].function_entry_address = addresses[i];
      if (i < names.size()) results[i].function_name = names[i];
      if (dl.ok) {
        results[i].pseudocode = std::move(dl.pseudocode);
        results[i].locals = std::move(dl.locals);
        results[i].completed = true;
      } else {
        results[i].completed = false;
        results[i].error_message = dl.error;
      }
    }));
  }

  // Wait for all to complete
  for (auto& f : futures) {
    f.get();
  }

  return results;
}

// Reserve every slot (wait until all idle), run \p apply on each adapter, then
// release. Serializes the mutation against any concurrent lease/decompile so a
// batch decompile can never race the scope edit. Returns true only if every
// slot reports success.
bool DecompilerPool::applyToAllSlots(
    const std::function<bool(ArchAdapter&)>& apply) {
  {
    std::unique_lock lock(mu_);
    cv_.wait(lock, [this] {
      return std::all_of(slots_.begin(), slots_.end(),
                         [](const Slot& s) { return s.available; });
    });
    for (auto& s : slots_) s.available = false;
  }
  // RAII: release every slot on ANY exit path -- including an exception thrown
  // by apply(). Without this, a throwing apply() would leave all slots marked
  // busy and never signal cv_, permanently wedging acquire()/applyToAllSlots.
  struct SlotReleaser {
    DecompilerPool* pool;
    ~SlotReleaser() {
      {
        std::lock_guard lock(pool->mu_);
        for (auto& s : pool->slots_) s.available = true;
      }
      pool->cv_.notify_all();
    }
  } releaser{this};

  bool all_ok = true;
  for (std::size_t i = 0; i < slots_.size(); i++) {
    bool ok = apply(*slots_[i].adapter);
    if (!ok) all_ok = false;
  }
  return all_ok;
}

// Decompiler-level sibling of applyToAllSlots: some mutations (function rename,
// prototype, struct/enum define, global name, byte write) live on the Decompiler
// rather than on ArchAdapter. Same reserve-all / RAII-release-all semantics, so a
// throwing apply() can never wedge the pool. Slot 0 (the primary) is applied
// first, so getError() (which reads slot 0) still reflects a primary failure.
bool DecompilerPool::applyDecompilerToAllSlots(
    const std::function<bool(ghidra_standalone::Decompiler&)>& apply) {
  {
    std::unique_lock lock(mu_);
    cv_.wait(lock, [this] {
      return std::all_of(slots_.begin(), slots_.end(),
                         [](const Slot& s) { return s.available; });
    });
    for (auto& s : slots_) s.available = false;
  }
  struct SlotReleaser {
    DecompilerPool* pool;
    ~SlotReleaser() {
      {
        std::lock_guard lock(pool->mu_);
        for (auto& s : pool->slots_) s.available = true;
      }
      pool->cv_.notify_all();
    }
  } releaser{this};

  bool all_ok = true;
  for (std::size_t i = 0; i < slots_.size(); i++) {
    bool ok = apply(*slots_[i].decomp);
    if (!ok) all_ok = false;
  }
  return all_ok;
}

LocalMutationStatus DecompilerPool::applyLocalRenameAllSlots(
    std::uint64_t func_entry, const std::string& local_id,
    const std::string& new_name) {
  LocalMutationStatus result = LocalMutationStatus::kOk;
  applyToAllSlots([&](ArchAdapter& a) {
    LocalMutationStatus st = a.applyLocalRename(func_entry, local_id, new_name);
    if (st != LocalMutationStatus::kOk && result == LocalMutationStatus::kOk) {
      result = st;
    }
    return st == LocalMutationStatus::kOk;
  });
  return result;
}

LocalMutationStatus DecompilerPool::applyLocalRetypeAllSlots(
    std::uint64_t func_entry, const std::string& local_id,
    const std::string& new_type) {
  LocalMutationStatus result = LocalMutationStatus::kOk;
  applyToAllSlots([&](ArchAdapter& a) {
    LocalMutationStatus st = a.applyLocalRetype(func_entry, local_id, new_type);
    if (st != LocalMutationStatus::kOk && result == LocalMutationStatus::kOk) {
      result = st;
    }
    return st == LocalMutationStatus::kOk;
  });
  return result;
}

}  // namespace libghidra::client::detail
