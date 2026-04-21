// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
                                const std::string& arch) {
  for (auto& slot : slots_) {
    if (!slot.decomp->loadBinary(path, arch)) return false;
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
      std::string code = slots_[0].decomp->decompileAt(addresses[i]);
      results[i].function_entry_address = addresses[i];
      if (i < names.size()) results[i].function_name = names[i];
      if (!code.empty()) {
        results[i].pseudocode = std::move(code);
        results[i].completed = true;
      } else {
        results[i].completed = false;
        results[i].error_message = slots_[0].decomp->getError();
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
      std::string code = lease.decomp().decompileAt(addresses[i]);

      results[i].function_entry_address = addresses[i];
      if (i < names.size()) results[i].function_name = names[i];
      if (!code.empty()) {
        results[i].pseudocode = std::move(code);
        results[i].completed = true;
      } else {
        results[i].completed = false;
        results[i].error_message = lease.decomp().getError();
      }
    }));
  }

  // Wait for all to complete
  for (auto& f : futures) {
    f.get();
  }

  return results;
}

}  // namespace libghidra::client::detail
