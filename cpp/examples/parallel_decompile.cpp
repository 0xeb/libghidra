// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// parallel_decompile: Batch decompilation using the decompiler pool.
//
// Usage: parallel_decompile <binary_path> [pool_size] [ghidra_root] [arch]
//
// Demonstrates: CreateLocalClient with pool_size > 1 for parallel
// decompilation via ListDecompilations.  Times the decompilation and
// prints throughput stats.

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

#include "libghidra/ghidra.hpp"

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0]
              << " <binary_path> [pool_size] [ghidra_root] [arch]\n"
              << "\n"
              << "  pool_size: number of parallel decompiler engines (default 4)\n"
              << "  Decompiles all functions in the binary and reports timing.\n";
    return 1;
  }

  const std::string binary_path = argv[1];
  const int pool_size = (argc >= 3) ? std::atoi(argv[2]) : 4;
  const std::string ghidra_root = (argc >= 4) ? argv[3] : "";
  const std::string arch = (argc >= 5) ? argv[4] : "";

  std::cout << "Loading binary: " << binary_path << "\n";
  std::cout << "Pool size: " << pool_size << "\n";

  auto t0 = std::chrono::steady_clock::now();

  auto client = ghidra::local({
      .ghidra_root = ghidra_root,
      .default_arch = arch,
      .pool_size = pool_size,
  });

  ghidra::OpenRequest req;
  req.program_path = binary_path;
  auto open_result = client->OpenProgram(req);
  if (!open_result.ok()) {
    std::cerr << "Failed to load binary: " << open_result.status.message << "\n";
    return 1;
  }

  auto t1 = std::chrono::steady_clock::now();
  auto load_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
  std::cout << "Load time: " << load_ms << " ms\n";

  // List all functions
  auto funcs = client->ListFunctions(0, 0, 0, 0);
  if (!funcs.ok()) {
    std::cerr << "ListFunctions failed: " << funcs.status.message << "\n";
    return 1;
  }

  int total = static_cast<int>(funcs.value->functions.size());
  std::cout << "Found " << total << " function(s)\n";

  if (total == 0) {
    std::cout << "No functions to decompile.\n";
    return 0;
  }

  // Batch decompile all functions via ListDecompilations (uses pool)
  auto t2 = std::chrono::steady_clock::now();
  auto decomps = client->ListDecompilations(0, 0, 0, 0, 60000);
  auto t3 = std::chrono::steady_clock::now();

  if (!decomps.ok()) {
    std::cerr << "ListDecompilations failed: " << decomps.status.message << "\n";
    return 1;
  }

  auto decomp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();
  int ok_count = 0, fail_count = 0;
  std::size_t total_bytes = 0;
  for (const auto& d : decomps.value->decompilations) {
    if (d.completed) {
      ok_count++;
      total_bytes += d.pseudocode.size();
    } else {
      fail_count++;
    }
  }

  std::cout << "\nResults:\n";
  std::cout << "  Succeeded: " << ok_count << "\n";
  std::cout << "  Failed:    " << fail_count << "\n";
  std::cout << "  Total pseudocode: " << total_bytes << " bytes\n";
  std::cout << "  Decompilation time: " << decomp_ms << " ms\n";

  if (decomp_ms > 0) {
    double funcs_per_sec = static_cast<double>(ok_count) * 1000.0 / decomp_ms;
    std::cout << "  Throughput: " << std::fixed << std::setprecision(1)
              << funcs_per_sec << " functions/sec\n";
  }

  return (fail_count > 0) ? 1 : 0;
}
