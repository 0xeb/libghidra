// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// cfg_analysis: Basic blocks and control flow graph via the local backend.
//
// Usage: cfg_analysis <binary_path> [ghidra_root] [arch]
//
// Demonstrates: ListFunctions, ListBasicBlocks, ListCFGEdges.
//
// If ghidra_root is omitted, uses embedded processor specs (no Ghidra needed).

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

#include "libghidra/ghidra.hpp"

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0]
              << " <binary_path> [ghidra_root] [arch]\n";
    return 1;
  }

  const std::string binary_path = argv[1];
  const std::string ghidra_root = (argc >= 3) ? argv[2] : "";
  const std::string arch = (argc >= 4) ? argv[3] : "";

  auto client = ghidra::local({
      .ghidra_root = ghidra_root,
      .default_arch = arch,
  });

  ghidra::OpenRequest req;
  req.program_path = binary_path;
  auto open_result = client->OpenProgram(req);
  if (!open_result.ok()) {
    std::cerr << "Failed to load binary: " << open_result.status.message << "\n";
    return 1;
  }
  std::cout << "Loaded: " << open_result.value->program_name << "\n\n";

  // Find first function
  auto funcs = client->ListFunctions(0, UINT64_MAX, 1, 0);
  if (!funcs.ok() || funcs.value->functions.empty()) {
    std::cerr << "No functions found.\n";
    return 1;
  }

  const auto& func = funcs.value->functions[0];
  std::cout << "Function: " << func.name
            << " @ 0x" << std::hex << func.entry_address
            << " (0x" << func.start_address << " - 0x" << func.end_address << ")\n\n";

  // --- Basic blocks ---
  auto blocks = client->ListBasicBlocks(func.start_address, func.end_address, 0, 0);
  if (!blocks.ok()) {
    std::cerr << "ListBasicBlocks failed: " << blocks.status.message << "\n";
    return 1;
  }

  std::cout << "Basic blocks (" << std::dec << blocks.value->blocks.size() << "):\n";
  std::cout << std::left
            << std::setw(18) << "  START"
            << std::setw(18) << "END"
            << std::setw(8) << "IN"
            << "OUT\n";
  std::cout << "  " << std::string(44, '-') << "\n";

  for (const auto& b : blocks.value->blocks) {
    std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(12) << b.start_address
              << "  0x" << std::setw(12) << b.end_address
              << "  " << std::setfill(' ') << std::dec
              << std::setw(6) << b.in_degree
              << "  " << b.out_degree << "\n";
  }

  // --- CFG edges ---
  auto edges = client->ListCFGEdges(func.start_address, func.end_address, 0, 0);
  if (!edges.ok()) {
    std::cerr << "\nListCFGEdges failed: " << edges.status.message << "\n";
    return 1;
  }

  std::cout << "\nCFG edges (" << std::dec << edges.value->edges.size() << "):\n";
  std::cout << std::left
            << std::setw(18) << "  SRC"
            << std::setw(18) << "DST"
            << "KIND\n";
  std::cout << "  " << std::string(42, '-') << "\n";

  for (const auto& e : edges.value->edges) {
    std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(12) << e.src_block_start
              << "  0x" << std::setw(12) << e.dst_block_start
              << "  " << std::setfill(' ') << e.edge_kind << "\n";
  }

  // --- Summary ---
  std::cout << "\nSummary: " << std::dec << blocks.value->blocks.size()
            << " blocks, " << edges.value->edges.size() << " edges\n";

  return 0;
}
