// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// list_xrefs: Demonstrate cross-reference extraction via the local backend.
//
// Usage: list_xrefs <binary_path> [ghidra_root] [arch]
//
// Demonstrates: CreateLocalClient -> OpenProgram -> ListXrefs.
// Decompiles all discovered functions, then extracts call and data xrefs
// from the decompiler's pcode analysis.
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

  // Open the binary
  ghidra::OpenRequest req;
  req.program_path = binary_path;
  auto open_result = client->OpenProgram(req);
  if (!open_result.ok()) {
    std::cerr << "Failed to load binary: " << open_result.status.message << "\n";
    return 1;
  }
  std::cout << "Loaded: " << open_result.value->program_name << "\n\n";

  // List all functions first
  auto funcs = client->ListFunctions(0, UINT64_MAX, 0, 0);
  if (!funcs.ok()) {
    std::cerr << "ListFunctions failed: " << funcs.status.message << "\n";
    return 1;
  }
  std::cout << "Found " << funcs.value->functions.size() << " functions\n\n";

  // Get xrefs across the entire address space
  auto xrefs = client->ListXrefs(0, UINT64_MAX, 0, 0);
  if (!xrefs.ok()) {
    std::cerr << "ListXrefs failed: " << xrefs.status.message << "\n";
    return 1;
  }

  std::cout << "Cross-references (" << xrefs.value->xrefs.size() << " total):\n";
  std::cout << std::string(72, '-') << "\n";
  std::cout << std::left << std::setw(18) << "FROM"
            << std::setw(18) << "TO"
            << std::setw(20) << "TYPE"
            << "FLAGS\n";
  std::cout << std::string(72, '-') << "\n";

  for (const auto& x : xrefs.value->xrefs) {
    std::cout << "0x" << std::hex << std::setfill('0') << std::setw(12) << x.from_address
              << "  0x" << std::setw(12) << x.to_address
              << "  " << std::setfill(' ') << std::left << std::setw(20) << x.ref_type;

    if (x.is_flow) std::cout << "flow ";
    if (x.is_memory) std::cout << "mem ";
    std::cout << "\n";
  }

  return 0;
}
