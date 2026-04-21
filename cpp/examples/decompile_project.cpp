// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// decompile_project: Open a Ghidra project (.gpr) and decompile functions via IClient.
//
// Usage: decompile_project <gpr_path> <binary_path> [function_name] [ghidra_root]
//
// If [function_name] is given, decompiles that specific function.
// Otherwise lists all functions and decompiles the first 3.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

#include "libghidra/ghidra.hpp"

int main(int argc, char* argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0]
              << " <gpr_path> <binary_path> [function_name] [ghidra_root]\n";
    return 1;
  }

  const std::string gpr_path = argv[1];
  const std::string binary_path = argv[2];
  const std::string target_func = (argc >= 4) ? argv[3] : "";
  const std::string ghidra_root = (argc >= 5) ? argv[4] : "";

  auto client = ghidra::local({
      .ghidra_root = ghidra_root,
  });

  // --- Open via project path ---
  std::cout << "Opening project: " << gpr_path << "\n";

  ghidra::OpenRequest req;
  req.project_path = gpr_path;
  req.program_path = binary_path;
  auto open_result = client->OpenProgram(req);
  if (!open_result.ok()) {
    std::cerr << "Failed: " << open_result.status.message << "\n";
    return 1;
  }
  std::cout << "Binary loaded and project names applied.\n\n";

  // --- List functions ---
  auto funcs_result = client->ListFunctions(0, 0, 10000, 0);
  if (!funcs_result.ok()) {
    std::cerr << "ListFunctions failed: " << funcs_result.status.message << "\n";
    return 1;
  }
  auto& funcs = funcs_result.value->functions;
  std::cout << funcs.size() << " functions found.\n\n";

  if (!target_func.empty()) {
    // Find and decompile specific function
    auto it = std::find_if(funcs.begin(), funcs.end(),
                           [&](const ghidra::Function& f) { return f.name == target_func; });
    if (it == funcs.end()) {
      std::cerr << "Function '" << target_func << "' not found\n";
      return 1;
    }

    std::cout << "=== " << it->name << " @ 0x" << std::hex << it->entry_address
              << std::dec << " ===\n";
    auto d = client->GetDecompilation(it->entry_address, 30000);
    if (d.ok() && d.value->decompilation &&
        !d.value->decompilation->pseudocode.empty()) {
      std::cout << d.value->decompilation->pseudocode << "\n";
    } else {
      std::cerr << "Decompilation failed\n";
      return 1;
    }
  } else {
    // List all, decompile first 3
    for (const auto& f : funcs) {
      std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(8)
                << f.entry_address << std::dec << "  "
                << (f.name.empty() ? "(unnamed)" : f.name) << "\n";
    }

    int count = std::min(static_cast<int>(funcs.size()), 3);
    for (int i = 0; i < count; i++) {
      std::cout << "\n=== " << funcs[i].name << " @ 0x" << std::hex
                << funcs[i].entry_address << std::dec << " ===\n";
      auto d = client->GetDecompilation(funcs[i].entry_address, 30000);
      if (d.ok() && d.value->decompilation &&
          !d.value->decompilation->pseudocode.empty()) {
        std::cout << d.value->decompilation->pseudocode << "\n";
      } else {
        std::cerr << "  (failed)\n";
      }
    }
  }

  return 0;
}
