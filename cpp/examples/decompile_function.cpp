// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// decompile_function: Minimal decompilation via the libghidra IClient interface.
//
// Usage: decompile_function <binary_path> <hex_address> [ghidra_root] [arch]
//
// Demonstrates: CreateLocalClient -> OpenProgram -> GetDecompilation -> print.
//
// If ghidra_root is omitted, uses embedded processor specs (no Ghidra needed).

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "libghidra/ghidra.hpp"

int main(int argc, char* argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0]
              << " <binary_path> <hex_address> [ghidra_root] [arch]\n";
    return 1;
  }

  const std::string binary_path = argv[1];
  const uint64_t address = std::strtoull(argv[2], nullptr, 16);
  const std::string ghidra_root = (argc >= 4) ? argv[3] : "";
  const std::string arch = (argc >= 5) ? argv[4] : "";

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

  // Decompile
  auto decomp = client->GetDecompilation(address, 30000);
  if (!decomp.ok() || !decomp.value->decompilation ||
      decomp.value->decompilation->pseudocode.empty()) {
    std::string err = decomp.ok() && decomp.value->decompilation
                          ? decomp.value->decompilation->error_message
                          : decomp.status.message;
    std::cerr << "Decompilation failed: " << err << "\n";
    return 1;
  }

  std::cout << decomp.value->decompilation->pseudocode;
  return 0;
}
