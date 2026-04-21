// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// data_items: Data item operations via the local backend.
//
// Usage: data_items <binary_path> [ghidra_root] [arch]
//
// Demonstrates: ApplyDataType, ListDataItems, RenameDataItem, DeleteDataItem.
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

  // Pick an address from the first memory block
  auto blocks = client->ListMemoryBlocks(1, 0);
  if (!blocks.ok() || blocks.value->blocks.empty()) {
    std::cerr << "No memory blocks.\n";
    return 1;
  }
  uint64_t addr = blocks.value->blocks[0].start_address;

  // --- Apply a data type to create a data item ---
  auto apply = client->ApplyDataType(addr, "int");
  std::cout << "ApplyDataType(int @ 0x" << std::hex << addr << "): "
            << (apply.ok() ? "OK" : apply.status.message) << "\n";

  // --- List data items in range ---
  auto items = client->ListDataItems(addr, addr + 64, 0, 0);
  if (items.ok()) {
    std::cout << "\nData items (" << std::dec << items.value->data_items.size() << "):\n";
    for (const auto& d : items.value->data_items) {
      std::cout << "  0x" << std::hex << d.address
                << "  " << d.name
                << "  type=" << d.data_type
                << "  size=" << std::dec << d.size << "\n";
    }
  }

  // --- Rename the data item ---
  auto ren = client->RenameDataItem(addr, "my_variable");
  std::cout << "\nRenameDataItem: " << (ren.ok() ? "OK" : ren.status.message) << "\n";

  // --- Delete the data item ---
  auto del = client->DeleteDataItem(addr);
  std::cout << "DeleteDataItem: " << (del.ok() ? "OK" : del.status.message) << "\n";

  // --- Confirm deletion ---
  auto items2 = client->ListDataItems(addr, addr + 64, 0, 0);
  if (items2.ok()) {
    std::cout << "\nData items after deletion: "
              << items2.value->data_items.size() << "\n";
  }

  return 0;
}
