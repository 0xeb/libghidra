// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// memory_ops: Memory read, write, and patch operations via the local backend.
//
// Usage: memory_ops <binary_path> [ghidra_root] [arch]
//
// Demonstrates: ListMemoryBlocks, ReadBytes, WriteBytes, PatchBytesBatch.
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

  // --- List memory blocks ---
  auto blocks = client->ListMemoryBlocks(0, 0);
  if (!blocks.ok()) {
    std::cerr << "ListMemoryBlocks failed: " << blocks.status.message << "\n";
    return 1;
  }

  std::cout << "Memory blocks (" << blocks.value->blocks.size() << "):\n";
  for (const auto& b : blocks.value->blocks) {
    std::cout << "  " << b.name
              << "  0x" << std::hex << b.start_address
              << " - 0x" << b.end_address
              << "  size=" << std::dec << b.size
              << "  " << (b.is_read ? "R" : "-")
              << (b.is_write ? "W" : "-")
              << (b.is_execute ? "X" : "-") << "\n";
  }

  if (blocks.value->blocks.empty()) {
    std::cout << "No memory blocks found.\n";
    return 0;
  }

  uint64_t base = blocks.value->blocks[0].start_address;

  // --- Read bytes ---
  auto read = client->ReadBytes(base, 32);
  if (!read.ok()) {
    std::cerr << "ReadBytes failed: " << read.status.message << "\n";
    return 1;
  }

  std::cout << "\nFirst 32 bytes at 0x" << std::hex << base << ":\n  ";
  for (auto b : read.value->data) {
    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)b << " ";
  }
  std::cout << "\n";

  // --- Write bytes (CoW overlay) ---
  std::vector<uint8_t> patch_data = {0xDE, 0xAD, 0xBE, 0xEF};
  auto write = client->WriteBytes(base, patch_data);
  if (!write.ok()) {
    std::cerr << "WriteBytes failed: " << write.status.message << "\n";
    return 1;
  }
  std::cout << "\nWriteBytes: wrote " << std::dec << write.value->bytes_written
            << " bytes at 0x" << std::hex << base << "\n";

  // Read back to verify
  auto verify = client->ReadBytes(base, 4);
  if (verify.ok()) {
    std::cout << "Read-back: ";
    for (auto b : verify.value->data)
      std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)b << " ";
    std::cout << "\n";
  }

  // --- Batch patch ---
  libghidra::client::BytePatch p1{base + 8, {0x41, 0x42}};
  libghidra::client::BytePatch p2{base + 16, {0x43, 0x44}};
  auto batch = client->PatchBytesBatch({p1, p2});
  if (!batch.ok()) {
    std::cerr << "PatchBytesBatch failed: " << batch.status.message << "\n";
    return 1;
  }
  std::cout << "\nPatchBytesBatch: " << std::dec << batch.value->patch_count
            << " patches, " << batch.value->bytes_written << " bytes\n";

  // Read back patched region
  auto final_read = client->ReadBytes(base, 32);
  if (final_read.ok()) {
    std::cout << "Final 32 bytes:\n  ";
    for (auto b : final_read.value->data)
      std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)b << " ";
    std::cout << "\n";
  }

  return 0;
}
