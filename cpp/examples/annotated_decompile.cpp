// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// annotated_decompile: Full-workflow demonstration of the libghidra local backend.
//
// Exercises: CreateType (structs), CreateTypeEnum (enums), RenameFunction,
// SetFunctionSignature, SaveProgram, restore via re-OpenProgram.
//
// Usage: annotated_decompile <binary> [ghidra_root] [arch]

#include <cstdlib>
#include <iostream>
#include <string>

#include "libghidra/ghidra.hpp"

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <binary> [ghidra_root] [arch]\n";
    return 1;
  }

  const std::string binary_path = argv[1];
  const std::string ghidra_root = (argc >= 3) ? argv[2] : "";
  const std::string arch_id = (argc >= 4) ? argv[3] : "";
  const std::string state_path = binary_path + ".ghidra_state.xml";

  auto client = ghidra::local({
      .ghidra_root = ghidra_root,
      .state_path = state_path,
      .default_arch = arch_id,
  });

  // --- Open binary ---
  ghidra::OpenRequest req;
  req.program_path = binary_path;
  auto open_result = client->OpenProgram(req);
  if (!open_result.ok()) {
    std::cerr << "Error loading binary: " << open_result.status.message << "\n";
    return 1;
  }
  std::cout << "Loaded: " << binary_path << "\n";

  // --- Create a struct type ---
  auto cr = client->CreateType("packet_t", "struct", 268);
  std::cout << "CreateType(packet_t): " << (cr.ok() ? "OK" : cr.status.message) << "\n";

  // --- Create an enum type ---
  auto er = client->CreateTypeEnum("status_t", 4, false);
  std::cout << "CreateTypeEnum(status_t): " << (er.ok() ? "OK" : er.status.message)
            << "\n";

  // --- Name functions ---
  auto n1 = client->RenameFunction(0x1000, "process_packet");
  std::cout << "RenameFunction(0x1000, process_packet): "
            << (n1.ok() ? "OK" : n1.status.message) << "\n";

  auto n2 = client->RenameFunction(0x2000, "validate_checksum");
  std::cout << "RenameFunction(0x2000, validate_checksum): "
            << (n2.ok() ? "OK" : n2.status.message) << "\n";

  // --- Set function prototype ---
  auto sp = client->SetFunctionSignature(0x1000, "int process_packet(int flags)");
  std::cout << "SetFunctionSignature(0x1000): "
            << (sp.ok() ? "OK" : sp.status.message) << "\n";

  // --- Decompile with annotations ---
  std::cout << "\n// ========== process_packet @ 0x1000 ==========\n";
  auto decomp = client->GetDecompilation(0x1000, 30000);
  if (decomp.ok() && decomp.value->decompilation &&
      !decomp.value->decompilation->pseudocode.empty()) {
    std::cout << decomp.value->decompilation->pseudocode;
  } else {
    std::cerr << "Decompile failed\n";
  }

  // --- Save state ---
  auto save = client->SaveProgram();
  std::cout << "\nSaveProgram: " << (save.ok() ? "OK" : save.status.message) << "\n";

  // --- Check capabilities ---
  auto caps = client->GetCapabilities();
  if (caps.ok()) {
    std::cout << "\nCapabilities:\n";
    for (const auto& c : *caps.value) {
      std::cout << "  " << c.id << ": " << c.status;
      if (!c.note.empty()) std::cout << " (" << c.note << ")";
      std::cout << "\n";
    }
  }

  // --- Restore state on a fresh instance ---
  auto client2 = ghidra::local({
      .ghidra_root = ghidra_root,
      .state_path = state_path,
      .default_arch = arch_id,
  });

  ghidra::OpenRequest req2;
  req2.program_path = binary_path;
  auto open2 = client2->OpenProgram(req2);
  std::cout << "\nRestore: " << (open2.ok() ? "OK" : open2.status.message) << "\n";

  if (open2.ok()) {
    std::cout << "\n// ========== Restored: process_packet @ 0x1000 ==========\n";
    auto d2 = client2->GetDecompilation(0x1000, 30000);
    if (d2.ok() && d2.value->decompilation &&
        !d2.value->decompilation->pseudocode.empty()) {
      std::cout << d2.value->decompilation->pseudocode;
    } else {
      std::cerr << "Decompile after restore failed\n";
    }
  }

  std::cout << "\nDone.\n";
  return 0;
}
