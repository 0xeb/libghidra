// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// session_lifecycle: Session management via the local backend.
//
// Usage: session_lifecycle <binary_path> [ghidra_root] [arch]
//
// Demonstrates: GetStatus, GetCapabilities, GetRevision, RenameFunction,
//   SaveProgram, DiscardProgram, CloseProgram, re-OpenProgram.
//
// If ghidra_root is omitted, uses embedded processor specs (no Ghidra needed).

#include <cstdint>
#include <cstdlib>
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
  const std::string state_path = binary_path + ".ghidra_state.xml";

  auto client = ghidra::local({
      .ghidra_root = ghidra_root,
      .state_path = state_path,
      .default_arch = arch,
  });

  // --- Open binary ---
  ghidra::OpenRequest req;
  req.program_path = binary_path;
  auto open_result = client->OpenProgram(req);
  if (!open_result.ok()) {
    std::cerr << "Failed to load binary: " << open_result.status.message << "\n";
    return 1;
  }
  std::cout << "Loaded: " << open_result.value->program_name << "\n";
  std::cout << "Language: " << open_result.value->language_id << "\n";
  std::cout << "Compiler: " << open_result.value->compiler_spec << "\n\n";

  // --- GetStatus ---
  auto status = client->GetStatus();
  if (status.ok()) {
    std::cout << "Status:\n";
    std::cout << "  Service: " << status.value->service_name << "\n";
    std::cout << "  Version: " << status.value->service_version << "\n";
    std::cout << "  Mode:    " << status.value->host_mode << "\n";
  }

  // --- GetCapabilities ---
  auto caps = client->GetCapabilities();
  if (caps.ok()) {
    std::cout << "\nCapabilities (" << caps.value->size() << "):\n";
    int shown = 0;
    for (const auto& c : *caps.value) {
      std::cout << "  " << c.id << ": " << c.status;
      if (!c.note.empty()) std::cout << " (" << c.note << ")";
      std::cout << "\n";
      if (++shown >= 10) {
        std::cout << "  ... and " << (caps.value->size() - 10) << " more\n";
        break;
      }
    }
  }

  // --- GetRevision ---
  auto rev1 = client->GetRevision();
  if (rev1.ok()) {
    std::cout << "\nRevision: " << rev1.value->revision << "\n";
  }

  // --- Make a mutation, check revision increments ---
  auto rename = client->RenameFunction(open_result.value->image_base, "entry_renamed");
  std::cout << "RenameFunction: " << (rename.ok() ? "OK" : rename.status.message) << "\n";

  auto rev2 = client->GetRevision();
  if (rev2.ok()) {
    std::cout << "Revision after mutation: " << rev2.value->revision << "\n";
  }

  // --- Save state ---
  auto save = client->SaveProgram();
  std::cout << "\nSaveProgram: " << (save.ok() ? "OK" : save.status.message) << "\n";

  // --- Close program ---
  auto close = client->CloseProgram(ghidra::ShutdownPolicy::kSave);
  std::cout << "CloseProgram: " << (close.ok() ? "OK" : close.status.message) << "\n";

  // --- Re-open on a fresh client to verify persistence ---
  auto client2 = ghidra::local({
      .ghidra_root = ghidra_root,
      .state_path = state_path,
      .default_arch = arch,
  });

  ghidra::OpenRequest req2;
  req2.program_path = binary_path;
  auto open2 = client2->OpenProgram(req2);
  std::cout << "\nRestore: " << (open2.ok() ? "OK" : open2.status.message) << "\n";

  if (open2.ok()) {
    auto rev3 = client2->GetRevision();
    if (rev3.ok()) {
      std::cout << "Restored revision: " << rev3.value->revision << "\n";
    }
  }

  // --- Discard changes ---
  auto discard = client2->DiscardProgram();
  std::cout << "DiscardProgram: " << (discard.ok() ? "OK" : discard.status.message) << "\n";

  std::cout << "\nDone.\n";
  return 0;
}
