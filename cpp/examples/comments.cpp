// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// comments: Comment CRUD operations via the local backend.
//
// Usage: comments <binary_path> [ghidra_root] [arch]
//
// Demonstrates: SetComment, GetComments, DeleteComment with all CommentKind values.
//
// If ghidra_root is omitted, uses embedded processor specs (no Ghidra needed).

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "libghidra/ghidra.hpp"

static const char* kind_name(ghidra::CommentKind k) {
  switch (k) {
    case ghidra::CommentKind::kEol:        return "EOL";
    case ghidra::CommentKind::kPre:        return "PRE";
    case ghidra::CommentKind::kPost:       return "POST";
    case ghidra::CommentKind::kPlate:      return "PLATE";
    case ghidra::CommentKind::kRepeatable: return "REPEATABLE";
    default:                               return "?";
  }
}

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

  // Find first function to get a valid address
  auto funcs = client->ListFunctions(0, UINT64_MAX, 1, 0);
  if (!funcs.ok() || funcs.value->functions.empty()) {
    std::cerr << "No functions found.\n";
    return 1;
  }
  uint64_t addr = funcs.value->functions[0].entry_address;
  std::cout << "Target address: 0x" << std::hex << addr << "\n\n";

  // --- Set comments of each kind ---
  struct { ghidra::CommentKind kind; const char* text; } comments[] = {
    {ghidra::CommentKind::kEol,   "End-of-line comment"},
    {ghidra::CommentKind::kPre,   "Pre-instruction comment"},
    {ghidra::CommentKind::kPost,  "Post-instruction comment"},
    {ghidra::CommentKind::kPlate, "Function plate comment"},
  };

  for (const auto& c : comments) {
    auto r = client->SetComment(addr, c.kind, c.text);
    std::cout << "SetComment(" << kind_name(c.kind) << "): "
              << (r.ok() ? "OK" : r.status.message) << "\n";
  }

  // --- List all comments ---
  auto list = client->GetComments(addr, addr + 1, 0, 0);
  if (list.ok()) {
    std::cout << "\nComments at 0x" << std::hex << addr << " ("
              << std::dec << list.value->comments.size() << "):\n";
    for (const auto& c : list.value->comments) {
      std::cout << "  [" << kind_name(c.kind) << "] " << c.text << "\n";
    }
  }

  // --- Delete one comment ---
  auto del = client->DeleteComment(addr, ghidra::CommentKind::kPost);
  std::cout << "\nDeleteComment(POST): " << (del.ok() ? "OK" : del.status.message) << "\n";

  // --- List again to confirm deletion ---
  auto list2 = client->GetComments(addr, addr + 1, 0, 0);
  if (list2.ok()) {
    std::cout << "\nComments after deletion ("
              << list2.value->comments.size() << "):\n";
    for (const auto& c : list2.value->comments) {
      std::cout << "  [" << kind_name(c.kind) << "] " << c.text << "\n";
    }
  }

  return 0;
}
