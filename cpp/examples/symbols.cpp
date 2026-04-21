// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// symbols: Symbol table operations via the local backend.
//
// Usage: symbols <binary_path> [ghidra_root] [arch]
//
// Demonstrates: ListSymbols, GetSymbol, RenameSymbol, DeleteSymbol.
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

  // --- List symbols ---
  auto syms = client->ListSymbols(0, UINT64_MAX, 20, 0);
  if (!syms.ok()) {
    std::cerr << "ListSymbols failed: " << syms.status.message << "\n";
    return 1;
  }

  std::cout << "Symbols (first " << syms.value->symbols.size() << "):\n";
  std::cout << std::left << std::setw(18) << "ADDRESS"
            << std::setw(30) << "NAME"
            << std::setw(12) << "TYPE"
            << "PRIMARY\n";
  std::cout << std::string(66, '-') << "\n";

  for (const auto& s : syms.value->symbols) {
    std::cout << "0x" << std::hex << std::setfill('0') << std::setw(12) << s.address
              << "    " << std::setfill(' ') << std::left
              << std::setw(30) << s.name
              << std::setw(12) << s.type
              << (s.is_primary ? "yes" : "no") << "\n";
  }

  if (syms.value->symbols.empty()) {
    std::cout << "No symbols found.\n";
    return 0;
  }

  // --- Get a specific symbol ---
  uint64_t sym_addr = syms.value->symbols[0].address;
  auto get = client->GetSymbol(sym_addr);
  if (get.ok() && get.value->symbol) {
    std::cout << "\nGetSymbol(0x" << std::hex << sym_addr << "): "
              << get.value->symbol->name << " [" << get.value->symbol->type << "]\n";
  }

  // --- Rename a symbol ---
  auto ren = client->RenameSymbol(sym_addr, "renamed_symbol");
  std::cout << "\nRenameSymbol: " << (ren.ok() ? "OK" : ren.status.message) << "\n";

  // Verify rename
  auto get2 = client->GetSymbol(sym_addr);
  if (get2.ok() && get2.value->symbol) {
    std::cout << "After rename: " << get2.value->symbol->name << "\n";
  }

  // --- Delete a symbol ---
  auto del = client->DeleteSymbol(sym_addr, "renamed_symbol");
  std::cout << "\nDeleteSymbol: " << (del.ok() ? "OK" : del.status.message) << "\n";

  return 0;
}
