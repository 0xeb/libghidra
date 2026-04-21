// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// function_signatures: Signature inspection and mutation via the local backend.
//
// Usage: function_signatures <binary_path> [ghidra_root] [arch]
//
// Demonstrates: GetDecompilation (prerequisite), GetFunctionSignature,
//   ListFunctionSignatures, RenameFunctionParameter, SetFunctionParameterType,
//   RenameFunctionLocal, SetFunctionLocalType.
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
  uint64_t addr = funcs.value->functions[0].entry_address;
  std::cout << "Function: " << funcs.value->functions[0].name
            << " @ 0x" << std::hex << addr << "\n";

  // Decompile to populate signature data
  auto decomp = client->GetDecompilation(addr, 30000);
  if (!decomp.ok()) {
    std::cerr << "Decompilation failed: " << decomp.status.message << "\n";
    return 1;
  }
  std::cout << "Decompilation: OK\n\n";

  // --- Get function signature ---
  auto sig = client->GetFunctionSignature(addr);
  if (sig.ok() && sig.value->signature) {
    const auto& s = *sig.value->signature;
    std::cout << "Signature:\n";
    std::cout << "  Prototype:   " << s.prototype << "\n";
    std::cout << "  Return type: " << s.return_type << "\n";
    std::cout << "  Convention:  " << s.calling_convention << "\n";
    std::cout << "  Var args:    " << (s.has_var_args ? "yes" : "no") << "\n";
    std::cout << "  Parameters (" << s.parameters.size() << "):\n";
    for (const auto& p : s.parameters) {
      std::cout << "    [" << p.ordinal << "] " << p.data_type << " " << p.name;
      if (p.is_auto_parameter) std::cout << " (auto)";
      std::cout << "\n";
    }
  }

  // --- List all function signatures ---
  auto sigs = client->ListFunctionSignatures(0, UINT64_MAX, 10, 0);
  if (sigs.ok()) {
    std::cout << "\nAll signatures (first " << sigs.value->signatures.size() << "):\n";
    for (const auto& s : sigs.value->signatures) {
      std::cout << "  0x" << std::hex << s.function_entry_address << "  "
                << s.prototype << "\n";
    }
  }

  // --- Mutate parameter (if function has params) ---
  if (sig.ok() && sig.value->signature &&
      !sig.value->signature->parameters.empty()) {
    auto rp = client->RenameFunctionParameter(addr, 0, "arg_first");
    std::cout << "\nRenameFunctionParameter(0, arg_first): "
              << (rp.ok() ? "OK" : rp.status.message) << "\n";

    auto st = client->SetFunctionParameterType(addr, 0, "uint");
    std::cout << "SetFunctionParameterType(0, uint): "
              << (st.ok() ? "OK" : st.status.message) << "\n";
  }

  // --- Re-decompile to show effect ---
  auto decomp2 = client->GetDecompilation(addr, 30000);
  if (decomp2.ok() && decomp2.value->decompilation) {
    std::cout << "\nDecompilation after mutation:\n"
              << decomp2.value->decompilation->pseudocode;
  }

  return 0;
}
