// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// disassemble: Instruction disassembly via the local backend.
//
// Usage: disassemble <binary_path> [ghidra_root] [arch]
//
// Demonstrates: ListFunctions, GetInstruction, ListInstructions.
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

  // Find the first function
  auto funcs = client->ListFunctions(0, UINT64_MAX, 1, 0);
  if (!funcs.ok() || funcs.value->functions.empty()) {
    std::cerr << "No functions found.\n";
    return 1;
  }

  const auto& func = funcs.value->functions[0];
  std::cout << "Function: " << func.name
            << " @ 0x" << std::hex << func.entry_address << "\n\n";

  // Single instruction at entry point
  auto single = client->GetInstruction(func.entry_address);
  if (single.ok() && single.value->instruction) {
    const auto& insn = *single.value->instruction;
    std::cout << "Entry instruction: " << insn.disassembly
              << " (" << std::dec << insn.length << " bytes)\n\n";
  }

  // Disassemble all instructions in the function's range
  auto instrs = client->ListInstructions(func.start_address, func.end_address, 0, 0);
  if (!instrs.ok()) {
    std::cerr << "ListInstructions failed: " << instrs.status.message << "\n";
    return 1;
  }

  std::cout << "Instructions (" << instrs.value->instructions.size() << "):\n";
  std::cout << std::left << std::setw(18) << "ADDRESS"
            << std::setw(12) << "MNEMONIC"
            << std::setw(30) << "OPERANDS"
            << "LEN\n";
  std::cout << std::string(64, '-') << "\n";

  for (const auto& i : instrs.value->instructions) {
    std::cout << "0x" << std::hex << std::setfill('0') << std::setw(12) << i.address
              << "    " << std::setfill(' ') << std::left
              << std::setw(12) << i.mnemonic
              << std::setw(30) << i.operand_text
              << std::dec << i.length << "\n";
  }

  return 0;
}
