// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// structural_analysis: Switch tables, dominators, loops, and decompile tokens
// via the local backend.
//
// Usage: structural_analysis <binary_path> [ghidra_root] [arch]
//
// Demonstrates: ListSwitchTables, ListDominators, ListPostDominators,
//               ListLoops, GetDecompilation (token summary).
//
// If ghidra_root is omitted, uses embedded processor specs (no Ghidra needed).

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>

#include "libghidra/ghidra.hpp"

static const char* token_kind_name(libghidra::client::DecompileTokenKind kind) {
  switch (kind) {
    case libghidra::client::DecompileTokenKind::kKeyword:   return "keyword";
    case libghidra::client::DecompileTokenKind::kComment:   return "comment";
    case libghidra::client::DecompileTokenKind::kType:      return "type";
    case libghidra::client::DecompileTokenKind::kFunction:  return "function";
    case libghidra::client::DecompileTokenKind::kVariable:  return "variable";
    case libghidra::client::DecompileTokenKind::kConst:     return "const";
    case libghidra::client::DecompileTokenKind::kParameter: return "parameter";
    case libghidra::client::DecompileTokenKind::kGlobal:    return "global";
    case libghidra::client::DecompileTokenKind::kDefault:   return "default";
    case libghidra::client::DecompileTokenKind::kError:     return "error";
    case libghidra::client::DecompileTokenKind::kSpecial:   return "special";
    default: return "unspecified";
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

  // Find first function
  auto funcs = client->ListFunctions(0, UINT64_MAX, 1, 0);
  if (!funcs.ok() || funcs.value->functions.empty()) {
    std::cerr << "No functions found.\n";
    return 1;
  }

  const auto& func = funcs.value->functions[0];
  std::cout << "Function: " << func.name
            << " @ 0x" << std::hex << func.entry_address
            << " (0x" << func.start_address << " - 0x" << func.end_address << ")\n\n";

  // --- Switch tables ---
  auto switches = client->ListSwitchTables(func.start_address, func.end_address, 0, 0);
  if (!switches.ok()) {
    std::cerr << "ListSwitchTables failed: " << switches.status.message << "\n";
    return 1;
  }

  std::cout << "Switch tables (" << std::dec << switches.value->switch_tables.size() << "):\n";
  if (switches.value->switch_tables.empty()) {
    std::cout << "  (none)\n";
  }
  for (const auto& st : switches.value->switch_tables) {
    std::cout << "  switch @ 0x" << std::hex << st.switch_address
              << "  cases=" << std::dec << st.case_count
              << "  default=0x" << std::hex << st.default_address << "\n";
    for (const auto& c : st.cases) {
      std::cout << "    case " << std::dec << c.value
                << " -> 0x" << std::hex << c.target_address << "\n";
    }
  }

  // --- Dominators ---
  auto doms = client->ListDominators(func.start_address, func.end_address, 0, 0);
  if (!doms.ok()) {
    std::cerr << "\nListDominators failed: " << doms.status.message << "\n";
    return 1;
  }

  std::cout << "\nDominators (" << std::dec << doms.value->dominators.size() << "):\n";
  std::cout << std::left
            << std::setw(18) << "  BLOCK"
            << std::setw(18) << "IDOM"
            << std::setw(8) << "DEPTH"
            << "ENTRY?\n";
  std::cout << "  " << std::string(50, '-') << "\n";

  for (const auto& d : doms.value->dominators) {
    std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(12) << d.block_address
              << "  0x" << std::setw(12) << d.idom_address
              << "  " << std::setfill(' ') << std::dec
              << std::setw(6) << d.depth
              << "  " << (d.is_entry ? "yes" : "no") << "\n";
  }

  // --- Post-dominators ---
  auto pdoms = client->ListPostDominators(func.start_address, func.end_address, 0, 0);
  if (!pdoms.ok()) {
    std::cerr << "\nListPostDominators failed: " << pdoms.status.message << "\n";
    return 1;
  }

  std::cout << "\nPost-dominators (" << std::dec << pdoms.value->post_dominators.size() << "):\n";
  std::cout << std::left
            << std::setw(18) << "  BLOCK"
            << std::setw(18) << "IPDOM"
            << std::setw(8) << "DEPTH"
            << "EXIT?\n";
  std::cout << "  " << std::string(50, '-') << "\n";

  for (const auto& pd : pdoms.value->post_dominators) {
    std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(12) << pd.block_address
              << "  0x" << std::setw(12) << pd.ipdom_address
              << "  " << std::setfill(' ') << std::dec
              << std::setw(6) << pd.depth
              << "  " << (pd.is_exit ? "yes" : "no") << "\n";
  }

  // --- Loops ---
  auto loops = client->ListLoops(func.start_address, func.end_address, 0, 0);
  if (!loops.ok()) {
    std::cerr << "\nListLoops failed: " << loops.status.message << "\n";
    return 1;
  }

  std::cout << "\nLoops (" << std::dec << loops.value->loops.size() << "):\n";
  if (loops.value->loops.empty()) {
    std::cout << "  (none)\n";
  }
  std::cout << std::left
            << std::setw(18) << "  HEADER"
            << std::setw(18) << "BACK-EDGE"
            << std::setw(10) << "KIND"
            << std::setw(8) << "BLOCKS"
            << "DEPTH\n";
  if (!loops.value->loops.empty()) {
    std::cout << "  " << std::string(60, '-') << "\n";
  }

  for (const auto& lp : loops.value->loops) {
    std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(12) << lp.header_address
              << "  0x" << std::setw(12) << lp.back_edge_source
              << "  " << std::setfill(' ') << std::left
              << std::setw(8) << lp.loop_kind
              << "  " << std::dec << std::setw(6) << lp.block_count
              << "  " << lp.depth << "\n";
  }

  // --- Decompile tokens ---
  auto decomp = client->GetDecompilation(func.entry_address, 30000);
  if (!decomp.ok()) {
    std::cerr << "\nGetDecompilation failed: " << decomp.status.message << "\n";
    return 1;
  }

  if (!decomp.value->decompilation) {
    std::cerr << "\nNo decompilation result.\n";
    return 1;
  }

  const auto& d = *decomp.value->decompilation;
  std::cout << "\nDecompilation tokens (" << std::dec << d.tokens.size() << " total):\n";

  // Summarize by kind
  std::map<std::string, int> kind_counts;
  for (const auto& tok : d.tokens) {
    kind_counts[token_kind_name(tok.kind)]++;
  }
  for (const auto& [kind, count] : kind_counts) {
    std::cout << "  " << std::left << std::setw(14) << kind << count << "\n";
  }

  // Show first 20 tokens as a sample
  int limit = std::min(static_cast<int>(d.tokens.size()), 20);
  std::cout << "\nFirst " << limit << " tokens:\n";
  std::cout << std::left
            << std::setw(6) << "  LINE"
            << std::setw(6) << "COL"
            << std::setw(14) << "KIND"
            << "TEXT\n";
  std::cout << "  " << std::string(40, '-') << "\n";

  for (int i = 0; i < limit; ++i) {
    const auto& tok = d.tokens[i];
    std::cout << "  " << std::setw(4) << tok.line_number
              << "  " << std::setw(4) << tok.column_offset
              << "  " << std::setw(12) << token_kind_name(tok.kind)
              << "  " << tok.text << "\n";
  }

  // --- Summary ---
  std::cout << "\nSummary: "
            << switches.value->switch_tables.size() << " switch tables, "
            << doms.value->dominators.size() << " dominators, "
            << pdoms.value->post_dominators.size() << " post-dominators, "
            << loops.value->loops.size() << " loops, "
            << d.tokens.size() << " tokens\n";

  return 0;
}
