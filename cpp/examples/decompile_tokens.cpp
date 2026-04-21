// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// decompile_tokens: Structured analysis of decompilation token streams.
//
// Usage: decompile_tokens <binary_path> [ghidra_root] [arch]
//
// Demonstrates: GetDecompilation (token-level analysis) for reconstructing
// source lines, inspecting call sites, and mapping locals from the token stream.
//
// Reconstructs source lines, finds function calls, maps variables, lists
// type references, and performs token-level search — all from the token stream.
//
// If ghidra_root is omitted, uses embedded processor specs (no Ghidra needed).

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

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
  std::cout << "Loaded: " << open_result.value->program_name << "\n";

  // Find first non-trivial function
  auto funcs = client->ListFunctions(0, UINT64_MAX, 20, 0);
  if (!funcs.ok() || funcs.value->functions.empty()) {
    std::cerr << "No functions found.\n";
    return 1;
  }

  const libghidra::client::FunctionRecord* target = nullptr;
  for (const auto& f : funcs.value->functions) {
    if (f.size > 64) { target = &f; break; }
  }
  if (!target) target = &funcs.value->functions[0];

  std::cout << "Function: " << target->name
            << " @ 0x" << std::hex << target->entry_address << std::dec
            << " (" << target->size << " bytes)\n";

  // Decompile
  auto decomp = client->GetDecompilation(target->entry_address, 30000);
  if (!decomp.ok() || !decomp.value->decompilation) {
    std::cerr << "Decompilation failed: "
              << (decomp.ok() ? "no result" : decomp.status.message) << "\n";
    return 1;
  }

  const auto& d = *decomp.value->decompilation;
  const auto& tokens = d.tokens;
  const auto& locals = d.locals;

  std::cout << "\nDecompiled " << target->name << ": "
            << tokens.size() << " tokens, "
            << locals.size() << " locals\n";

  // ========================================================================
  // 1. Reconstruct source lines
  // ========================================================================
  std::cout << "\n=== Reconstructed source ===\n";
  std::map<int, std::string> lines;
  for (const auto& tok : tokens) {
    lines[tok.line_number] += tok.text;
  }
  for (const auto& [line_num, text] : lines) {
    std::cout << std::setw(4) << line_num << " | " << text << "\n";
  }

  // ========================================================================
  // 2. Function calls (kind == Function)
  // ========================================================================
  std::cout << "\n=== Function calls (ctree_v_calls equivalent) ===\n";
  std::map<std::string, int> call_counts;
  for (const auto& tok : tokens) {
    if (tok.kind == libghidra::client::DecompileTokenKind::kFunction) {
      call_counts[tok.text]++;
    }
  }
  if (call_counts.empty()) {
    std::cout << "  (no function call tokens)\n";
  }
  for (const auto& [name, count] : call_counts) {
    std::cout << "  " << std::left << std::setw(30) << name
              << count << " reference(s)\n";
  }

  // ========================================================================
  // 3. Variable map (kind == Variable | Parameter)
  // ========================================================================
  std::cout << "\n=== Variable map (ctree_lvars equivalent) ===\n";
  struct VarInfo {
    int ref_count = 0;
    std::string var_type;
    std::string var_storage;
    std::string token_kind;
  };
  std::map<std::string, VarInfo> var_map;
  for (const auto& tok : tokens) {
    if (tok.kind == libghidra::client::DecompileTokenKind::kVariable ||
        tok.kind == libghidra::client::DecompileTokenKind::kParameter) {
      auto& info = var_map[tok.var_name.empty() ? tok.text : tok.var_name];
      info.ref_count++;
      if (!tok.var_type.empty()) info.var_type = tok.var_type;
      if (!tok.var_storage.empty()) info.var_storage = tok.var_storage;
      info.token_kind = token_kind_name(tok.kind);
    }
  }
  std::cout << std::left
            << std::setw(20) << "  NAME"
            << std::setw(8) << "REFS"
            << std::setw(10) << "ROLE"
            << std::setw(20) << "TYPE"
            << "STORAGE\n";
  std::cout << "  " << std::string(70, '-') << "\n";
  for (const auto& [name, info] : var_map) {
    std::cout << "  " << std::setw(18) << name
              << std::setw(8) << info.ref_count
              << std::setw(10) << info.token_kind
              << std::setw(20) << (info.var_type.empty() ? "-" : info.var_type)
              << (info.var_storage.empty() ? "-" : info.var_storage) << "\n";
  }

  // Cross-reference with locals
  std::cout << "\n  Locals from decompilation (" << locals.size() << "):\n";
  for (const auto& local : locals) {
    bool in_tokens = var_map.count(local.name) > 0;
    std::cout << "    " << std::setw(18) << local.name
              << "type=" << std::setw(16) << local.data_type
              << "storage=" << std::setw(12) << local.storage
              << (in_tokens ? "[in tokens]" : "[not in tokens]") << "\n";
  }

  // ========================================================================
  // 4. Type references (kind == Type)
  // ========================================================================
  std::cout << "\n=== Type references ===\n";
  std::set<std::string> type_refs;
  for (const auto& tok : tokens) {
    if (tok.kind == libghidra::client::DecompileTokenKind::kType) {
      type_refs.insert(tok.text);
    }
  }
  if (type_refs.empty()) {
    std::cout << "  (no type tokens)\n";
  }
  for (const auto& t : type_refs) {
    std::cout << "  " << t << "\n";
  }

  // ========================================================================
  // 5. Token kind distribution
  // ========================================================================
  std::cout << "\n=== Token kind distribution ===\n";
  std::map<std::string, int> kind_counts;
  for (const auto& tok : tokens) {
    kind_counts[token_kind_name(tok.kind)]++;
  }
  for (const auto& [kind, count] : kind_counts) {
    std::cout << "  " << std::left << std::setw(14) << kind << count << "\n";
  }

  // ========================================================================
  // 6. Token search (search for "return" keyword with line context)
  // ========================================================================
  std::string pattern = "return";
  if (!var_map.empty()) {
    pattern = var_map.begin()->first;  // search for first variable name
  }
  std::cout << "\n=== Token search for \"" << pattern << "\" ===\n";
  for (const auto& tok : tokens) {
    if (tok.text.find(pattern) != std::string::npos) {
      std::cout << "  line " << std::setw(3) << tok.line_number
                << " col " << std::setw(3) << tok.column_offset
                << "  [" << std::setw(10) << token_kind_name(tok.kind) << "]"
                << "  \"" << tok.text << "\"";
      // Show line context
      auto it = lines.find(tok.line_number);
      if (it != lines.end()) {
        std::cout << "  -->  " << it->second;
      }
      std::cout << "\n";
    }
  }

  // ========================================================================
  // Summary
  // ========================================================================
  std::cout << "\n=== Summary ===\n";
  std::cout << "  Function:       " << target->name << "\n";
  std::cout << "  Total tokens:   " << tokens.size() << "\n";
  std::cout << "  Source lines:   " << lines.size() << "\n";
  std::cout << "  Callees:        " << call_counts.size() << "\n";
  std::cout << "  Variables:      " << var_map.size() << "\n";
  std::cout << "  Types used:     " << type_refs.size() << "\n";
  std::cout << "  Locals:         " << locals.size() << "\n";

  return 0;
}
