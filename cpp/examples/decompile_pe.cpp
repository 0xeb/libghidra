// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// decompile_pe: PE-aware batch decompilation via the libghidra IClient.
//
// 1. Parses PE headers to find .text section
// 2. Parses MSVC MAP file to discover function names + RVAs
// 3. Opens binary via IClient, names functions, batch decompiles
//
// Usage: decompile_pe <pe_file> <map_file> [obj_filter] [ghidra_root]

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "libghidra/ghidra.hpp"
#include "pe_info.h"

struct MapFunction {
  std::string name;
  uint64_t rvaBase;
};

static std::vector<MapFunction> parseMapFile(const std::string& path,
                                             const std::string& objFilter) {
  std::vector<MapFunction> funcs;
  std::ifstream f(path);
  if (!f) return funcs;

  std::string line;
  while (std::getline(f, line)) {
    if (line.find(objFilter) == std::string::npos) continue;
    if (line.find(" f ") == std::string::npos) continue;
    if (line.find("0001:") == std::string::npos) continue;

    std::istringstream iss(line);
    std::string secOffset, name, rvaStr;
    iss >> secOffset >> name >> rvaStr;
    if (name.empty() || rvaStr.empty()) continue;

    MapFunction fn;
    fn.name = name;
    fn.rvaBase = std::strtoull(rvaStr.c_str(), nullptr, 16);
    funcs.push_back(fn);
  }
  return funcs;
}

int main(int argc, char* argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0]
              << " <pe_file> <map_file> [obj_filter] [ghidra_root]\n";
    return 1;
  }

  const std::string pe_path = argv[1];
  const std::string map_path = argv[2];
  const std::string obj_filter = (argc >= 4) ? argv[3] : "test_target.obj";
  const std::string ghidra_root = (argc >= 5) ? argv[4] : "";

  // --- Parse PE ---
  pe::PEInfo pe;
  if (!pe::parsePE(pe_path, pe)) {
    std::cerr << "Error: failed to parse PE headers\n";
    return 1;
  }

  std::cout << "PE: " << pe_path << "\n";
  std::cout << "  Image base: 0x" << std::hex << pe.imageBase << std::dec << "\n";
  for (const auto& sec : pe.sections) {
    std::cout << "  " << std::setw(8) << std::left << sec.name << "  VA=0x" << std::hex
              << sec.virtualAddress << "  FileOff=0x" << sec.rawDataOffset << "  Size=0x"
              << sec.rawDataSize << std::dec << "\n";
  }

  // --- Parse MAP file ---
  auto funcs = parseMapFile(map_path, obj_filter);
  if (funcs.empty()) {
    std::cerr << "No functions found matching '" << obj_filter << "'\n";
    return 1;
  }

  std::cout << "\nDiscovered " << funcs.size() << " function(s):\n";
  for (const auto& fn : funcs) {
    uint64_t rva = fn.rvaBase - pe.imageBase;
    uint64_t fileOff = pe::rvaToFileOffset(pe, rva);
    std::cout << "  " << std::setw(20) << std::left << fn.name << "  RVA=0x" << std::hex
              << rva << "  FileOff=0x" << fileOff << std::dec << "\n";
  }

  // --- Open binary via IClient ---
  std::string arch = pe::machineToGhidraArch(pe.machine);
  auto client = ghidra::local({
      .ghidra_root = ghidra_root,
      .default_arch = arch,
  });

  ghidra::OpenRequest req;
  req.program_path = pe_path;
  auto open_result = client->OpenProgram(req);
  if (!open_result.ok()) {
    std::cerr << "Error: " << open_result.status.message << "\n";
    return 1;
  }

  // --- Name functions ---
  for (const auto& fn : funcs) {
    uint64_t rva = fn.rvaBase - pe.imageBase;
    uint64_t fileOff = pe::rvaToFileOffset(pe, rva);
    auto r = client->RenameFunction(fileOff, fn.name);
    if (!r.ok()) {
      std::cerr << "Warning: could not name " << fn.name << " at 0x" << std::hex
                << fileOff << std::dec << ": " << r.status.message << "\n";
    }
  }

  // --- Decompile each ---
  int ok = 0, fail = 0;
  for (const auto& fn : funcs) {
    uint64_t rva = fn.rvaBase - pe.imageBase;
    uint64_t fileOff = pe::rvaToFileOffset(pe, rva);

    std::cout << "\n// ========== " << fn.name << " (0x" << std::hex << fileOff
              << std::dec << ") ==========\n";

    auto result = client->GetDecompilation(fileOff, 30000);
    if (result.ok() && result.value->decompilation &&
        !result.value->decompilation->pseudocode.empty()) {
      std::cout << result.value->decompilation->pseudocode;
      ok++;
    } else {
      std::cerr << "  FAILED\n";
      fail++;
    }
  }

  std::cout << "\n// " << ok << " succeeded, " << fail << " failed, " << funcs.size()
            << " total\n";
  return (fail > 0) ? 1 : 0;
}
