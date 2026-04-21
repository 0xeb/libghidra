// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// libghidra_cli: Full CLI tool using the libghidra IClient local backend.
//
// Subcommands:
//   info          <binary> [--state file] [ghidra_root] [arch]
//   list          <binary> [--state file] [ghidra_root] [arch]
//   decompile     <binary> <addr|name> [--state file] [ghidra_root] [arch]
//   decompile-all <binary> [-o dir] [--state file] [ghidra_root] [arch]
//   name          <binary> <addr> <name> [--state file] [ghidra_root] [arch]
//   prototype     <binary> <addr> <proto> [--state file] [ghidra_root] [arch]
//   save          <binary> <state_file> [ghidra_root] [arch]

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

#ifdef _WIN32
#include <direct.h>
#define MKDIR(d) _mkdir(d)
#else
#include <sys/stat.h>
#define MKDIR(d) mkdir(d, 0755)
#endif

// -- Helpers ------------------------------------------------------------------

static void print_usage(const char* argv0) {
  std::cerr
      << "Usage: " << argv0 << " <command> [options]\n\n"
      << "Commands:\n"
      << "  info          <binary> [--state file] [ghidra_root] [arch]\n"
      << "  list          <binary> [--state file] [ghidra_root] [arch]\n"
      << "  decompile     <binary> <addr|name> [--state file] [ghidra_root] [arch]\n"
      << "  decompile-all <binary> [-o dir] [--state file] [ghidra_root] [arch]\n"
      << "  name          <binary> <addr> <name> [--state file] [ghidra_root] [arch]\n"
      << "  prototype     <binary> <addr> <proto> [--state file] [ghidra_root] [arch]\n"
      << "  save          <binary> <state_file> [ghidra_root] [arch]\n";
}

static uint64_t parse_address(const std::string& s) {
  return std::strtoull(s.c_str(), nullptr, 16);
}

static bool looks_like_address(const std::string& s) {
  if (s.empty()) return false;
  size_t start = 0;
  if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) start = 2;
  if (start >= s.size()) return false;
  for (size_t i = start; i < s.size(); i++) {
    char c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
      return false;
  }
  return true;
}

static std::string sanitize_filename(const std::string& name) {
  std::string out;
  for (char c : name) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c == '_' || c == '-' || c == '.')
      out += c;
    else
      out += '_';
  }
  return out;
}

static std::string extract_state_flag(std::vector<std::string>& args) {
  for (size_t i = 0; i < args.size(); i++) {
    if (args[i] == "--state" && i + 1 < args.size()) {
      std::string val = args[i + 1];
      args.erase(args.begin() + i, args.begin() + i + 2);
      return val;
    }
  }
  return "";
}

static std::vector<std::string> args_to_vec(int argc, char* argv[]) {
  std::vector<std::string> v;
  for (int i = 0; i < argc; i++) v.push_back(argv[i]);
  return v;
}

static std::unique_ptr<ghidra::Client> smart_open(const std::string& binary,
                                                const std::string& ghidra_root,
                                                const std::string& arch,
                                                const std::string& state_file,
                                                pe::PEInfo& pe_out) {
  pe_out = pe::PEInfo{};
  bool is_pe = pe::parsePE(binary, pe_out);

  std::string resolved_arch = arch;
  if (resolved_arch.empty() && is_pe) {
    resolved_arch = pe::machineToGhidraArch(pe_out.machine);
  }

  auto client = ghidra::local({
      .ghidra_root = ghidra_root,
      .state_path = state_file,
      .default_arch = resolved_arch,
  });

  ghidra::OpenRequest req;
  req.program_path = binary;
  auto r = client->OpenProgram(req);
  if (!r.ok()) {
    std::cerr << "Error: " << r.status.message << "\n";
    return nullptr;
  }

  // If no state file, auto-name PE exports/entry
  if (state_file.empty() && is_pe) {
    if (pe_out.entryPointFileOffset != 0)
      client->RenameFunction(pe_out.entryPointFileOffset, "entry");
    for (const auto& exp : pe_out.exports) {
      if (exp.fileOffset != 0) client->RenameFunction(exp.fileOffset, exp.name);
    }
  }

  return client;
}

// -- Subcommands --------------------------------------------------------------

static int cmd_info(int argc, char* argv[]) {
  if (argc < 1) {
    std::cerr << "Usage: libghidra_cli info <binary> [--state file] [ghidra_root] [arch]\n";
    return 1;
  }
  auto args = args_to_vec(argc, argv);
  std::string state_file = extract_state_flag(args);
  const std::string binary = args[0];
  const std::string ghidra_root = (args.size() >= 2) ? args[1] : "";
  const std::string arch = (args.size() >= 3) ? args[2] : "";

  pe::PEInfo pe;
  auto client = smart_open(binary, ghidra_root, arch, state_file, pe);
  if (!client) return 1;

  auto funcs_r = client->ListFunctions(0, 0, 100000, 0);
  auto& funcs = funcs_r.value->functions;

  std::cout << "Binary:    " << binary << "\n";
  if (pe.valid) {
    std::cout << "Format:    PE" << (pe.magic == 0x20B ? "32+" : "32") << "\n";
    std::cout << "Machine:   " << pe::machineToString(pe.machine) << "\n";
    std::cout << "ImageBase: 0x" << std::hex << pe.imageBase << std::dec << "\n";
    std::cout << "Sections:  " << pe.sections.size() << "\n";
    std::cout << "Exports:   " << pe.exports.size() << "\n";
  }
  std::cout << "Functions: " << funcs.size() << "\n";

  int named = 0;
  for (auto& f : funcs) {
    if (!f.name.empty() && f.name.substr(0, 4) != "FUN_") named++;
  }
  std::cout << "Named:     " << named << "\nAuto:      " << (funcs.size() - named) << "\n";
  return 0;
}

static int cmd_list(int argc, char* argv[]) {
  if (argc < 1) {
    std::cerr << "Usage: libghidra_cli list <binary> [--state file] [ghidra_root] [arch]\n";
    return 1;
  }
  auto args = args_to_vec(argc, argv);
  std::string state_file = extract_state_flag(args);
  const std::string binary = args[0];
  const std::string ghidra_root = (args.size() >= 2) ? args[1] : "";
  const std::string arch = (args.size() >= 3) ? args[2] : "";

  pe::PEInfo pe;
  auto client = smart_open(binary, ghidra_root, arch, state_file, pe);
  if (!client) return 1;

  auto funcs_r = client->ListFunctions(0, 0, 100000, 0);
  auto funcs = std::move(funcs_r.value->functions);

  std::sort(funcs.begin(), funcs.end(),
            [](const ghidra::Function& a, const ghidra::Function& b) {
              return a.entry_address < b.entry_address;
            });

  std::cout << funcs.size() << " functions:\n\n";
  for (auto& f : funcs) {
    std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(8)
              << f.entry_address << std::dec << std::setfill(' ');
    if (f.size > 0) std::cout << "  " << std::setw(5) << f.size << "B";
    else std::cout << "       ";
    std::cout << "  " << (f.name.empty() ? "(unnamed)" : f.name) << "\n";
  }
  return 0;
}

static int cmd_decompile(int argc, char* argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: libghidra_cli decompile <binary> <addr|name> [--state file] "
                 "[ghidra_root] [arch]\n";
    return 1;
  }
  auto args = args_to_vec(argc, argv);
  std::string state_file = extract_state_flag(args);
  const std::string binary = args[0];
  const std::string target = args[1];
  const std::string ghidra_root = (args.size() >= 3) ? args[2] : "";
  const std::string arch = (args.size() >= 4) ? args[3] : "";

  pe::PEInfo pe;
  auto client = smart_open(binary, ghidra_root, arch, state_file, pe);
  if (!client) return 1;

  uint64_t addr = 0;
  if (looks_like_address(target)) {
    addr = parse_address(target);
    if (pe.valid && addr >= pe.imageBase) {
      uint64_t file_off = pe::vaToFileOffset(pe, addr);
      if (file_off != 0) addr = file_off;
    }
  } else {
    auto funcs_r = client->ListFunctions(0, 0, 100000, 0);
    bool found = false;
    for (auto& f : funcs_r.value->functions) {
      if (f.name == target) {
        addr = f.entry_address;
        found = true;
        break;
      }
    }
    if (!found) {
      std::cerr << "Function '" << target << "' not found.\n";
      return 1;
    }
  }

  auto d = client->GetDecompilation(addr, 30000);
  if (d.ok() && d.value->decompilation &&
      !d.value->decompilation->pseudocode.empty()) {
    std::cout << d.value->decompilation->pseudocode;
  } else {
    std::cerr << "Decompilation failed\n";
    return 1;
  }
  return 0;
}

static int cmd_decompile_all(int argc, char* argv[]) {
  if (argc < 1) {
    std::cerr << "Usage: libghidra_cli decompile-all <binary> [-o dir] [--state file] "
                 "[ghidra_root] [arch]\n";
    return 1;
  }
  auto args = args_to_vec(argc, argv);
  std::string state_file = extract_state_flag(args);
  const std::string binary = args[0];
  std::string output_dir;
  std::string ghidra_root;
  std::string arch;

  for (size_t i = 1; i < args.size(); i++) {
    if (args[i] == "-o" && i + 1 < args.size())
      output_dir = args[++i];
    else if (ghidra_root.empty())
      ghidra_root = args[i];
    else
      arch = args[i];
  }

  pe::PEInfo pe;
  auto client = smart_open(binary, ghidra_root, arch, state_file, pe);
  if (!client) return 1;

  auto funcs_r = client->ListFunctions(0, 0, 100000, 0);
  auto funcs = std::move(funcs_r.value->functions);
  std::sort(funcs.begin(), funcs.end(),
            [](const ghidra::Function& a, const ghidra::Function& b) {
              return a.entry_address < b.entry_address;
            });

  if (funcs.empty()) {
    std::cerr << "No functions found.\n";
    return 1;
  }
  if (!output_dir.empty()) MKDIR(output_dir.c_str());

  std::cerr << "Decompiling " << funcs.size() << " functions...\n";

  int success = 0, fail = 0;
  for (auto& f : funcs) {
    std::string display = f.name.empty()
                              ? ("0x" + (std::ostringstream() << std::hex << f.entry_address).str())
                              : f.name;

    auto d = client->GetDecompilation(f.entry_address, 30000);
    if (!d.ok() || !d.value->decompilation ||
        d.value->decompilation->pseudocode.empty()) {
      std::cerr << "  FAIL: " << display << "\n";
      fail++;
      continue;
    }

    if (output_dir.empty()) {
      std::cout << "// ===== " << display << " @ 0x" << std::hex << f.entry_address
                << std::dec << " =====\n";
      std::cout << d.value->decompilation->pseudocode << "\n";
    } else {
      std::ostringstream fname;
      fname << std::hex << std::setfill('0') << std::setw(8) << f.entry_address;
      std::string path =
          output_dir + "/" + fname.str() + "_" + sanitize_filename(display) + ".c";
      std::ofstream out(path);
      if (out) out << d.value->decompilation->pseudocode;
      else { fail++; continue; }
    }
    success++;
  }

  std::cerr << "\nDone: " << success << " OK, " << fail << " failed ("
            << funcs.size() << " total)\n";
  return (fail > 0) ? 1 : 0;
}

static int cmd_name(int argc, char* argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: libghidra_cli name <binary> <addr> <name> [--state file] "
                 "[ghidra_root] [arch]\n";
    return 1;
  }
  auto args = args_to_vec(argc, argv);
  std::string state_file = extract_state_flag(args);
  const std::string binary = args[0];
  uint64_t addr = parse_address(args[1]);
  const std::string name = args[2];
  const std::string ghidra_root = (args.size() >= 4) ? args[3] : "";
  const std::string arch = (args.size() >= 5) ? args[4] : "";

  pe::PEInfo pe;
  auto client = smart_open(binary, ghidra_root, arch, state_file, pe);
  if (!client) return 1;

  auto r = client->RenameFunction(addr, name);
  if (!r.ok()) {
    std::cerr << "Error naming function: " << r.status.message << "\n";
    return 1;
  }
  std::cerr << "Named 0x" << std::hex << addr << std::dec << " -> " << name << "\n";

  if (!state_file.empty()) {
    auto s = client->SaveProgram();
    if (s.ok()) std::cerr << "State saved to " << state_file << "\n";
  }
  return 0;
}

static int cmd_prototype(int argc, char* argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: libghidra_cli prototype <binary> <addr> <proto> [--state file] "
                 "[ghidra_root] [arch]\n";
    return 1;
  }
  auto args = args_to_vec(argc, argv);
  std::string state_file = extract_state_flag(args);
  const std::string binary = args[0];
  uint64_t addr = parse_address(args[1]);
  const std::string proto = args[2];
  const std::string ghidra_root = (args.size() >= 4) ? args[3] : "";
  const std::string arch = (args.size() >= 5) ? args[4] : "";

  pe::PEInfo pe;
  auto client = smart_open(binary, ghidra_root, arch, state_file, pe);
  if (!client) return 1;

  auto r = client->SetFunctionSignature(addr, proto);
  if (!r.ok()) {
    std::cerr << "Error setting prototype: " << r.status.message << "\n";
    return 1;
  }
  std::cerr << "Prototype set for 0x" << std::hex << addr << std::dec << "\n";

  if (!state_file.empty()) {
    auto s = client->SaveProgram();
    if (s.ok()) std::cerr << "State saved to " << state_file << "\n";
  }
  return 0;
}

static int cmd_save(int argc, char* argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: libghidra_cli save <binary> <state_file> [ghidra_root] [arch]\n";
    return 1;
  }
  const std::string binary = argv[0];
  const std::string state_file = argv[1];
  const std::string ghidra_root = (argc >= 3) ? argv[2] : "";
  const std::string arch = (argc >= 4) ? argv[3] : "";

  pe::PEInfo pe;
  auto client = smart_open(binary, ghidra_root, arch, state_file, pe);
  if (!client) return 1;

  auto s = client->SaveProgram();
  if (!s.ok()) {
    std::cerr << "Error saving state: " << s.status.message << "\n";
    return 1;
  }
  std::cerr << "State saved to " << state_file << "\n";
  return 0;
}

// -- Main ---------------------------------------------------------------------

int main(int argc, char* argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  const std::string cmd = argv[1];
  int sub_argc = argc - 2;
  char** sub_argv = argv + 2;

  if (cmd == "info") return cmd_info(sub_argc, sub_argv);
  if (cmd == "list") return cmd_list(sub_argc, sub_argv);
  if (cmd == "decompile") return cmd_decompile(sub_argc, sub_argv);
  if (cmd == "decompile-all") return cmd_decompile_all(sub_argc, sub_argv);
  if (cmd == "name") return cmd_name(sub_argc, sub_argv);
  if (cmd == "prototype") return cmd_prototype(sub_argc, sub_argv);
  if (cmd == "save") return cmd_save(sub_argc, sub_argv);

  std::cerr << "Unknown command: " << cmd << "\n\n";
  print_usage(argv[0]);
  return 1;
}
