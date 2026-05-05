// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// switch_active_program: import two binaries into one Ghidra project, query
// the first active program, close it, then open the second project program.
//
// Usage:
//   switch_active_program <ghidra_dir> <project_dir> <project_name> <binary_a> <binary_b>

#include <iostream>
#include <string>

#include "libghidra/ghidra.hpp"

int main(int argc, char* argv[]) {
  if (argc != 6) {
    std::cerr << "Usage: " << argv[0]
              << " <ghidra_dir> <project_dir> <project_name> <binary_a> <binary_b>\n";
    return 1;
  }

  ghidra::HeadlessOptions opts;
  opts.ghidra_dir = argv[1];
  opts.project_dir = argv[2];
  opts.project_name = argv[3];
  opts.binary = argv[4];
  opts.binaries = {argv[5]};
  opts.port = 0;
  opts.shutdown = "save";

  try {
    auto host = ghidra::launch_headless(std::move(opts));

    libghidra::client::ListProjectFilesRequest list_req;
    list_req.programs_only = true;
    auto listed = host->ListProjectFiles(list_req);
    if (!listed.ok() || listed.value->files.size() < 2) {
      std::cerr << "Expected at least two project programs\n";
      return 1;
    }

    const auto first = listed.value->files[0].path;
    const auto second = listed.value->files[1].path;

    auto first_open = host->OpenProgram({.program_path = first});
    if (!first_open.ok()) {
      std::cerr << "Open first failed: " << first_open.status.message << "\n";
      return 1;
    }
    std::cout << "Active: " << first << " -> " << first_open.value->program_name << "\n";

    auto closed = host->CloseProgram(ghidra::ShutdownPolicy::kSave);
    if (!closed.ok() || !closed.value->closed) {
      std::cerr << "CloseProgram failed\n";
      return 1;
    }

    libghidra::client::OpenProgramRequest open_second;
    open_second.project_path = argv[2];
    open_second.project_name = argv[3];
    open_second.program_path = second;
    auto second_open = host->OpenProgram(open_second);
    if (!second_open.ok()) {
      std::cerr << "Open second failed: " << second_open.status.message << "\n";
      return 1;
    }
    std::cout << "Active: " << second << " -> " << second_open.value->program_name << "\n";

    host.close(true);
  }
  catch (const std::exception& e) {
    std::cerr << e.what() << "\n";
    return 1;
  }

  return 0;
}
