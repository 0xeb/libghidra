// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// multi_program_strings: launch one live Ghidra headless project, import and
// analyze one or more binaries, count defined strings for each active program,
// save the project, and shut down.
//
// Usage:
//   multi_program_strings <ghidra_dir> <project_dir> <project_name> <binary> [binary...]

#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <utility>

#include "libghidra/ghidra.hpp"

int main(int argc, char* argv[]) {
  if (argc < 5) {
    std::cerr << "Usage: " << argv[0]
              << " <ghidra_dir> <project_dir> <project_name> <binary> [binary...]\n";
    return 1;
  }

  ghidra::HeadlessProjectOptions opts;
  opts.ghidra_dir = argv[1];
  opts.project_dir = argv[2];
  opts.project_name = argv[3];
  opts.port = 0;
  opts.shutdown = "save";
  opts.startup_timeout = std::chrono::seconds(600);
  opts.read_timeout = std::chrono::milliseconds(300000);

  try {
    auto host = ghidra::launch_headless_project(std::move(opts));
    int exit_status = 0;

    for (int i = 4; i < argc; ++i) {
      ghidra::ImportProgramRequest import;
      import.source_path = argv[i];
      import.overwrite = true;
      import.analyze = true;

      auto imported = host->ImportProgram(import);
      if (!imported.ok()) {
        std::cerr << "ImportProgram failed for " << argv[i] << ": "
                  << imported.status.message << "\n";
        exit_status = 1;
        break;
      }

      const std::string program_path = imported.value->primary_program_path;
      if (program_path.empty()) {
        std::cerr << "ImportProgram returned no primary program path for " << argv[i] << "\n";
        exit_status = 1;
        break;
      }

      std::cout << "imported  " << program_path << "  source=" << argv[i] << "\n";

      ghidra::OpenProgramRequest open;
      open.project_path = argv[2];
      open.project_name = argv[3];
      open.program_path = program_path;
      open.analyze = false;
      open.read_only = false;

      auto opened = host->OpenProgram(open);
      if (!opened.ok()) {
        std::cerr << "OpenProgram failed for " << program_path << ": "
                  << opened.status.message << "\n";
        exit_status = 1;
        break;
      }

      auto strings = host->ListDefinedStrings(
          0, std::numeric_limits<std::uint64_t>::max(), 0, 0);
      if (!strings.ok()) {
        std::cerr << "ListDefinedStrings failed for " << program_path << ": "
                  << strings.status.message << "\n";
        exit_status = 1;
        break;
      }

      std::cout << "strings   " << program_path
                << "  program=" << opened.value->program_name
                << "  count=" << strings.value->strings.size() << "\n";

      auto closed = host->CloseProgram(ghidra::ShutdownPolicy::kSave);
      if (!closed.ok() || !closed.value->closed) {
        std::cerr << "CloseProgram failed for " << program_path;
        if (!closed.ok()) {
          std::cerr << ": " << closed.status.message;
        }
        std::cerr << "\n";
        exit_status = 1;
        break;
      }
    }

    const int ghidra_exit = host.close(true, std::chrono::seconds(120));
    if (exit_status == 0 && ghidra_exit != 0) {
      std::cerr << "Ghidra exited with code " << ghidra_exit << "\n";
      return 1;
    }

    if (exit_status == 0) {
      std::cout << "saved     project=" << argv[3] << "\n";
    }
    return exit_status;
  }
  catch (const std::exception& e) {
    std::cerr << e.what() << "\n";
    return 1;
  }
}
