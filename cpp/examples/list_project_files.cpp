// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// list_project_files: import one or more binaries into a Ghidra project,
// start a managed headless libghidra host, and list project contents.
//
// Usage:
//   list_project_files <ghidra_dir> <project_dir> <project_name> <binary> [binary...]

#include <iostream>
#include <string>

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

  try {
    auto host = ghidra::launch_headless_project(std::move(opts));

    for (int i = 4; i < argc; ++i) {
      ghidra::ImportProgramRequest import;
      import.source_path = argv[i];
      import.overwrite = true;
      import.analyze = false;
      auto imported = host->ImportProgram(import);
      if (!imported.ok()) {
        std::cerr << "ImportProgram failed for " << argv[i] << ": "
                  << imported.status.message << "\n";
        return 1;
      }
    }

    libghidra::client::ListProjectFilesRequest req;
    req.include_folders = true;
    auto listed = host->ListProjectFiles(req);
    if (!listed.ok()) {
      std::cerr << "ListProjectFiles failed: " << listed.status.message << "\n";
      return 1;
    }

    for (const auto& file : listed.value->files) {
      std::cout << (file.is_folder ? "folder  " : "file    ")
                << (file.is_program ? "program " : "        ")
                << file.path << "\n";
    }

    host.close(true);
  }
  catch (const std::exception& e) {
    std::cerr << e.what() << "\n";
    return 1;
  }

  return 0;
}
