// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// headless_cookbook: Complete headless workflow — launch Ghidra, open/analyze
// a binary, run typed RPC calls, save, and shut down.
//
// Demonstrates every lifecycle step in one place:
//   1. Launch headless Ghidra on a configurable RPC port
//   2. Wait for readiness
//   3. Enumerate functions, decompile, inspect types
//   4. Rename a function to prove write-back works
//   5. Save the project
//   6. Gracefully shut down
//
// Usage:
//   headless_cookbook --ghidra <ghidra_dist> --binary <target.exe>
//                    [--port <rpc_port>] [--project <dir>]
//                    [--project-name <name>] [--no-analyze]
//
// Prerequisites:
//   - Ghidra distribution with the LibGhidraHost extension installed

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "libghidra/ghidra.hpp"

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

static void print_separator(const char* title) {
  printf("\n%s\n  %s\n%s\n\n", std::string(70, '=').c_str(), title,
         std::string(70, '=').c_str());
}

// ---------------------------------------------------------------------------
// step 1: verify connection
// ---------------------------------------------------------------------------

static bool verify_connection(ghidra::Client& c) {
  auto st = c.GetStatus();
  if (!st.ok()) {
    fprintf(stderr, "GetStatus failed: %s\n", st.status.message.c_str());
    return false;
  }
  printf("Connected to %s v%s (mode: %s, revision: %" PRIu64 ")\n",
         st.value->service_name.c_str(), st.value->service_version.c_str(),
         st.value->host_mode.c_str(), st.value->program_revision);
  return true;
}

// ---------------------------------------------------------------------------
// step 2: list functions (paginated)
// ---------------------------------------------------------------------------

static void list_functions(ghidra::Client& c) {
  print_separator("Functions");

  auto resp = c.ListFunctions(0, UINT64_MAX, 0, 0);
  if (!resp.ok()) {
    fprintf(stderr, "ListFunctions: %s\n", resp.status.message.c_str());
    return;
  }

  const auto& funcs = resp.value->functions;
  printf("  %zu functions\n\n", funcs.size());

  // Print first 20 with sizes
  const size_t limit = std::min<size_t>(funcs.size(), 20);
  printf("  %-50s %12s %6s\n", "Name", "Address", "Size");
  printf("  %s %s %s\n", std::string(50, '-').c_str(),
         std::string(12, '-').c_str(), std::string(6, '-').c_str());
  for (size_t i = 0; i < limit; ++i) {
    const auto& f = funcs[i];
    printf("  %-50s 0x%010" PRIx64 " %6" PRIu64 "\n", f.name.c_str(),
           f.entry_address, f.size);
  }
  if (funcs.size() > limit)
    printf("  ... and %zu more\n", funcs.size() - limit);
}

// ---------------------------------------------------------------------------
// step 3: decompile a function
// ---------------------------------------------------------------------------

static void decompile_first(ghidra::Client& c) {
  print_separator("Decompilation (first function)");

  auto resp = c.ListFunctions(0, UINT64_MAX, 1, 0);  // page_size=1
  if (!resp.ok() || resp.value->functions.empty()) {
    printf("  (no functions to decompile)\n");
    return;
  }

  const auto& func = resp.value->functions[0];
  printf("  Decompiling %s @ 0x%" PRIx64 " ...\n", func.name.c_str(),
         func.entry_address);

  auto dec = c.GetDecompilation(func.entry_address, 30000);
  if (!dec.ok()) {
    fprintf(stderr, "  GetDecompilation: %s\n", dec.status.message.c_str());
    return;
  }
  if (dec.value->decompilation && dec.value->decompilation->completed) {
    printf("\n%s\n", dec.value->decompilation->pseudocode.c_str());
  } else if (dec.value->decompilation) {
    printf("  error: %s\n", dec.value->decompilation->error_message.c_str());
  } else {
    printf("  (no decompilation result)\n");
  }
}

// ---------------------------------------------------------------------------
// step 4: rename a function (write-back proof)
// ---------------------------------------------------------------------------

static void rename_demo(ghidra::Client& c) {
  print_separator("Rename demo");

  auto resp = c.ListFunctions(0, UINT64_MAX, 1, 0);
  if (!resp.ok() || resp.value->functions.empty()) {
    printf("  (no functions to rename)\n");
    return;
  }

  const auto& func = resp.value->functions[0];
  std::string old_name = func.name;
  std::string new_name = "cookbook_renamed_" + old_name;

  printf("  Renaming 0x%" PRIx64 ": %s -> %s\n", func.entry_address,
         old_name.c_str(), new_name.c_str());
  auto rename = c.RenameFunction(func.entry_address, new_name);
  if (!rename.ok()) {
    fprintf(stderr, "  RenameFunction: %s\n", rename.status.message.c_str());
    return;
  }
  printf("  OK\n");

  // Rename back
  printf("  Restoring: %s -> %s\n", new_name.c_str(), old_name.c_str());
  c.RenameFunction(func.entry_address, old_name);
}

// ---------------------------------------------------------------------------
// step 5: inspect types
// ---------------------------------------------------------------------------

static void list_types(ghidra::Client& c) {
  print_separator("Types (first 10)");

  auto resp = c.ListTypes("", 10, 0);
  if (!resp.ok()) {
    fprintf(stderr, "ListTypes: %s\n", resp.status.message.c_str());
    return;
  }
  for (const auto& t : resp.value->types) {
    printf("  %-40s  kind=%-10s  length=%d\n", t.name.c_str(),
           t.kind.c_str(), t.length);
  }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
  std::string ghidra_dir, binary_path, project_dir, project_name;
  int port = 18080;
  bool analyze = true;

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--ghidra") == 0 && i + 1 < argc)
      ghidra_dir = argv[++i];
    else if (std::strcmp(argv[i], "--binary") == 0 && i + 1 < argc)
      binary_path = argv[++i];
    else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc)
      port = std::atoi(argv[++i]);
    else if (std::strcmp(argv[i], "--project") == 0 && i + 1 < argc)
      project_dir = argv[++i];
    else if (std::strcmp(argv[i], "--project-name") == 0 && i + 1 < argc)
      project_name = argv[++i];
    else if (std::strcmp(argv[i], "--no-analyze") == 0)
      analyze = false;
    else {
      fprintf(stderr,
              "Usage: %s --ghidra <dist> --binary <target> [--port N] "
              "[--project <dir>] [--project-name <name>] [--no-analyze]\n",
              argv[0]);
      return 1;
    }
  }

  if (ghidra_dir.empty() || binary_path.empty()) {
    fprintf(stderr, "ERROR: --ghidra and --binary are required\n");
    return 1;
  }

  printf("Headless Cookbook\n");
  printf("  ghidra:       %s\n", ghidra_dir.c_str());
  printf("  binary:       %s\n", binary_path.c_str());
  printf("  rpc port:     %d\n", port);
  printf("  analyze:      %s\n", analyze ? "yes" : "no");
  if (!project_dir.empty())
    printf("  project dir:  %s\n", project_dir.c_str());
  if (!project_name.empty())
    printf("  project name: %s\n", project_name.c_str());

  try {
    ghidra::HeadlessOptions opts;
    opts.ghidra_dir = ghidra_dir;
    opts.binary = binary_path;
    opts.port = port;
    opts.analyze = analyze;
    if (!project_dir.empty()) opts.project_dir = project_dir;
    if (!project_name.empty()) opts.project_name = project_name;
    opts.on_output = [](const std::string& line) {
      printf("  [ghidra] %s\n", line.c_str());
    };

    printf("\nLaunching headless Ghidra on port %d...\n", port);
    auto h = ghidra::launch_headless(std::move(opts));

    if (!verify_connection(*h)) return 1;

    list_functions(*h);
    decompile_first(*h);
    rename_demo(*h);
    list_types(*h);

    // Save
    print_separator("Save and shutdown");
    printf("  Saving project...\n");
    auto save = h->SaveProgram();
    printf("  save: %s\n", save.ok() ? "ok" : save.status.message.c_str());

    // Shutdown
    printf("  Shutting down Ghidra...\n");
    int code = h.close(/*save=*/true);
    printf("  Ghidra exited with code %d\n", code);

  } catch (const std::exception& e) {
    fprintf(stderr, "\nERROR: %s\n", e.what());
    return 1;
  }

  printf("\nDone.\n");
  return 0;
}
