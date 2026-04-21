// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// parallel_headless: Launch two headless Ghidra instances on different RPC
// ports and query them concurrently.
//
// Demonstrates running multiple headless sessions in parallel, each with its
// own RPC port, project directory, and lifecycle.  Useful for batch analysis
// of multiple binaries or comparing two binaries side by side.
//
// Usage:
//   parallel_headless --ghidra <ghidra_dist>
//                     --binary-a <a.exe> --binary-b <b.exe>
//                     [--port-a <port>] [--port-b <port>]
//
// Prerequisites:
//   - Ghidra distribution with the LibGhidraHost extension installed

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <string>
#include <vector>

#include "libghidra/ghidra.hpp"

// ---------------------------------------------------------------------------
// Analysis: collect function names from a headless instance
// ---------------------------------------------------------------------------

struct InstanceResult {
  std::string label;
  std::vector<std::string> function_names;
  uint64_t total_code_bytes = 0;
  std::string error;
};

static InstanceResult analyze_instance(const std::string& label,
                                       const std::string& ghidra_dir,
                                       const std::string& binary_path,
                                       int port) {
  InstanceResult result;
  result.label = label;

  try {
    printf("[%s] Launching on port %d: %s\n", label.c_str(), port,
           binary_path.c_str());

    ghidra::HeadlessOptions opts;
    opts.ghidra_dir = ghidra_dir;
    opts.binary = binary_path;
    opts.port = port;
    opts.shutdown = "discard";  // read-only analysis, no save needed
    opts.on_output = [&label](const std::string& line) {
      printf("  [%s] %s\n", label.c_str(), line.c_str());
    };

    auto h = ghidra::launch_headless(std::move(opts));

    auto status = h->GetStatus();
    if (!status.ok()) {
      result.error = "GetStatus: " + status.status.message;
      h.close(false);
      return result;
    }
    printf("[%s] Connected: %s v%s\n", label.c_str(),
           status.value->service_name.c_str(),
           status.value->service_version.c_str());

    auto funcs = h->ListFunctions(0, UINT64_MAX, 0, 0);
    if (!funcs.ok()) {
      result.error = "ListFunctions: " + funcs.status.message;
      h.close(false);
      return result;
    }

    for (const auto& f : funcs.value->functions) {
      result.function_names.push_back(f.name);
      result.total_code_bytes += f.size;
    }

    printf("[%s] Found %zu functions, %" PRIu64 " bytes of code\n",
           label.c_str(), result.function_names.size(),
           result.total_code_bytes);

    h.close(/*save=*/false);
    printf("[%s] Shut down\n", label.c_str());

  } catch (const std::exception& e) {
    result.error = e.what();
  }

  return result;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
  std::string ghidra_dir, binary_a, binary_b;
  int port_a = 18080;
  int port_b = 18081;

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--ghidra") == 0 && i + 1 < argc)
      ghidra_dir = argv[++i];
    else if (std::strcmp(argv[i], "--binary-a") == 0 && i + 1 < argc)
      binary_a = argv[++i];
    else if (std::strcmp(argv[i], "--binary-b") == 0 && i + 1 < argc)
      binary_b = argv[++i];
    else if (std::strcmp(argv[i], "--port-a") == 0 && i + 1 < argc)
      port_a = std::atoi(argv[++i]);
    else if (std::strcmp(argv[i], "--port-b") == 0 && i + 1 < argc)
      port_b = std::atoi(argv[++i]);
    else {
      fprintf(stderr,
              "Usage: %s --ghidra <dist> --binary-a <a.exe> --binary-b <b.exe>"
              " [--port-a N] [--port-b N]\n",
              argv[0]);
      return 1;
    }
  }

  if (ghidra_dir.empty() || binary_a.empty() || binary_b.empty()) {
    fprintf(stderr,
            "ERROR: --ghidra, --binary-a, and --binary-b are required\n");
    return 1;
  }

  if (port_a == port_b) {
    fprintf(stderr, "ERROR: --port-a and --port-b must be different\n");
    return 1;
  }

  printf("Parallel Headless Analysis\n");
  printf("  ghidra:    %s\n", ghidra_dir.c_str());
  printf("  binary A:  %s  (port %d)\n", binary_a.c_str(), port_a);
  printf("  binary B:  %s  (port %d)\n", binary_b.c_str(), port_b);
  printf("\n");

  // Launch both instances concurrently
  auto future_a = std::async(std::launch::async, analyze_instance, "A",
                             ghidra_dir, binary_a, port_a);
  auto future_b = std::async(std::launch::async, analyze_instance, "B",
                             ghidra_dir, binary_b, port_b);

  auto result_a = future_a.get();
  auto result_b = future_b.get();

  // Print comparison
  printf("\n%s\n", std::string(70, '=').c_str());
  printf("  Comparison\n");
  printf("%s\n\n", std::string(70, '=').c_str());

  auto print_result = [](const InstanceResult& r) {
    if (!r.error.empty()) {
      printf("  [%s] ERROR: %s\n", r.label.c_str(), r.error.c_str());
      return;
    }
    printf("  [%s] %zu functions, %" PRIu64 " bytes of code\n",
           r.label.c_str(), r.function_names.size(), r.total_code_bytes);

    const size_t limit = std::min<size_t>(r.function_names.size(), 10);
    for (size_t i = 0; i < limit; ++i)
      printf("       %s\n", r.function_names[i].c_str());
    if (r.function_names.size() > limit)
      printf("       ... and %zu more\n", r.function_names.size() - limit);
  };

  print_result(result_a);
  printf("\n");
  print_result(result_b);

  bool ok = result_a.error.empty() && result_b.error.empty();
  printf("\n%s\n", ok ? "Done." : "Completed with errors.");
  return ok ? 0 : 1;
}
