// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// end_to_end: Launch headless Ghidra, analyze a binary, enumerate functions
// with basic blocks and decompilation, save the project, and shut down.
//
// Usage:
//   end_to_end --ghidra <ghidra_dist> --binary <target.exe> [--port <port>]
//
// Prerequisites:
//   - Ghidra distribution with the LibGhidraHost extension installed
//     (install via: gradle installExtension -PGHIDRA_INSTALL_DIR=<dist>)

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "libghidra/ghidra.hpp"

// ---------------------------------------------------------------------------
// Analysis: enumerate functions with blocks, edges, and decompilation
// ---------------------------------------------------------------------------

static void analyze(ghidra::Client& client) {
  auto funcs_resp = client.ListFunctions(0, UINT64_MAX, 0, 0);
  if (!funcs_resp.ok()) {
    fprintf(stderr, "ListFunctions failed: %s\n",
            funcs_resp.status.message.c_str());
    return;
  }
  const auto& functions = funcs_resp.value->functions;
  printf("\n%s\n  %zu functions found\n%s\n\n",
         std::string(70, '=').c_str(), functions.size(),
         std::string(70, '=').c_str());

  for (const auto& func : functions) {
    printf("--- %s @ 0x%llx  (%llu bytes, %u params) ---\n",
           func.name.c_str(), (unsigned long long)func.entry_address,
           (unsigned long long)func.size, func.parameter_count);

    // Basic blocks
    auto bb =
        client.ListBasicBlocks(func.start_address, func.end_address, 0, 0);
    if (bb.ok() && !bb.value->blocks.empty()) {
      printf("  Basic blocks (%zu):\n", bb.value->blocks.size());
      for (const auto& b : bb.value->blocks) {
        printf("    0x%llx..0x%llx  in_degree=%u  out_degree=%u\n",
               (unsigned long long)b.start_address,
               (unsigned long long)b.end_address, b.in_degree, b.out_degree);
      }
    } else {
      printf("  Basic blocks: (none)\n");
    }

    // CFG edges
    auto edges =
        client.ListCFGEdges(func.start_address, func.end_address, 0, 0);
    if (edges.ok() && !edges.value->edges.empty()) {
      printf("  CFG edges (%zu):\n", edges.value->edges.size());
      for (const auto& e : edges.value->edges) {
        printf("    0x%llx -> 0x%llx  (%s)\n",
               (unsigned long long)e.src_block_start,
               (unsigned long long)e.dst_block_start, e.edge_kind.c_str());
      }
    }

    // Decompilation
    auto dec = client.GetDecompilation(func.entry_address, 30000);
    if (dec.ok() && dec.value->decompilation &&
        dec.value->decompilation->completed) {
      const auto& code = dec.value->decompilation->pseudocode;
      int line_count = 1;
      for (char c : code)
        if (c == '\n') ++line_count;
      printf("  Decompilation (%d lines):\n", line_count);
      printf("    ");
      for (char c : code) {
        putchar(c);
        if (c == '\n') printf("    ");
      }
      printf("\n");
    } else if (dec.ok() && dec.value->decompilation &&
               !dec.value->decompilation->error_message.empty()) {
      printf("  Decompilation error: %s\n",
             dec.value->decompilation->error_message.c_str());
    } else {
      printf("  Decompilation: %s\n",
             dec.ok() ? "(empty)" : dec.status.message.c_str());
    }

    printf("\n");
  }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
  std::string ghidra_dir, binary_path;
  int port = 18080;

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--ghidra") == 0 && i + 1 < argc)
      ghidra_dir = argv[++i];
    else if (std::strcmp(argv[i], "--binary") == 0 && i + 1 < argc)
      binary_path = argv[++i];
    else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc)
      port = std::atoi(argv[++i]);
    else {
      fprintf(stderr,
              "Usage: %s --ghidra <ghidra_dist> --binary <target> [--port N]\n",
              argv[0]);
      return 1;
    }
  }
  if (ghidra_dir.empty() || binary_path.empty()) {
    fprintf(stderr, "ERROR: --ghidra and --binary are required\n");
    return 1;
  }

  try {
    auto h = ghidra::launch_headless({
        .ghidra_dir = ghidra_dir,
        .binary = binary_path,
        .port = port,
        .on_output = [](const std::string& line) {
          printf("  [ghidra] %s\n", line.c_str());
        },
    });

    auto status = h->GetStatus();
    if (!status.ok()) {
      fprintf(stderr, "Cannot reach host: %s\n",
              status.status.message.c_str());
      return 1;
    }
    printf("\nConnected: %s v%s (mode: %s)\n\n",
           status.value->service_name.c_str(),
           status.value->service_version.c_str(),
           status.value->host_mode.c_str());

    analyze(*h);

    printf("Saving project...\n");
    auto save = h->SaveProgram();
    printf("  saved=%s\n", save.ok() ? "true" : "false");

    int code = h.close();
    printf("  Ghidra exited with code %d\n", code);

  } catch (const std::exception& e) {
    fprintf(stderr, "\nERROR: %s\n", e.what());
    return 1;
  }

  printf("\nDone.\n");
  return 0;
}
