// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// quickstart: Connect to a running LibGhidraHost, list functions, and decompile one.
//
// Usage: quickstart [host_url] [project_path] [program_path]
//
// Defaults: http://127.0.0.1:18080, expects a program already open in Ghidra.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "libghidra/ghidra.hpp"

int main(int argc, char* argv[]) {
  const std::string host_url =
      (argc >= 2) ? argv[1] : "http://127.0.0.1:18080";

  auto client = ghidra::connect(host_url);

  // 1. Check host health
  auto status = client->GetStatus();
  if (!status.ok()) {
    fprintf(stderr, "Cannot reach host at %s: %s\n", host_url.c_str(),
            status.status.message.c_str());
    return 1;
  }
  printf("Connected: %s v%s (mode: %s)\n",
         status.value->service_name.c_str(),
         status.value->service_version.c_str(),
         status.value->host_mode.c_str());

  // 2. Open a program (if project path provided on command line)
  if (argc >= 4) {
    ghidra::OpenRequest req;
    req.project_path = argv[2];
    req.program_path = argv[3];
    auto open = client->OpenProgram(req);
    if (!open.ok()) {
      fprintf(stderr, "OpenProgram failed: %s\n",
              open.status.message.c_str());
      return 1;
    }
    printf("Opened: %s (lang=%s, base=0x%llx)\n",
           open.value->program_name.c_str(),
           open.value->language_id.c_str(),
           (unsigned long long)open.value->image_base);
  }

  // 3. List the first 10 functions
  auto funcs = client->ListFunctions(0, UINT64_MAX, 10, 0);
  if (!funcs.ok()) {
    fprintf(stderr, "ListFunctions failed: %s\n",
            funcs.status.message.c_str());
    return 1;
  }

  printf("\nFunctions (%zu shown):\n", funcs.value->functions.size());
  for (const auto& f : funcs.value->functions) {
    printf("  0x%llx  %s  (%llu bytes)\n",
           (unsigned long long)f.entry_address, f.name.c_str(),
           (unsigned long long)f.size);
  }

  // 4. Decompile the first function
  if (!funcs.value->functions.empty()) {
    uint64_t addr = funcs.value->functions[0].entry_address;
    printf("\nDecompiling %s at 0x%llx...\n",
           funcs.value->functions[0].name.c_str(),
           (unsigned long long)addr);

    auto decomp = client->GetDecompilation(addr, 30000);
    if (decomp.ok() && decomp.value->decompilation &&
        !decomp.value->decompilation->pseudocode.empty()) {
      printf("\n%s\n", decomp.value->decompilation->pseudocode.c_str());
    } else {
      std::string err = decomp.ok() ? "empty result" : decomp.status.message;
      fprintf(stderr, "Decompilation failed: %s\n", err.c_str());
    }
  }

  return 0;
}
