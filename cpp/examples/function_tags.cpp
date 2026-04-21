// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// function_tags: Create tags, tag/untag functions, list mappings, clean up.
//
// Usage: function_tags [host_url]

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
  printf("Connected: %s v%s\n",
         status.value->service_name.c_str(),
         status.value->service_version.c_str());

  // 2. Create two tags
  printf("\n--- Creating tags ---\n");
  auto t1 = client->CreateFunctionTag("crypto", "Cryptographic routines");
  printf("  CreateFunctionTag('crypto'): %s\n",
         t1.ok() ? "OK" : t1.status.message.c_str());

  auto t2 = client->CreateFunctionTag("network", "Network I/O functions");
  printf("  CreateFunctionTag('network'): %s\n",
         t2.ok() ? "OK" : t2.status.message.c_str());

  // 3. List all tags
  printf("\n--- All function tags ---\n");
  auto tags = client->ListFunctionTags();
  if (!tags.ok()) {
    fprintf(stderr, "ListFunctionTags failed: %s\n",
            tags.status.message.c_str());
    return 1;
  }
  for (const auto& t : tags.value->tags) {
    printf("  name='%s'  comment='%s'\n", t.name.c_str(), t.comment.c_str());
  }

  // 4. Tag first two functions
  auto funcs = client->ListFunctions(0, UINT64_MAX, 2, 0);
  if (!funcs.ok() || funcs.value->functions.empty()) {
    fprintf(stderr, "ListFunctions failed or empty\n");
    return 1;
  }

  printf("\n--- Tagging functions ---\n");
  for (const auto& f : funcs.value->functions) {
    auto r = client->TagFunction(f.entry_address, "crypto");
    printf("  TagFunction(%s, 'crypto'): %s\n", f.name.c_str(),
           r.ok() ? "OK" : r.status.message.c_str());
  }

  // Also tag first function with 'network'
  uint64_t first_addr = funcs.value->functions[0].entry_address;
  auto r2 = client->TagFunction(first_addr, "network");
  printf("  TagFunction(%s, 'network'): %s\n",
         funcs.value->functions[0].name.c_str(),
         r2.ok() ? "OK" : r2.status.message.c_str());

  // 5. List all mappings
  printf("\n--- All tag mappings ---\n");
  auto mappings = client->ListFunctionTagMappings(0);
  if (mappings.ok()) {
    for (const auto& m : mappings.value->mappings) {
      printf("  0x%llx -> '%s'\n",
             (unsigned long long)m.function_entry, m.tag_name.c_str());
    }
  }

  // 6. List mappings for first function only
  printf("\n--- Tags for 0x%llx ---\n", (unsigned long long)first_addr);
  auto fm = client->ListFunctionTagMappings(first_addr);
  if (fm.ok()) {
    for (const auto& m : fm.value->mappings) {
      printf("  '%s'\n", m.tag_name.c_str());
    }
  }

  // 7. Untag and clean up
  printf("\n--- Cleanup ---\n");
  for (const auto& f : funcs.value->functions) {
    client->UntagFunction(f.entry_address, "crypto");
  }
  client->UntagFunction(first_addr, "network");
  printf("  Untagged all functions\n");

  client->DeleteFunctionTag("crypto");
  client->DeleteFunctionTag("network");
  printf("  Deleted both tags\n");

  return 0;
}
