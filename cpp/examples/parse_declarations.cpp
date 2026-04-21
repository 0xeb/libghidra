// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// parse_declarations: Import C type declarations, verify they exist, clean up.
//
// Usage: parse_declarations [host_url]

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

  // 2. Parse a block of C declarations
  const char* decls = R"(
    typedef enum ExampleOpcode {
      OP_NONE = 0,
      OP_INIT = 1,
      OP_PROCESS = 2,
      OP_SHUTDOWN = 3
    } ExampleOpcode;

    typedef struct ExampleHeader {
      int magic;
      int version;
      int flags;
    } ExampleHeader;

    typedef struct ExamplePacket {
      ExampleHeader header;
      ExampleOpcode opcode;
      int payload_size;
    } ExamplePacket;
  )";

  printf("\n--- Parsing C declarations ---\n");
  auto result = client->ParseDeclarations(decls);
  if (!result.ok()) {
    fprintf(stderr, "ParseDeclarations failed: %s\n",
            result.status.message.c_str());
    return 1;
  }
  printf("Types created: %d\n", result.value->types_created);
  for (const auto& name : result.value->type_names) {
    printf("  + %s\n", name.c_str());
  }
  if (!result.value->errors.empty()) {
    printf("Errors:\n");
    for (const auto& err : result.value->errors) {
      printf("  ! %s\n", err.c_str());
    }
  }

  // 3. Verify the types exist in the type system
  printf("\n--- Verifying types ---\n");
  const char* check_names[] = {
      "/ExampleOpcode", "/ExampleHeader", "/ExamplePacket"};
  for (const auto& name : check_names) {
    auto t = client->GetType(name);
    if (t.ok() && t.value->type) {
      printf("  %s: kind=%s length=%llu\n", name,
             t.value->type->kind.c_str(),
             (unsigned long long)t.value->type->length);
    } else {
      printf("  %s: NOT FOUND\n", name);
    }
  }

  // 4. Clean up: delete the types we created
  printf("\n--- Cleanup ---\n");
  client->DeleteType("/ExamplePacket");
  client->DeleteType("/ExampleHeader");
  client->DeleteType("/ExampleOpcode");
  printf("  Deleted all example types\n");

  return 0;
}
