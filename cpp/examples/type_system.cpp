// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// type_system: Type exploration and lifecycle via the local backend.
//
// Usage: type_system <binary_path> [ghidra_root] [arch]
//
// Demonstrates: ListTypes, GetType, CreateType, RenameType, DeleteType,
//   CreateTypeAlias, SetTypeAliasTarget, DeleteTypeAlias, ListTypeAliases,
//   ListTypeEnums, ListTypeUnions.
//
// If ghidra_root is omitted, uses embedded processor specs (no Ghidra needed).

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "libghidra/ghidra.hpp"

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0]
              << " <binary_path> [ghidra_root] [arch]\n";
    return 1;
  }

  const std::string binary_path = argv[1];
  const std::string ghidra_root = (argc >= 3) ? argv[2] : "";
  const std::string arch = (argc >= 4) ? argv[3] : "";

  auto client = ghidra::local({
      .ghidra_root = ghidra_root,
      .default_arch = arch,
  });

  ghidra::OpenRequest req;
  req.program_path = binary_path;
  auto open_result = client->OpenProgram(req);
  if (!open_result.ok()) {
    std::cerr << "Failed to load binary: " << open_result.status.message << "\n";
    return 1;
  }
  std::cout << "Loaded: " << open_result.value->program_name << "\n\n";

  // --- List built-in types ---
  auto types = client->ListTypes("", 20, 0);
  if (types.ok()) {
    std::cout << "Types (first " << types.value->types.size() << "):\n";
    for (const auto& t : types.value->types) {
      std::cout << "  " << t.name << "  kind=" << t.kind
                << "  size=" << t.length << "\n";
    }
  }

  // --- Get a specific type ---
  auto get = client->GetType("int");
  if (get.ok() && get.value->type) {
    std::cout << "\nGetType(int): " << get.value->type->name
              << "  kind=" << get.value->type->kind
              << "  size=" << get.value->type->length << "\n";
  }

  // --- Create a struct ---
  auto cr = client->CreateType("my_config_t", "struct", 16);
  std::cout << "\nCreateType(my_config_t, struct, 16): "
            << (cr.ok() ? "OK" : cr.status.message) << "\n";

  // --- Create an alias ---
  auto alias = client->CreateTypeAlias("config_ptr", "my_config_t *");
  std::cout << "CreateTypeAlias(config_ptr -> my_config_t *): "
            << (alias.ok() ? "OK" : alias.status.message) << "\n";

  // --- List aliases ---
  auto aliases = client->ListTypeAliases("", 0, 0);
  if (aliases.ok()) {
    std::cout << "\nType aliases (" << aliases.value->aliases.size() << "):\n";
    for (const auto& a : aliases.value->aliases) {
      std::cout << "  " << a.name << " -> " << a.target_type << "\n";
    }
  }

  // --- List enums ---
  auto enums = client->ListTypeEnums("", 0, 0);
  if (enums.ok()) {
    std::cout << "\nEnums (" << enums.value->enums.size() << "):\n";
    for (const auto& e : enums.value->enums) {
      std::cout << "  " << e.name << "  width=" << e.width << "\n";
    }
  }

  // --- List unions ---
  auto unions = client->ListTypeUnions("", 0, 0);
  if (unions.ok()) {
    std::cout << "\nUnions (" << unions.value->unions.size() << "):\n";
    for (const auto& u : unions.value->unions) {
      std::cout << "  " << u.name << "  size=" << u.size << "\n";
    }
  }

  // --- Rename the struct ---
  auto ren = client->RenameType("my_config_t", "app_config_t");
  std::cout << "\nRenameType(my_config_t -> app_config_t): "
            << (ren.ok() ? "OK" : ren.status.message) << "\n";

  // --- Retarget the alias ---
  auto retarget = client->SetTypeAliasTarget("config_ptr", "app_config_t *");
  std::cout << "SetTypeAliasTarget(config_ptr -> app_config_t *): "
            << (retarget.ok() ? "OK" : retarget.status.message) << "\n";

  // --- Cleanup: delete alias then type ---
  auto del_alias = client->DeleteTypeAlias("config_ptr");
  std::cout << "\nDeleteTypeAlias(config_ptr): "
            << (del_alias.ok() ? "OK" : del_alias.status.message) << "\n";

  auto del_type = client->DeleteType("app_config_t");
  std::cout << "DeleteType(app_config_t): "
            << (del_type.ok() ? "OK" : del_type.status.message) << "\n";

  return 0;
}
