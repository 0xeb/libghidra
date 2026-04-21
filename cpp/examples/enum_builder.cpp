// enum_builder: Enum type operations via the local backend.
//
// Usage: enum_builder <binary_path> [ghidra_root] [arch]
//
// Demonstrates: CreateTypeEnum, AddTypeEnumMember, ListTypeEnumMembers,
//   RenameTypeEnumMember, SetTypeEnumMemberValue, SetTypeEnumMemberComment,
//   DeleteTypeEnumMember.
//
// If ghidra_root is omitted, uses embedded processor specs (no Ghidra needed).

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

#include "libghidra/ghidra.hpp"

static void print_enum_members(ghidra::Client* client, const std::string& name) {
  auto members = client->ListTypeEnumMembers(name, 0, 0);
  if (!members.ok()) {
    std::cerr << "  ListTypeEnumMembers failed: " << members.status.message << "\n";
    return;
  }
  std::cout << "  " << std::left
            << std::setw(6) << "ORD"
            << std::setw(20) << "NAME"
            << std::setw(10) << "VALUE"
            << "COMMENT\n";
  std::cout << "  " << std::string(42, '-') << "\n";
  for (const auto& m : members.value->members) {
    std::cout << "  " << std::left
              << std::setw(6) << m.ordinal
              << std::setw(20) << m.name
              << std::setw(10) << m.value
              << m.comment << "\n";
  }
}

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

  // --- Create enum ---
  auto cr = client->CreateTypeEnum("error_code_t", 4, false);
  std::cout << "CreateTypeEnum(error_code_t, 4 bytes, unsigned): "
            << (cr.ok() ? "OK" : cr.status.message) << "\n\n";

  // --- Add members ---
  struct { const char* name; int64_t value; } entries[] = {
    {"OK",      0},
    {"FAIL",    1},
    {"TIMEOUT", 2},
    {"RETRY",   3},
  };

  for (const auto& e : entries) {
    auto r = client->AddTypeEnumMember("error_code_t", e.name, e.value);
    std::cout << "AddTypeEnumMember(" << e.name << "=" << e.value << "): "
              << (r.ok() ? "OK" : r.status.message) << "\n";
  }

  // --- Show initial state ---
  std::cout << "\nInitial enum:\n";
  print_enum_members(client.get(), "error_code_t");

  // --- Rename FAIL -> ERROR (ordinal 1) ---
  auto ren = client->RenameTypeEnumMember("error_code_t", 1, "ERROR");
  std::cout << "\nRenameTypeEnumMember(ord=1, ERROR): "
            << (ren.ok() ? "OK" : ren.status.message) << "\n";

  // --- Change TIMEOUT value to 5 (ordinal 2) ---
  auto chval = client->SetTypeEnumMemberValue("error_code_t", 2, 5);
  std::cout << "SetTypeEnumMemberValue(ord=2, 5): "
            << (chval.ok() ? "OK" : chval.status.message) << "\n";

  // --- Add comment to RETRY (ordinal 3) ---
  auto cmt = client->SetTypeEnumMemberComment("error_code_t", 3, "Transient failure");
  std::cout << "SetTypeEnumMemberComment(ord=3): "
            << (cmt.ok() ? "OK" : cmt.status.message) << "\n";

  // --- Delete OK (ordinal 0) ---
  auto del = client->DeleteTypeEnumMember("error_code_t", 0);
  std::cout << "DeleteTypeEnumMember(ord=0): "
            << (del.ok() ? "OK" : del.status.message) << "\n";

  // --- Show final state ---
  std::cout << "\nFinal enum:\n";
  print_enum_members(client.get(), "error_code_t");

  // Cleanup
  client->DeleteTypeEnum("error_code_t");
  return 0;
}
