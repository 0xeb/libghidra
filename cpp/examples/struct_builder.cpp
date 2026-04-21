// struct_builder: Struct member operations via the local backend.
//
// Usage: struct_builder <binary_path> [ghidra_root] [arch]
//
// Demonstrates: CreateType, AddTypeMember, ListTypeMembers, RenameTypeMember,
//   SetTypeMemberType, SetTypeMemberComment, DeleteTypeMember.
//
// If ghidra_root is omitted, uses embedded processor specs (no Ghidra needed).

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

#include "libghidra/ghidra.hpp"

static void print_members(ghidra::Client* client, const std::string& type_name) {
  auto members = client->ListTypeMembers(type_name, 0, 0);
  if (!members.ok()) {
    std::cerr << "  ListTypeMembers failed: " << members.status.message << "\n";
    return;
  }
  std::cout << "  " << std::left
            << std::setw(6) << "ORD"
            << std::setw(8) << "OFFSET"
            << std::setw(20) << "NAME"
            << std::setw(16) << "TYPE"
            << "COMMENT\n";
  std::cout << "  " << std::string(56, '-') << "\n";
  for (const auto& m : members.value->members) {
    std::cout << "  " << std::left
              << std::setw(6) << m.ordinal
              << std::setw(8) << m.offset
              << std::setw(20) << m.name
              << std::setw(16) << m.member_type
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

  // --- Create struct ---
  auto cr = client->CreateType("packet_header_t", "struct", 10);
  std::cout << "CreateType(packet_header_t, 10): "
            << (cr.ok() ? "OK" : cr.status.message) << "\n\n";

  // --- Add fields incrementally ---
  struct { const char* name; const char* type; uint64_t size; } fields[] = {
    {"magic",   "uint",  4},
    {"version", "byte",  1},
    {"length",  "uint",  4},
    {"flags",   "byte",  1},
  };

  for (const auto& f : fields) {
    auto r = client->AddTypeMember("packet_header_t", f.name, f.type, f.size);
    std::cout << "AddTypeMember(" << f.name << ", " << f.type << "): "
              << (r.ok() ? "OK" : r.status.message) << "\n";
  }

  // --- Show initial layout ---
  std::cout << "\nInitial layout:\n";
  print_members(client.get(), "packet_header_t");

  // --- Rename a member ---
  auto ren = client->RenameTypeMember("packet_header_t", 1, "proto_version");
  std::cout << "\nRenameTypeMember(ord=1, proto_version): "
            << (ren.ok() ? "OK" : ren.status.message) << "\n";

  // --- Change a member's type ---
  auto chtype = client->SetTypeMemberType("packet_header_t", 2, "int");
  std::cout << "SetTypeMemberType(ord=2, int): "
            << (chtype.ok() ? "OK" : chtype.status.message) << "\n";

  // --- Add a comment to a member ---
  auto cmt = client->SetTypeMemberComment("packet_header_t", 3, "Bitmask: 0x01=compressed");
  std::cout << "SetTypeMemberComment(ord=3): "
            << (cmt.ok() ? "OK" : cmt.status.message) << "\n";

  // --- Delete a member ---
  auto del = client->DeleteTypeMember("packet_header_t", 0);
  std::cout << "DeleteTypeMember(ord=0): "
            << (del.ok() ? "OK" : del.status.message) << "\n";

  // --- Show final layout ---
  std::cout << "\nFinal layout:\n";
  print_members(client.get(), "packet_header_t");

  // Cleanup
  client->DeleteType("packet_header_t");
  return 0;
}
