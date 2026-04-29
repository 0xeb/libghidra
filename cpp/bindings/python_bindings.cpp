// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// nanobind bindings for libghidra LocalClient.
// Exposes the offline decompiler backend to Python as libghidra._libghidra.
// Uses stable ABI — one .pyd for all Python 3.12+.

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

#include "libghidra/ghidra.hpp"

namespace nb = nanobind;
using namespace libghidra::client;

// ---------------------------------------------------------------------------
// StatusOr<T> helper: extract value or throw Python ValueError
// ---------------------------------------------------------------------------

template <typename T>
static T unwrap(StatusOr<T>&& result) {
  if (!result.ok()) {
    throw nb::value_error((result.status.code + ": " + result.status.message).c_str());
  }
  return std::move(*result.value);
}

// ---------------------------------------------------------------------------
// Conversion helpers: C++ records -> Python dicts
// ---------------------------------------------------------------------------

static nb::dict to_dict(const FunctionRecord& r) {
  nb::dict d;
  d["entry_address"] = r.entry_address;
  d["name"] = r.name;
  d["start_address"] = r.start_address;
  d["end_address"] = r.end_address;
  d["size"] = r.size;
  d["namespace_name"] = r.namespace_name;
  d["prototype"] = r.prototype;
  d["is_thunk"] = r.is_thunk;
  d["parameter_count"] = r.parameter_count;
  return d;
}

static nb::dict to_dict(const SymbolRecord& r) {
  nb::dict d;
  d["symbol_id"] = r.symbol_id;
  d["address"] = r.address;
  d["name"] = r.name;
  d["full_name"] = r.full_name;
  d["type"] = r.type;
  d["namespace_name"] = r.namespace_name;
  d["source"] = r.source;
  d["is_primary"] = r.is_primary;
  d["is_external"] = r.is_external;
  d["is_dynamic"] = r.is_dynamic;
  return d;
}

static nb::dict to_dict(const DecompileLocalRecord& r) {
  nb::dict d;
  d["local_id"] = r.local_id;
  d["kind"] = static_cast<int>(r.kind);
  d["name"] = r.name;
  d["data_type"] = r.data_type;
  d["storage"] = r.storage;
  d["ordinal"] = r.ordinal;
  return d;
}

static nb::dict to_dict(const DecompileTokenRecord& r) {
  nb::dict d;
  d["text"] = r.text;
  d["kind"] = static_cast<int>(r.kind);
  d["line_number"] = r.line_number;
  d["column_offset"] = r.column_offset;
  d["var_name"] = r.var_name;
  d["var_type"] = r.var_type;
  d["var_storage"] = r.var_storage;
  return d;
}

static nb::dict to_dict(const DecompilationRecord& r) {
  nb::dict d;
  d["function_entry_address"] = r.function_entry_address;
  d["function_name"] = r.function_name;
  d["prototype"] = r.prototype;
  d["pseudocode"] = r.pseudocode;
  d["completed"] = r.completed;
  d["is_fallback"] = r.is_fallback;
  d["error_message"] = r.error_message;
  nb::list locals_list;
  for (const auto& l : r.locals) locals_list.append(to_dict(l));
  d["locals"] = locals_list;
  nb::list tokens_list;
  for (const auto& t : r.tokens) tokens_list.append(to_dict(t));
  d["tokens"] = tokens_list;
  return d;
}

static nb::dict to_dict(const InstructionRecord& r) {
  nb::dict d;
  d["address"] = r.address;
  d["mnemonic"] = r.mnemonic;
  d["operand_text"] = r.operand_text;
  d["disassembly"] = r.disassembly;
  d["length"] = r.length;
  return d;
}

static nb::dict to_dict(const MemoryBlockRecord& r) {
  nb::dict d;
  d["name"] = r.name;
  d["start_address"] = r.start_address;
  d["end_address"] = r.end_address;
  d["size"] = r.size;
  d["is_read"] = r.is_read;
  d["is_write"] = r.is_write;
  d["is_execute"] = r.is_execute;
  d["is_volatile"] = r.is_volatile;
  d["is_initialized"] = r.is_initialized;
  d["source_name"] = r.source_name;
  d["comment"] = r.comment;
  return d;
}

static nb::dict to_dict(const XrefRecord& r) {
  nb::dict d;
  d["from_address"] = r.from_address;
  d["to_address"] = r.to_address;
  d["operand_index"] = r.operand_index;
  d["ref_type"] = r.ref_type;
  d["is_primary"] = r.is_primary;
  d["source"] = r.source;
  d["symbol_id"] = r.symbol_id;
  d["is_external"] = r.is_external;
  d["is_memory"] = r.is_memory;
  d["is_flow"] = r.is_flow;
  return d;
}

static nb::dict to_dict(const TypeRecord& r) {
  nb::dict d;
  d["type_id"] = r.type_id;
  d["name"] = r.name;
  d["path_name"] = r.path_name;
  d["category_path"] = r.category_path;
  d["display_name"] = r.display_name;
  d["kind"] = r.kind;
  d["length"] = r.length;
  d["is_not_yet_defined"] = r.is_not_yet_defined;
  d["source_archive"] = r.source_archive;
  d["universal_id"] = r.universal_id;
  return d;
}

static nb::dict to_dict(const TypeMemberRecord& r) {
  nb::dict d;
  d["parent_type_id"] = r.parent_type_id;
  d["parent_type_path_name"] = r.parent_type_path_name;
  d["parent_type_name"] = r.parent_type_name;
  d["ordinal"] = r.ordinal;
  d["name"] = r.name;
  d["member_type"] = r.member_type;
  d["offset"] = r.offset;
  d["size"] = r.size;
  d["comment"] = r.comment;
  return d;
}

static nb::dict to_dict(const BasicBlockRecord& r) {
  nb::dict d;
  d["function_entry"] = r.function_entry;
  d["start_address"] = r.start_address;
  d["end_address"] = r.end_address;
  d["in_degree"] = r.in_degree;
  d["out_degree"] = r.out_degree;
  return d;
}

static nb::dict to_dict(const CFGEdgeRecord& r) {
  nb::dict d;
  d["function_entry"] = r.function_entry;
  d["src_block_start"] = r.src_block_start;
  d["dst_block_start"] = r.dst_block_start;
  d["edge_kind"] = r.edge_kind;
  return d;
}

static nb::dict to_dict(const DefinedStringRecord& r) {
  nb::dict d;
  d["address"] = r.address;
  d["value"] = r.value;
  d["length"] = r.length;
  d["data_type"] = r.data_type;
  d["encoding"] = r.encoding;
  return d;
}

static nb::dict to_dict(const HealthStatus& r) {
  nb::dict d;
  d["ok"] = r.ok;
  d["service_name"] = r.service_name;
  d["service_version"] = r.service_version;
  d["host_mode"] = r.host_mode;
  d["program_revision"] = r.program_revision;
  // Convert warnings vector manually since nb::dict assignment from vector
  // needs an explicit nb::list
  nb::list warns;
  for (const auto& w : r.warnings) warns.append(w);
  d["warnings"] = warns;
  return d;
}

static nb::dict to_dict(const Capability& r) {
  nb::dict d;
  d["id"] = r.id;
  d["status"] = r.status;
  d["note"] = r.note;
  return d;
}

// ---------------------------------------------------------------------------
// List conversion helper
// ---------------------------------------------------------------------------

template <typename T>
static nb::list to_list(const std::vector<T>& vec) {
  nb::list result;
  for (const auto& item : vec) result.append(to_dict(item));
  return result;
}

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

NB_MODULE(_libghidra, m) {
  m.doc() = "libghidra native local backend (offline decompiler)";

  // ---- LocalClient class ----
  nb::class_<IClient>(m, "LocalClient")
      // --- Health ---
      .def("get_status", [](IClient& self) {
        return to_dict(unwrap(self.GetStatus()));
      })
      .def("get_capabilities", [](IClient& self) {
        return to_list(unwrap(self.GetCapabilities()));
      })

      // --- Session ---
      .def("open_program", [](IClient& self,
                               const std::string& program_path,
                               bool analyze,
                               bool read_only,
                               const std::string& project_path,
                               const std::string& project_name,
                               const std::string& language_id,
                               const std::string& compiler_spec_id,
                               const std::string& format,
                               uint64_t base_address) {
        OpenProgramRequest req;
        req.program_path = program_path;
        req.analyze = analyze;
        req.read_only = read_only;
        req.project_path = project_path;
        req.project_name = project_name;
        req.language_id = language_id;
        req.compiler_spec_id = compiler_spec_id;
        req.format = format;
        req.base_address = base_address;
        auto resp = unwrap(self.OpenProgram(req));
        nb::dict d;
        d["program_name"] = resp.program_name;
        d["language_id"] = resp.language_id;
        d["compiler_spec"] = resp.compiler_spec;
        d["image_base"] = resp.image_base;
        return d;
      }, nb::arg("program_path"),
         nb::arg("analyze") = false,
         nb::arg("read_only") = false,
         nb::arg("project_path") = "",
         nb::arg("project_name") = "",
         nb::arg("language_id") = "",
         nb::arg("compiler_spec_id") = "",
         nb::arg("format") = "",
         nb::arg("base_address") = static_cast<uint64_t>(0))

      .def("close_program", [](IClient& self, int policy) {
        auto resp = unwrap(self.CloseProgram(static_cast<ShutdownPolicy>(policy)));
        return resp.closed;
      }, nb::arg("policy") = 0)

      .def("save_program", [](IClient& self) {
        return unwrap(self.SaveProgram()).saved;
      })

      .def("discard_program", [](IClient& self) {
        return unwrap(self.DiscardProgram()).discarded;
      })

      .def("get_revision", [](IClient& self) {
        return unwrap(self.GetRevision()).revision;
      })

      // --- Functions ---
      .def("get_function", [](IClient& self, uint64_t address) -> nb::object {
        auto resp = unwrap(self.GetFunction(address));
        if (resp.function.has_value())
          return to_dict(resp.function.value());
        return nb::none();
      }, nb::arg("address"))

      .def("list_functions", [](IClient& self,
                                 uint64_t range_start,
                                 uint64_t range_end,
                                 int limit, int offset) {
        auto resp = unwrap(self.ListFunctions(range_start, range_end, limit, offset));
        return to_list(resp.functions);
      }, nb::arg("range_start") = 0, nb::arg("range_end") = 0,
         nb::arg("limit") = 0, nb::arg("offset") = 0)

      .def("rename_function", [](IClient& self, uint64_t address, const std::string& name) {
        auto resp = unwrap(self.RenameFunction(address, name));
        nb::dict d;
        d["renamed"] = resp.renamed;
        d["name"] = resp.name;
        return d;
      }, nb::arg("address"), nb::arg("new_name"))

      .def("list_basic_blocks", [](IClient& self,
                                    uint64_t range_start, uint64_t range_end,
                                    int limit, int offset) {
        return to_list(unwrap(self.ListBasicBlocks(range_start, range_end, limit, offset)).blocks);
      }, nb::arg("range_start") = 0, nb::arg("range_end") = 0,
         nb::arg("limit") = 0, nb::arg("offset") = 0)

      .def("list_cfg_edges", [](IClient& self,
                                 uint64_t range_start, uint64_t range_end,
                                 int limit, int offset) {
        return to_list(unwrap(self.ListCFGEdges(range_start, range_end, limit, offset)).edges);
      }, nb::arg("range_start") = 0, nb::arg("range_end") = 0,
         nb::arg("limit") = 0, nb::arg("offset") = 0)

      // --- Decompiler ---
      .def("get_decompilation", [](IClient& self, uint64_t address, int timeout_ms) -> nb::object {
        auto resp = unwrap(self.GetDecompilation(address, timeout_ms));
        if (resp.decompilation.has_value())
          return to_dict(resp.decompilation.value());
        return nb::none();
      }, nb::arg("address"), nb::arg("timeout_ms") = 30000)

      .def("list_decompilations", [](IClient& self,
                                      uint64_t range_start, uint64_t range_end,
                                      int limit, int offset, int timeout_ms) {
        auto resp = unwrap(self.ListDecompilations(range_start, range_end, limit, offset, timeout_ms));
        nb::list result;
        for (const auto& d : resp.decompilations) result.append(to_dict(d));
        return result;
      }, nb::arg("range_start") = 0, nb::arg("range_end") = 0,
         nb::arg("limit") = 0, nb::arg("offset") = 0,
         nb::arg("timeout_ms") = 30000)

      // --- Symbols ---
      .def("get_symbol", [](IClient& self, uint64_t address) -> nb::object {
        auto resp = unwrap(self.GetSymbol(address));
        if (resp.symbol.has_value())
          return to_dict(resp.symbol.value());
        return nb::none();
      }, nb::arg("address"))

      .def("list_symbols", [](IClient& self,
                               uint64_t range_start, uint64_t range_end,
                               int limit, int offset) {
        return to_list(unwrap(self.ListSymbols(range_start, range_end, limit, offset)).symbols);
      }, nb::arg("range_start") = 0, nb::arg("range_end") = 0,
         nb::arg("limit") = 0, nb::arg("offset") = 0)

      .def("rename_symbol", [](IClient& self, uint64_t address, const std::string& name) {
        auto resp = unwrap(self.RenameSymbol(address, name));
        nb::dict d;
        d["renamed"] = resp.renamed;
        d["name"] = resp.name;
        return d;
      }, nb::arg("address"), nb::arg("new_name"))

      // --- Memory ---
      .def("read_bytes", [](IClient& self, uint64_t address, uint32_t length) {
        auto resp = unwrap(self.ReadBytes(address, length));
        return nb::bytes(reinterpret_cast<const char*>(resp.data.data()), resp.data.size());
      }, nb::arg("address"), nb::arg("length"))

      .def("list_memory_blocks", [](IClient& self, int limit, int offset) {
        return to_list(unwrap(self.ListMemoryBlocks(limit, offset)).blocks);
      }, nb::arg("limit") = 0, nb::arg("offset") = 0)

      // --- Listing ---
      .def("get_instruction", [](IClient& self, uint64_t address) -> nb::object {
        auto resp = unwrap(self.GetInstruction(address));
        if (resp.instruction.has_value())
          return to_dict(resp.instruction.value());
        return nb::none();
      }, nb::arg("address"))

      .def("list_instructions", [](IClient& self,
                                    uint64_t range_start, uint64_t range_end,
                                    int limit, int offset) {
        return to_list(unwrap(self.ListInstructions(range_start, range_end, limit, offset)).instructions);
      }, nb::arg("range_start") = 0, nb::arg("range_end") = 0,
         nb::arg("limit") = 0, nb::arg("offset") = 0)

      .def("list_defined_strings", [](IClient& self,
                                       uint64_t range_start, uint64_t range_end,
                                       int limit, int offset) {
        return to_list(unwrap(self.ListDefinedStrings(range_start, range_end, limit, offset)).strings);
      }, nb::arg("range_start") = 0, nb::arg("range_end") = 0,
         nb::arg("limit") = 0, nb::arg("offset") = 0)

      // --- Xrefs ---
      .def("list_xrefs", [](IClient& self,
                             uint64_t range_start, uint64_t range_end,
                             int limit, int offset) {
        return to_list(unwrap(self.ListXrefs(range_start, range_end, limit, offset)).xrefs);
      }, nb::arg("range_start") = 0, nb::arg("range_end") = 0,
         nb::arg("limit") = 0, nb::arg("offset") = 0)

      // --- Types ---
      .def("get_type", [](IClient& self, const std::string& path) -> nb::object {
        auto resp = unwrap(self.GetType(path));
        if (resp.type.has_value())
          return to_dict(resp.type.value());
        return nb::none();
      }, nb::arg("path"))

      .def("list_types", [](IClient& self, const std::string& query, int limit, int offset) {
        return to_list(unwrap(self.ListTypes(query, limit, offset)).types);
      }, nb::arg("query") = "", nb::arg("limit") = 0, nb::arg("offset") = 0)

      .def("list_type_members", [](IClient& self, const std::string& type_id_or_path,
                                    int limit, int offset) {
        return to_list(unwrap(self.ListTypeMembers(type_id_or_path, limit, offset)).members);
      }, nb::arg("type_id_or_path"), nb::arg("limit") = 0, nb::arg("offset") = 0)
      ;

  // ---- Factory function ----
  m.def("create_local_client", [](const std::string& ghidra_root,
                                   const std::string& state_path,
                                   const std::string& default_arch,
                                   int pool_size) -> std::unique_ptr<IClient> {
    LocalClientOptions opts;
    opts.ghidra_root = ghidra_root;
    opts.state_path = state_path;
    opts.default_arch = default_arch;
    opts.pool_size = pool_size;
    return CreateLocalClient(std::move(opts));
  }, nb::arg("ghidra_root") = "",
     nb::arg("state_path") = "",
     nb::arg("default_arch") = "",
     nb::arg("pool_size") = 1,
     "Create an offline LocalClient backed by the Ghidra decompiler engine.");
}
