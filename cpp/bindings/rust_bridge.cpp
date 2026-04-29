// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// rust_bridge.cpp — implementations for the cxx FFI bridge declared in
// rust_bridge.hpp. Mirrors python_bindings.cpp's mapping from C++
// libghidra::client::IClient onto a serialization-friendly surface; the
// difference is we emit JSON strings instead of nb::dict.

#include "libghidra/rust_bridge.hpp"

#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "libghidra/ghidra.hpp"

// cxx-generated header: defines `libghidra::ffi::CreateOptions` (the Rust
// shared struct declared in `rust/src/local_ffi.rs`) and the mangled
// declarations of every bridge method. cxx-build emits the header at
// `<OUT_DIR>/cxxbridge/include/<crate>/<path-to-bridge>.rs.h`.
#include "libghidra/src/local_ffi.rs.h"

namespace libghidra {
namespace ffi {

using libghidra::client::BasicBlockRecord;
using libghidra::client::Capability;
using libghidra::client::CFGEdgeRecord;
using libghidra::client::DecompileLocalRecord;
using libghidra::client::DecompileTokenRecord;
using libghidra::client::DecompilationRecord;
using libghidra::client::DefinedStringRecord;
using libghidra::client::FunctionRecord;
using libghidra::client::HealthStatus;
using libghidra::client::InstructionRecord;
using libghidra::client::LocalClientOptions;
using libghidra::client::MemoryBlockRecord;
using libghidra::client::OpenProgramRequest;
using libghidra::client::ShutdownPolicy;
using libghidra::client::SymbolRecord;
using libghidra::client::TypeMemberRecord;
using libghidra::client::TypeRecord;
using libghidra::client::XrefRecord;

// ---------------------------------------------------------------------------
// StatusOr<T> unwrap (mirrors python_bindings.cpp::unwrap)
// ---------------------------------------------------------------------------
template <typename T>
static T unwrap(libghidra::client::StatusOr<T>&& result) {
  if (!result.ok()) {
    throw std::runtime_error(result.status.code + ": " + result.status.message);
  }
  return std::move(*result.value);
}

// ===========================================================================
// Minimal JSON writer
//
// Stream-based; we never need to parse JSON on the C++ side, only emit it.
// Output is compact (no whitespace) and ASCII-safe (UTF-8 passthrough; only
// the JSON-mandated escapes are applied).
// ===========================================================================

class Json {
 public:
  Json() = default;

  std::string take() { return std::move(buf_); }

  // -- Containers --------------------------------------------------------
  Json& begin_obj() { sep_(); buf_.push_back('{'); needs_comma_ = false; return *this; }
  Json& end_obj()   { buf_.push_back('}'); needs_comma_ = true; return *this; }
  Json& begin_arr() { sep_(); buf_.push_back('['); needs_comma_ = false; return *this; }
  Json& end_arr()   { buf_.push_back(']'); needs_comma_ = true; return *this; }

  // -- Object keys -------------------------------------------------------
  Json& key(const char* k) {
    sep_();
    write_str_(k);
    buf_.push_back(':');
    needs_comma_ = false;
    return *this;
  }

  // -- Scalars -----------------------------------------------------------
  Json& str(const std::string& s) { sep_(); write_str_(s.c_str(), s.size()); needs_comma_ = true; return *this; }
  Json& str(const char* s)        { sep_(); write_str_(s); needs_comma_ = true; return *this; }
  Json& boolean(bool b)           { sep_(); buf_ += b ? "true" : "false"; needs_comma_ = true; return *this; }
  Json& null()                    { sep_(); buf_ += "null"; needs_comma_ = true; return *this; }
  Json& num(int v)                { sep_(); buf_ += std::to_string(v); needs_comma_ = true; return *this; }
  Json& num(int64_t v)            { sep_(); buf_ += std::to_string(v); needs_comma_ = true; return *this; }
  Json& num(uint32_t v)           { sep_(); buf_ += std::to_string(v); needs_comma_ = true; return *this; }
  Json& num(uint64_t v)           { sep_(); buf_ += std::to_string(v); needs_comma_ = true; return *this; }

  // -- Convenience field setters ----------------------------------------
  Json& field(const char* k, const std::string& v) { return key(k).str(v); }
  Json& field(const char* k, const char* v)        { return key(k).str(v); }
  Json& field(const char* k, bool v)               { return key(k).boolean(v); }
  Json& field(const char* k, int v)                { return key(k).num(v); }
  Json& field(const char* k, int64_t v)            { return key(k).num(v); }
  Json& field(const char* k, uint32_t v)           { return key(k).num(v); }
  Json& field(const char* k, uint64_t v)           { return key(k).num(v); }

 private:
  void sep_() {
    if (needs_comma_) buf_.push_back(',');
  }

  void write_str_(const char* s) { write_str_(s, std::char_traits<char>::length(s)); }
  void write_str_(const char* s, size_t n) {
    buf_.push_back('"');
    for (size_t i = 0; i < n; ++i) {
      unsigned char c = static_cast<unsigned char>(s[i]);
      switch (c) {
        case '"':  buf_ += "\\\""; break;
        case '\\': buf_ += "\\\\"; break;
        case '\b': buf_ += "\\b"; break;
        case '\f': buf_ += "\\f"; break;
        case '\n': buf_ += "\\n"; break;
        case '\r': buf_ += "\\r"; break;
        case '\t': buf_ += "\\t"; break;
        default:
          if (c < 0x20) {
            char esc[8];
            std::snprintf(esc, sizeof(esc), "\\u%04x", static_cast<unsigned>(c));
            buf_ += esc;
          } else {
            buf_.push_back(static_cast<char>(c));
          }
      }
    }
    buf_.push_back('"');
  }

  std::string buf_;
  bool needs_comma_ = false;
};

// ---------------------------------------------------------------------------
// Record -> JSON encoders (mirror python_bindings.cpp::to_dict)
// ---------------------------------------------------------------------------

static void encode(Json& j, const FunctionRecord& r) {
  j.begin_obj()
    .field("entry_address", r.entry_address)
    .field("name", r.name)
    .field("start_address", r.start_address)
    .field("end_address", r.end_address)
    .field("size", r.size)
    .field("namespace_name", r.namespace_name)
    .field("prototype", r.prototype)
    .field("is_thunk", r.is_thunk)
    .field("parameter_count", r.parameter_count)
    .end_obj();
}

static void encode(Json& j, const SymbolRecord& r) {
  j.begin_obj()
    .field("symbol_id", r.symbol_id)
    .field("address", r.address)
    .field("name", r.name)
    .field("full_name", r.full_name)
    .field("type", r.type)
    .field("namespace_name", r.namespace_name)
    .field("source", r.source)
    .field("is_primary", r.is_primary)
    .field("is_external", r.is_external)
    .field("is_dynamic", r.is_dynamic)
    .end_obj();
}

static void encode(Json& j, const DecompileLocalRecord& r) {
  j.begin_obj()
    .field("local_id", r.local_id)
    .field("kind", static_cast<int>(r.kind))
    .field("name", r.name)
    .field("data_type", r.data_type)
    .field("storage", r.storage)
    .field("ordinal", r.ordinal)
    .end_obj();
}

static void encode(Json& j, const DecompileTokenRecord& r) {
  j.begin_obj()
    .field("text", r.text)
    .field("kind", static_cast<int>(r.kind))
    .field("line_number", r.line_number)
    .field("column_offset", r.column_offset)
    .field("var_name", r.var_name)
    .field("var_type", r.var_type)
    .field("var_storage", r.var_storage)
    .end_obj();
}

static void encode(Json& j, const DecompilationRecord& r) {
  j.begin_obj()
    .field("function_entry_address", r.function_entry_address)
    .field("function_name", r.function_name)
    .field("prototype", r.prototype)
    .field("pseudocode", r.pseudocode)
    .field("completed", r.completed)
    .field("is_fallback", r.is_fallback)
    .field("error_message", r.error_message)
    .key("locals").begin_arr();
  for (const auto& l : r.locals) encode(j, l);
  j.end_arr().key("tokens").begin_arr();
  for (const auto& t : r.tokens) encode(j, t);
  j.end_arr().end_obj();
}

static void encode(Json& j, const InstructionRecord& r) {
  j.begin_obj()
    .field("address", r.address)
    .field("mnemonic", r.mnemonic)
    .field("operand_text", r.operand_text)
    .field("disassembly", r.disassembly)
    .field("length", r.length)
    .end_obj();
}

static void encode(Json& j, const MemoryBlockRecord& r) {
  j.begin_obj()
    .field("name", r.name)
    .field("start_address", r.start_address)
    .field("end_address", r.end_address)
    .field("size", r.size)
    .field("is_read", r.is_read)
    .field("is_write", r.is_write)
    .field("is_execute", r.is_execute)
    .field("is_volatile", r.is_volatile)
    .field("is_initialized", r.is_initialized)
    .field("source_name", r.source_name)
    .field("comment", r.comment)
    .end_obj();
}

static void encode(Json& j, const XrefRecord& r) {
  j.begin_obj()
    .field("from_address", r.from_address)
    .field("to_address", r.to_address)
    .field("operand_index", r.operand_index)
    .field("ref_type", r.ref_type)
    .field("is_primary", r.is_primary)
    .field("source", r.source)
    .field("symbol_id", r.symbol_id)
    .field("is_external", r.is_external)
    .field("is_memory", r.is_memory)
    .field("is_flow", r.is_flow)
    .end_obj();
}

static void encode(Json& j, const TypeRecord& r) {
  j.begin_obj()
    .field("type_id", r.type_id)
    .field("name", r.name)
    .field("path_name", r.path_name)
    .field("category_path", r.category_path)
    .field("display_name", r.display_name)
    .field("kind", r.kind)
    .field("length", r.length)
    .field("is_not_yet_defined", r.is_not_yet_defined)
    .field("source_archive", r.source_archive)
    .field("universal_id", r.universal_id)
    .end_obj();
}

static void encode(Json& j, const TypeMemberRecord& r) {
  j.begin_obj()
    .field("parent_type_id", r.parent_type_id)
    .field("parent_type_path_name", r.parent_type_path_name)
    .field("parent_type_name", r.parent_type_name)
    .field("ordinal", r.ordinal)
    .field("name", r.name)
    .field("member_type", r.member_type)
    .field("offset", r.offset)
    .field("size", r.size)
    .field("comment", r.comment)
    .end_obj();
}

static void encode(Json& j, const BasicBlockRecord& r) {
  j.begin_obj()
    .field("function_entry", r.function_entry)
    .field("start_address", r.start_address)
    .field("end_address", r.end_address)
    .field("in_degree", r.in_degree)
    .field("out_degree", r.out_degree)
    .end_obj();
}

static void encode(Json& j, const CFGEdgeRecord& r) {
  j.begin_obj()
    .field("function_entry", r.function_entry)
    .field("src_block_start", r.src_block_start)
    .field("dst_block_start", r.dst_block_start)
    .field("edge_kind", r.edge_kind)
    .end_obj();
}

static void encode(Json& j, const DefinedStringRecord& r) {
  j.begin_obj()
    .field("address", r.address)
    .field("value", r.value)
    .field("length", r.length)
    .field("data_type", r.data_type)
    .field("encoding", r.encoding)
    .end_obj();
}

static void encode(Json& j, const HealthStatus& r) {
  j.begin_obj()
    .field("ok", r.ok)
    .field("service_name", r.service_name)
    .field("service_version", r.service_version)
    .field("host_mode", r.host_mode)
    .field("program_revision", r.program_revision)
    .key("warnings").begin_arr();
  for (const auto& w : r.warnings) j.str(w);
  j.end_arr().end_obj();
}

static void encode(Json& j, const Capability& r) {
  j.begin_obj()
    .field("id", r.id)
    .field("status", r.status)
    .field("note", r.note)
    .end_obj();
}

template <typename T>
static rust::String encode_list(const std::vector<T>& items) {
  Json j;
  j.begin_arr();
  for (const auto& item : items) encode(j, item);
  j.end_arr();
  return rust::String(j.take());
}

template <typename T>
static rust::String encode_one(const T& r) {
  Json j;
  encode(j, r);
  return rust::String(j.take());
}

static std::string str_of(rust::Str s) { return std::string(s); }

// ===========================================================================
// LocalClientHandle implementation
// ===========================================================================

LocalClientHandle::LocalClientHandle(std::unique_ptr<libghidra::client::IClient> impl)
    : impl_(std::move(impl)) {
  if (!impl_) {
    throw std::runtime_error("config_error: CreateLocalClient returned null");
  }
}

LocalClientHandle::~LocalClientHandle() = default;

// --- Health -----------------------------------------------------------------

rust::String LocalClientHandle::get_status_json() const {
  auto resp = unwrap(impl_->GetStatus());
  return encode_one(resp);
}

rust::String LocalClientHandle::get_capabilities_json() const {
  auto items = unwrap(impl_->GetCapabilities());
  return encode_list(items);
}

// --- Session ----------------------------------------------------------------

rust::String LocalClientHandle::open_program_json(rust::Str program_path,
                                                  bool analyze,
                                                  bool read_only,
                                                  rust::Str project_path,
                                                  rust::Str project_name,
                                                  rust::Str language_id,
                                                  rust::Str compiler_spec_id,
                                                  rust::Str format,
                                                  uint64_t base_address) const {
  OpenProgramRequest req;
  req.program_path = str_of(program_path);
  req.analyze = analyze;
  req.read_only = read_only;
  req.project_path = str_of(project_path);
  req.project_name = str_of(project_name);
  req.language_id = str_of(language_id);
  req.compiler_spec_id = str_of(compiler_spec_id);
  req.format = str_of(format);
  req.base_address = base_address;

  auto resp = unwrap(impl_->OpenProgram(req));
  Json j;
  j.begin_obj()
    .field("program_name", resp.program_name)
    .field("language_id", resp.language_id)
    .field("compiler_spec", resp.compiler_spec)
    .field("image_base", resp.image_base)
    .end_obj();
  return rust::String(j.take());
}

bool LocalClientHandle::close_program(int32_t policy) const {
  auto resp = unwrap(impl_->CloseProgram(static_cast<ShutdownPolicy>(policy)));
  return resp.closed;
}

bool LocalClientHandle::save_program() const {
  return unwrap(impl_->SaveProgram()).saved;
}

bool LocalClientHandle::discard_program() const {
  return unwrap(impl_->DiscardProgram()).discarded;
}

uint64_t LocalClientHandle::get_revision() const {
  return unwrap(impl_->GetRevision()).revision;
}

// --- Functions --------------------------------------------------------------

rust::String LocalClientHandle::get_function_json(uint64_t address) const {
  auto resp = unwrap(impl_->GetFunction(address));
  if (!resp.function.has_value()) return rust::String("");
  return encode_one(resp.function.value());
}

rust::String LocalClientHandle::list_functions_json(uint64_t range_start,
                                                    uint64_t range_end,
                                                    int32_t limit,
                                                    int32_t offset) const {
  auto resp = unwrap(impl_->ListFunctions(range_start, range_end, limit, offset));
  return encode_list(resp.functions);
}

rust::String LocalClientHandle::rename_function_json(uint64_t address,
                                                     rust::Str new_name) const {
  auto resp = unwrap(impl_->RenameFunction(address, str_of(new_name)));
  Json j;
  j.begin_obj()
    .field("renamed", resp.renamed)
    .field("name", resp.name)
    .end_obj();
  return rust::String(j.take());
}

rust::String LocalClientHandle::list_basic_blocks_json(uint64_t range_start,
                                                       uint64_t range_end,
                                                       int32_t limit,
                                                       int32_t offset) const {
  auto resp = unwrap(impl_->ListBasicBlocks(range_start, range_end, limit, offset));
  return encode_list(resp.blocks);
}

rust::String LocalClientHandle::list_cfg_edges_json(uint64_t range_start,
                                                    uint64_t range_end,
                                                    int32_t limit,
                                                    int32_t offset) const {
  auto resp = unwrap(impl_->ListCFGEdges(range_start, range_end, limit, offset));
  return encode_list(resp.edges);
}

// --- Decompiler -------------------------------------------------------------

rust::String LocalClientHandle::get_decompilation_json(uint64_t address,
                                                       int32_t timeout_ms) const {
  auto resp = unwrap(impl_->GetDecompilation(address, timeout_ms));
  if (!resp.decompilation.has_value()) return rust::String("");
  return encode_one(resp.decompilation.value());
}

rust::String LocalClientHandle::list_decompilations_json(uint64_t range_start,
                                                         uint64_t range_end,
                                                         int32_t limit,
                                                         int32_t offset,
                                                         int32_t timeout_ms) const {
  auto resp = unwrap(impl_->ListDecompilations(range_start, range_end, limit, offset, timeout_ms));
  return encode_list(resp.decompilations);
}

// --- Symbols ----------------------------------------------------------------

rust::String LocalClientHandle::get_symbol_json(uint64_t address) const {
  auto resp = unwrap(impl_->GetSymbol(address));
  if (!resp.symbol.has_value()) return rust::String("");
  return encode_one(resp.symbol.value());
}

rust::String LocalClientHandle::list_symbols_json(uint64_t range_start,
                                                  uint64_t range_end,
                                                  int32_t limit,
                                                  int32_t offset) const {
  auto resp = unwrap(impl_->ListSymbols(range_start, range_end, limit, offset));
  return encode_list(resp.symbols);
}

rust::String LocalClientHandle::rename_symbol_json(uint64_t address,
                                                   rust::Str new_name) const {
  auto resp = unwrap(impl_->RenameSymbol(address, str_of(new_name)));
  Json j;
  j.begin_obj()
    .field("renamed", resp.renamed)
    .field("name", resp.name)
    .end_obj();
  return rust::String(j.take());
}

// --- Memory -----------------------------------------------------------------

rust::Vec<uint8_t> LocalClientHandle::read_bytes(uint64_t address, uint32_t length) const {
  auto resp = unwrap(impl_->ReadBytes(address, length));
  rust::Vec<uint8_t> out;
  out.reserve(resp.data.size());
  for (auto b : resp.data) out.push_back(b);
  return out;
}

rust::String LocalClientHandle::list_memory_blocks_json(int32_t limit, int32_t offset) const {
  auto resp = unwrap(impl_->ListMemoryBlocks(limit, offset));
  return encode_list(resp.blocks);
}

// --- Listing ----------------------------------------------------------------

rust::String LocalClientHandle::get_instruction_json(uint64_t address) const {
  auto resp = unwrap(impl_->GetInstruction(address));
  if (!resp.instruction.has_value()) return rust::String("");
  return encode_one(resp.instruction.value());
}

rust::String LocalClientHandle::list_instructions_json(uint64_t range_start,
                                                       uint64_t range_end,
                                                       int32_t limit,
                                                       int32_t offset) const {
  auto resp = unwrap(impl_->ListInstructions(range_start, range_end, limit, offset));
  return encode_list(resp.instructions);
}

rust::String LocalClientHandle::list_defined_strings_json(uint64_t range_start,
                                                          uint64_t range_end,
                                                          int32_t limit,
                                                          int32_t offset) const {
  auto resp = unwrap(impl_->ListDefinedStrings(range_start, range_end, limit, offset));
  return encode_list(resp.strings);
}

// --- Xrefs ------------------------------------------------------------------

rust::String LocalClientHandle::list_xrefs_json(uint64_t range_start,
                                                uint64_t range_end,
                                                int32_t limit,
                                                int32_t offset) const {
  auto resp = unwrap(impl_->ListXrefs(range_start, range_end, limit, offset));
  return encode_list(resp.xrefs);
}

// --- Types ------------------------------------------------------------------

rust::String LocalClientHandle::get_type_json(rust::Str path) const {
  auto resp = unwrap(impl_->GetType(str_of(path)));
  if (!resp.type.has_value()) return rust::String("");
  return encode_one(resp.type.value());
}

rust::String LocalClientHandle::list_types_json(rust::Str query,
                                                int32_t limit,
                                                int32_t offset) const {
  auto resp = unwrap(impl_->ListTypes(str_of(query), limit, offset));
  return encode_list(resp.types);
}

rust::String LocalClientHandle::list_type_members_json(rust::Str type_id_or_path,
                                                       int32_t limit,
                                                       int32_t offset) const {
  auto resp = unwrap(impl_->ListTypeMembers(str_of(type_id_or_path), limit, offset));
  return encode_list(resp.members);
}

// ===========================================================================
// Factory
// ===========================================================================

std::unique_ptr<LocalClientHandle> create_local_client(const CreateOptions& opts) {
  LocalClientOptions o;
  o.ghidra_root = std::string(opts.ghidra_root);
  o.state_path = std::string(opts.state_path);
  o.default_arch = std::string(opts.default_arch);
  o.pool_size = opts.pool_size;
  auto impl = libghidra::client::CreateLocalClient(std::move(o));
  if (!impl) {
    throw std::runtime_error("config_error: CreateLocalClient returned null");
  }
  return std::make_unique<LocalClientHandle>(std::move(impl));
}

}  // namespace ffi
}  // namespace libghidra
