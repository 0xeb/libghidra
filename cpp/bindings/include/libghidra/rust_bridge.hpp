// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// rust_bridge.hpp — C++ surface for the cxx FFI bridge into the Rust
// libghidra crate's `local` feature. Mirrors python_bindings.cpp in
// purpose: turns the C++ libghidra::client::IClient API into something
// callable from Rust.
//
// The bridge returns each result as a JSON string (rust::String). Rust
// deserializes those strings into the public model types. JSON was
// chosen to avoid hand-mirroring ~25 record structs across the cxx
// bridge — see plan section "JSON-bridge perf" for the trade-off.
//
// Failures throw std::runtime_error; cxx maps that into Rust Err(...).

#pragma once

#include <memory>
#include <string>

// cxx runtime; provides rust::String, rust::Slice, etc.
#include "rust/cxx.h"

// libghidra core
#include "libghidra/api.hpp"
#include "libghidra/local.hpp"

namespace libghidra {
namespace ffi {

// Forward-declared by the cxx-generated header (`local_ffi.rs.h`); the
// definition lives on the Rust side. We just need to see the name here so
// that bridge functions taking `const CreateOptions&` can be declared.
struct CreateOptions;

// Opaque handle wrapping the C++ IClient. Held as `UniquePtr<LocalClientHandle>`
// on the Rust side. All bridge methods are declared as members so cxx can
// generate `LocalClientHandle$method` shims that thunk into these.
class LocalClientHandle {
 public:
  explicit LocalClientHandle(std::unique_ptr<libghidra::client::IClient> impl);
  ~LocalClientHandle();

  // --- Health -----------------------------------------------------------
  rust::String get_status_json() const;
  rust::String get_capabilities_json() const;

  // --- Session ----------------------------------------------------------
  rust::String open_program_json(rust::Str program_path,
                                 bool analyze,
                                 bool read_only,
                                 rust::Str project_path,
                                 rust::Str project_name,
                                 rust::Str language_id,
                                 rust::Str compiler_spec_id,
                                 rust::Str format,
                                 uint64_t base_address) const;
  bool close_program(int32_t policy) const;
  bool save_program() const;
  bool discard_program() const;
  uint64_t get_revision() const;

  // --- Functions --------------------------------------------------------
  rust::String get_function_json(uint64_t address) const;     // "" for None
  rust::String list_functions_json(uint64_t range_start,
                                   uint64_t range_end,
                                   int32_t limit,
                                   int32_t offset) const;
  rust::String rename_function_json(uint64_t address,
                                    rust::Str new_name) const;
  rust::String list_basic_blocks_json(uint64_t range_start,
                                      uint64_t range_end,
                                      int32_t limit,
                                      int32_t offset) const;
  rust::String list_cfg_edges_json(uint64_t range_start,
                                   uint64_t range_end,
                                   int32_t limit,
                                   int32_t offset) const;

  // --- Decompiler -------------------------------------------------------
  rust::String get_decompilation_json(uint64_t address,
                                      int32_t timeout_ms) const;  // "" for None
  rust::String list_decompilations_json(uint64_t range_start,
                                        uint64_t range_end,
                                        int32_t limit,
                                        int32_t offset,
                                        int32_t timeout_ms) const;

  // --- Symbols ----------------------------------------------------------
  rust::String get_symbol_json(uint64_t address) const;     // "" for None
  rust::String list_symbols_json(uint64_t range_start,
                                 uint64_t range_end,
                                 int32_t limit,
                                 int32_t offset) const;
  rust::String rename_symbol_json(uint64_t address,
                                  rust::Str new_name) const;

  // --- Memory -----------------------------------------------------------
  rust::Vec<uint8_t> read_bytes(uint64_t address, uint32_t length) const;
  rust::String list_memory_blocks_json(int32_t limit, int32_t offset) const;

  // --- Listing ----------------------------------------------------------
  rust::String get_instruction_json(uint64_t address) const;   // "" for None
  rust::String list_instructions_json(uint64_t range_start,
                                      uint64_t range_end,
                                      int32_t limit,
                                      int32_t offset) const;
  rust::String list_defined_strings_json(uint64_t range_start,
                                         uint64_t range_end,
                                         int32_t limit,
                                         int32_t offset) const;

  // --- Xrefs ------------------------------------------------------------
  rust::String list_xrefs_json(uint64_t range_start,
                               uint64_t range_end,
                               int32_t limit,
                               int32_t offset) const;

  // --- Types ------------------------------------------------------------
  rust::String get_type_json(rust::Str path) const;            // "" for None
  rust::String list_types_json(rust::Str query,
                               int32_t limit,
                               int32_t offset) const;
  rust::String list_type_members_json(rust::Str type_id_or_path,
                                      int32_t limit,
                                      int32_t offset) const;

 private:
  std::unique_ptr<libghidra::client::IClient> impl_;
};

// Factory: mirrors python_bindings.cpp `create_local_client`. Throws on
// engine init failure — cxx propagates that as Err(...) on the Rust side.
std::unique_ptr<LocalClientHandle> create_local_client(const CreateOptions& opts);

}  // namespace ffi
}  // namespace libghidra
