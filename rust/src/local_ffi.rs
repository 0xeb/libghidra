// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// cxx FFI bridge to the C++ libghidra::local backend. The C++
// implementation lives in `cpp/bindings/rust_bridge.{hpp,cpp}` and links
// against `libghidra::local_whole`.
//
// Each "..._json" method returns a JSON-encoded payload that the wrapper
// in `local.rs` deserializes into the public model types. JSON keeps the
// bridge surface narrow — without it we would need to mirror every record
// type as a cxx-bridgeable struct in both languages.

#[cxx::bridge(namespace = "libghidra::ffi")]
pub(crate) mod ffi {
    /// Inputs to `create_local_client` (mirrors `LocalClientOptions` in
    /// `cpp/include/libghidra/local.hpp`). Defined on the Rust side so cxx
    /// can synthesise the matching C++ struct in `local_ffi.rs.h`.
    struct CreateOptions {
        ghidra_root: String,
        state_path: String,
        default_arch: String,
        pool_size: i32,
    }

    unsafe extern "C++" {
        include!("libghidra/rust_bridge.hpp");

        type LocalClientHandle;

        // -- Factory ------------------------------------------------------
        fn create_local_client(opts: &CreateOptions) -> Result<UniquePtr<LocalClientHandle>>;

        // -- Health -------------------------------------------------------
        fn get_status_json(self: &LocalClientHandle) -> Result<String>;
        fn get_capabilities_json(self: &LocalClientHandle) -> Result<String>;

        // -- Session ------------------------------------------------------
        #[allow(clippy::too_many_arguments)]
        fn open_program_json(
            self: &LocalClientHandle,
            program_path: &str,
            analyze: bool,
            read_only: bool,
            project_path: &str,
            project_name: &str,
            language_id: &str,
            compiler_spec_id: &str,
            format: &str,
            base_address: u64,
        ) -> Result<String>;
        fn close_program(self: &LocalClientHandle, policy: i32) -> Result<bool>;
        fn save_program(self: &LocalClientHandle) -> Result<bool>;
        fn discard_program(self: &LocalClientHandle) -> Result<bool>;
        fn get_revision(self: &LocalClientHandle) -> Result<u64>;

        // -- Functions ----------------------------------------------------
        fn get_function_json(self: &LocalClientHandle, address: u64) -> Result<String>;
        fn list_functions_json(
            self: &LocalClientHandle,
            range_start: u64,
            range_end: u64,
            limit: i32,
            offset: i32,
        ) -> Result<String>;
        fn rename_function_json(
            self: &LocalClientHandle,
            address: u64,
            new_name: &str,
        ) -> Result<String>;
        fn list_basic_blocks_json(
            self: &LocalClientHandle,
            range_start: u64,
            range_end: u64,
            limit: i32,
            offset: i32,
        ) -> Result<String>;
        fn list_cfg_edges_json(
            self: &LocalClientHandle,
            range_start: u64,
            range_end: u64,
            limit: i32,
            offset: i32,
        ) -> Result<String>;

        // -- Decompiler ---------------------------------------------------
        fn get_decompilation_json(
            self: &LocalClientHandle,
            address: u64,
            timeout_ms: i32,
        ) -> Result<String>;
        fn list_decompilations_json(
            self: &LocalClientHandle,
            range_start: u64,
            range_end: u64,
            limit: i32,
            offset: i32,
            timeout_ms: i32,
        ) -> Result<String>;

        // -- Symbols ------------------------------------------------------
        fn get_symbol_json(self: &LocalClientHandle, address: u64) -> Result<String>;
        fn list_symbols_json(
            self: &LocalClientHandle,
            range_start: u64,
            range_end: u64,
            limit: i32,
            offset: i32,
        ) -> Result<String>;
        fn rename_symbol_json(
            self: &LocalClientHandle,
            address: u64,
            new_name: &str,
        ) -> Result<String>;

        // -- Memory -------------------------------------------------------
        fn read_bytes(
            self: &LocalClientHandle,
            address: u64,
            length: u32,
        ) -> Result<Vec<u8>>;
        fn list_memory_blocks_json(
            self: &LocalClientHandle,
            limit: i32,
            offset: i32,
        ) -> Result<String>;

        // -- Listing ------------------------------------------------------
        fn get_instruction_json(self: &LocalClientHandle, address: u64) -> Result<String>;
        fn list_instructions_json(
            self: &LocalClientHandle,
            range_start: u64,
            range_end: u64,
            limit: i32,
            offset: i32,
        ) -> Result<String>;
        fn list_defined_strings_json(
            self: &LocalClientHandle,
            range_start: u64,
            range_end: u64,
            limit: i32,
            offset: i32,
        ) -> Result<String>;

        // -- Xrefs --------------------------------------------------------
        fn list_xrefs_json(
            self: &LocalClientHandle,
            range_start: u64,
            range_end: u64,
            limit: i32,
            offset: i32,
        ) -> Result<String>;

        // -- Types --------------------------------------------------------
        fn get_type_json(self: &LocalClientHandle, path: &str) -> Result<String>;
        fn list_types_json(
            self: &LocalClientHandle,
            query: &str,
            limit: i32,
            offset: i32,
        ) -> Result<String>;
        fn list_type_members_json(
            self: &LocalClientHandle,
            type_id_or_path: &str,
            limit: i32,
            offset: i32,
        ) -> Result<String>;
    }
}
