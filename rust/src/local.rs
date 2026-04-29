// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// LocalClient — offline decompiler backend backed by the C++ libghidra
// engine via the cxx FFI bridge declared in `local_ffi.rs`. Mirrors
// `python/src/libghidra/local.py` method-for-method.
//
// All public methods return typed records. The C++ bridge emits a JSON
// payload per call; helpers in this module deserialize each into the
// matching `models.rs` record. JSON shape mirrors python_bindings.cpp's
// `to_dict()` for the same record type — see `cpp/bindings/rust_bridge.cpp`.

use serde_json::Value;

use crate::error::{Error, ErrorCode, Result};
use crate::local_ffi::ffi;
use crate::models::{
    BasicBlockRecord, CFGEdgeRecord, Capability, DecompilationRecord, DecompileLocalKind,
    DecompileLocalRecord, DecompileTokenKind, DecompileTokenRecord, DefinedStringRecord,
    FunctionRecord, GetDecompilationResponse, GetFunctionResponse, GetInstructionResponse,
    GetSymbolResponse, GetTypeResponse, HealthStatus, InstructionRecord,
    ListBasicBlocksResponse, ListCFGEdgesResponse, ListDecompilationsResponse,
    ListDefinedStringsResponse, ListFunctionsResponse, ListInstructionsResponse,
    ListMemoryBlocksResponse, ListSymbolsResponse, ListTypeMembersResponse, ListTypesResponse,
    ListXrefsResponse, MemoryBlockRecord, OpenProgramRequest, OpenProgramResponse, ReadBytesResponse,
    RenameFunctionResponse, RenameSymbolResponse, RevisionResponse, SymbolRecord,
    TypeMemberRecord, TypeRecord, XrefRecord,
};

// ===========================================================================
// LocalClientOptions / LocalClient
// ===========================================================================

/// Options for creating a [`LocalClient`].
///
/// Mirrors `LocalClientOptions` in `python/src/libghidra/local.py`.
#[derive(Debug, Clone, Default)]
pub struct LocalClientOptions {
    /// Optional Ghidra installation root (Sleigh specs are embedded in the
    /// engine, so this can be empty).
    pub ghidra_root: String,
    /// Path used by the engine for any per-program scratch state.
    pub state_path: String,
    /// Sleigh language ID hint. Empty or "auto" enables auto-detection at
    /// `open_program` time via the `format_detect` module.
    pub default_arch: String,
    /// Number of decompiler workers in the pool. `0` is treated as `1`.
    pub pool_size: i32,
}

impl LocalClientOptions {
    /// Convenience: enable auto-detection of the Sleigh language ID.
    pub fn auto() -> Self {
        Self {
            default_arch: "auto".to_string(),
            pool_size: 1,
            ..Default::default()
        }
    }
}

/// Offline decompiler client. Provides the same API surface as `GhidraClient`
/// but works without a running Ghidra JVM. Created via
/// [`crate::local()`] / [`crate::local_with()`] or [`LocalClient::new`].
pub struct LocalClient {
    handle: cxx::UniquePtr<ffi::LocalClientHandle>,
    opts: LocalClientOptions,
}

impl LocalClient {
    /// Create a new local client with the given options. Wraps the cxx FFI
    /// `create_local_client` factory.
    pub fn new(opts: LocalClientOptions) -> Result<Self> {
        let create = ffi::CreateOptions {
            ghidra_root: opts.ghidra_root.clone(),
            state_path: opts.state_path.clone(),
            // The C++ side treats empty string as "auto"; our convenience
            // value "auto" maps to the same.
            default_arch: if opts.default_arch == "auto" {
                String::new()
            } else {
                opts.default_arch.clone()
            },
            pool_size: opts.pool_size.max(1),
        };
        let handle = ffi::create_local_client(&create).map_err(map_cxx_err)?;
        Ok(LocalClient { handle, opts })
    }

    /// Access the options this client was constructed with.
    pub fn options(&self) -> &LocalClientOptions {
        &self.opts
    }

    /// True when language auto-detection is enabled for `open_program`.
    /// Used by `format_detect::detect_and_open` to decide whether to fill in
    /// the language ID from the binary headers before calling open_program.
    pub fn auto_detect(&self) -> bool {
        self.opts.default_arch.is_empty() || self.opts.default_arch == "auto"
    }

    // -- Health ----------------------------------------------------------

    pub fn get_status(&self) -> Result<HealthStatus> {
        let v = call_json(self.handle.get_status_json())?;
        Ok(decode_health(&v))
    }

    pub fn get_capabilities(&self) -> Result<Vec<Capability>> {
        let v = call_json(self.handle.get_capabilities_json())?;
        Ok(v.as_array()
            .map(|arr| arr.iter().map(decode_capability).collect())
            .unwrap_or_default())
    }

    // -- Session ---------------------------------------------------------

    /// Open a program. Mirrors Python `LocalClient.open_program`. Accepts
    /// either an explicit `OpenProgramRequest` or, if you only have a path,
    /// build one via `OpenProgramRequest { program_path: ..., ..Default::default() }`.
    pub fn open_program(&self, request: OpenProgramRequest) -> Result<OpenProgramResponse> {
        let json = self
            .handle
            .open_program_json(
                &request.program_path,
                request.analyze,
                request.read_only,
                &request.project_path,
                &request.project_name,
                &request.language_id,
                &request.compiler_spec_id,
                &request.format,
                request.base_address,
            )
            .map_err(map_cxx_err)?;
        let v = parse_json(&json)?;
        Ok(OpenProgramResponse {
            program_name: take_str(&v, "program_name"),
            language_id: take_str(&v, "language_id"),
            compiler_spec: take_str(&v, "compiler_spec"),
            image_base: v["image_base"].as_u64().unwrap_or(0),
        })
    }

    pub fn close_program(&self, policy: i32) -> Result<bool> {
        self.handle.close_program(policy).map_err(map_cxx_err)
    }

    pub fn save_program(&self) -> Result<bool> {
        self.handle.save_program().map_err(map_cxx_err)
    }

    pub fn discard_program(&self) -> Result<bool> {
        self.handle.discard_program().map_err(map_cxx_err)
    }

    pub fn get_revision(&self) -> Result<RevisionResponse> {
        let revision = self.handle.get_revision().map_err(map_cxx_err)?;
        Ok(RevisionResponse { revision })
    }

    // -- Functions -------------------------------------------------------

    pub fn get_function(&self, address: u64) -> Result<GetFunctionResponse> {
        let json = self.handle.get_function_json(address).map_err(map_cxx_err)?;
        let function = if json.is_empty() {
            None
        } else {
            Some(decode_function(&parse_json(&json)?))
        };
        Ok(GetFunctionResponse { function })
    }

    pub fn list_functions(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListFunctionsResponse> {
        let v = call_json(
            self.handle
                .list_functions_json(range_start, range_end, limit, offset),
        )?;
        Ok(ListFunctionsResponse {
            functions: v
                .as_array()
                .map(|arr| arr.iter().map(decode_function).collect())
                .unwrap_or_default(),
        })
    }

    pub fn rename_function(
        &self,
        address: u64,
        new_name: &str,
    ) -> Result<RenameFunctionResponse> {
        let v = call_json(self.handle.rename_function_json(address, new_name))?;
        Ok(RenameFunctionResponse {
            renamed: v["renamed"].as_bool().unwrap_or(false),
            name: take_str(&v, "name"),
        })
    }

    pub fn list_basic_blocks(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListBasicBlocksResponse> {
        let v = call_json(
            self.handle
                .list_basic_blocks_json(range_start, range_end, limit, offset),
        )?;
        Ok(ListBasicBlocksResponse {
            blocks: v
                .as_array()
                .map(|arr| arr.iter().map(decode_basic_block).collect())
                .unwrap_or_default(),
        })
    }

    pub fn list_cfg_edges(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListCFGEdgesResponse> {
        let v = call_json(
            self.handle
                .list_cfg_edges_json(range_start, range_end, limit, offset),
        )?;
        Ok(ListCFGEdgesResponse {
            edges: v
                .as_array()
                .map(|arr| arr.iter().map(decode_cfg_edge).collect())
                .unwrap_or_default(),
        })
    }

    // -- Decompiler ------------------------------------------------------

    pub fn get_decompilation(
        &self,
        address: u64,
        timeout_ms: i32,
    ) -> Result<GetDecompilationResponse> {
        let json = self
            .handle
            .get_decompilation_json(address, timeout_ms)
            .map_err(map_cxx_err)?;
        let decompilation = if json.is_empty() {
            None
        } else {
            Some(decode_decompilation(&parse_json(&json)?))
        };
        Ok(GetDecompilationResponse { decompilation })
    }

    pub fn list_decompilations(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
        timeout_ms: i32,
    ) -> Result<ListDecompilationsResponse> {
        let v = call_json(self.handle.list_decompilations_json(
            range_start,
            range_end,
            limit,
            offset,
            timeout_ms,
        ))?;
        Ok(ListDecompilationsResponse {
            decompilations: v
                .as_array()
                .map(|arr| arr.iter().map(decode_decompilation).collect())
                .unwrap_or_default(),
        })
    }

    // -- Symbols ---------------------------------------------------------

    pub fn get_symbol(&self, address: u64) -> Result<GetSymbolResponse> {
        let json = self.handle.get_symbol_json(address).map_err(map_cxx_err)?;
        let symbol = if json.is_empty() {
            None
        } else {
            Some(decode_symbol(&parse_json(&json)?))
        };
        Ok(GetSymbolResponse { symbol })
    }

    pub fn list_symbols(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListSymbolsResponse> {
        let v = call_json(
            self.handle
                .list_symbols_json(range_start, range_end, limit, offset),
        )?;
        Ok(ListSymbolsResponse {
            symbols: v
                .as_array()
                .map(|arr| arr.iter().map(decode_symbol).collect())
                .unwrap_or_default(),
        })
    }

    pub fn rename_symbol(&self, address: u64, new_name: &str) -> Result<RenameSymbolResponse> {
        let v = call_json(self.handle.rename_symbol_json(address, new_name))?;
        Ok(RenameSymbolResponse {
            renamed: v["renamed"].as_bool().unwrap_or(false),
            name: take_str(&v, "name"),
        })
    }

    // -- Memory ----------------------------------------------------------

    pub fn read_bytes(&self, address: u64, length: u32) -> Result<ReadBytesResponse> {
        let data = self
            .handle
            .read_bytes(address, length)
            .map_err(map_cxx_err)?;
        Ok(ReadBytesResponse { data })
    }

    pub fn list_memory_blocks(
        &self,
        limit: i32,
        offset: i32,
    ) -> Result<ListMemoryBlocksResponse> {
        let v = call_json(self.handle.list_memory_blocks_json(limit, offset))?;
        Ok(ListMemoryBlocksResponse {
            blocks: v
                .as_array()
                .map(|arr| arr.iter().map(decode_memory_block).collect())
                .unwrap_or_default(),
        })
    }

    // -- Listing ---------------------------------------------------------

    pub fn get_instruction(&self, address: u64) -> Result<GetInstructionResponse> {
        let json = self
            .handle
            .get_instruction_json(address)
            .map_err(map_cxx_err)?;
        let instruction = if json.is_empty() {
            None
        } else {
            Some(decode_instruction(&parse_json(&json)?))
        };
        Ok(GetInstructionResponse { instruction })
    }

    pub fn list_instructions(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListInstructionsResponse> {
        let v = call_json(
            self.handle
                .list_instructions_json(range_start, range_end, limit, offset),
        )?;
        Ok(ListInstructionsResponse {
            instructions: v
                .as_array()
                .map(|arr| arr.iter().map(decode_instruction).collect())
                .unwrap_or_default(),
        })
    }

    pub fn list_defined_strings(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListDefinedStringsResponse> {
        let v = call_json(
            self.handle
                .list_defined_strings_json(range_start, range_end, limit, offset),
        )?;
        Ok(ListDefinedStringsResponse {
            strings: v
                .as_array()
                .map(|arr| arr.iter().map(decode_defined_string).collect())
                .unwrap_or_default(),
        })
    }

    // -- Xrefs -----------------------------------------------------------

    pub fn list_xrefs(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListXrefsResponse> {
        let v = call_json(
            self.handle
                .list_xrefs_json(range_start, range_end, limit, offset),
        )?;
        Ok(ListXrefsResponse {
            xrefs: v
                .as_array()
                .map(|arr| arr.iter().map(decode_xref).collect())
                .unwrap_or_default(),
        })
    }

    // -- Types -----------------------------------------------------------

    pub fn get_type(&self, path: &str) -> Result<GetTypeResponse> {
        let json = self.handle.get_type_json(path).map_err(map_cxx_err)?;
        let r#type = if json.is_empty() {
            None
        } else {
            Some(decode_type(&parse_json(&json)?))
        };
        Ok(GetTypeResponse { r#type })
    }

    pub fn list_types(
        &self,
        query: &str,
        limit: i32,
        offset: i32,
    ) -> Result<ListTypesResponse> {
        let v = call_json(self.handle.list_types_json(query, limit, offset))?;
        Ok(ListTypesResponse {
            types: v
                .as_array()
                .map(|arr| arr.iter().map(decode_type).collect())
                .unwrap_or_default(),
        })
    }

    pub fn list_type_members(
        &self,
        type_id_or_path: &str,
        limit: i32,
        offset: i32,
    ) -> Result<ListTypeMembersResponse> {
        let v = call_json(
            self.handle
                .list_type_members_json(type_id_or_path, limit, offset),
        )?;
        Ok(ListTypeMembersResponse {
            members: v
                .as_array()
                .map(|arr| arr.iter().map(decode_type_member).collect())
                .unwrap_or_default(),
        })
    }
}

// ===========================================================================
// JSON helpers
// ===========================================================================

fn parse_json(s: &str) -> Result<Value> {
    serde_json::from_str(s).map_err(|e| Error::new(ErrorCode::ParseError, e.to_string()))
}

/// Helper: take a `Result<rust::String, cxx::Exception>` from the FFI and
/// turn it into a parsed `serde_json::Value`. Errors map through `map_cxx_err`.
fn call_json(r: std::result::Result<String, cxx::Exception>) -> Result<Value> {
    let json = r.map_err(map_cxx_err)?;
    parse_json(&json)
}

fn take_str(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or("").to_string()
}

fn map_cxx_err(e: cxx::Exception) -> Error {
    let msg = e.what().to_string();
    if let Some((code_str, rest)) = msg.split_once(": ") {
        Error::new(ErrorCode::from_rpc_code(code_str), rest.to_string())
    } else {
        Error::new(ErrorCode::ApiError, msg)
    }
}

// ===========================================================================
// Per-record decoders (mirror python_bindings.cpp::to_dict for each type)
// ===========================================================================

fn decode_health(v: &Value) -> HealthStatus {
    HealthStatus {
        ok: v["ok"].as_bool().unwrap_or(false),
        service_name: take_str(v, "service_name"),
        service_version: take_str(v, "service_version"),
        host_mode: take_str(v, "host_mode"),
        program_revision: v["program_revision"].as_u64().unwrap_or(0),
        warnings: v["warnings"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn decode_capability(v: &Value) -> Capability {
    Capability {
        id: take_str(v, "id"),
        status: take_str(v, "status"),
        note: take_str(v, "note"),
    }
}

fn decode_function(v: &Value) -> FunctionRecord {
    FunctionRecord {
        entry_address: v["entry_address"].as_u64().unwrap_or(0),
        name: take_str(v, "name"),
        start_address: v["start_address"].as_u64().unwrap_or(0),
        end_address: v["end_address"].as_u64().unwrap_or(0),
        size: v["size"].as_u64().unwrap_or(0),
        namespace_name: take_str(v, "namespace_name"),
        prototype: take_str(v, "prototype"),
        is_thunk: v["is_thunk"].as_bool().unwrap_or(false),
        parameter_count: v["parameter_count"].as_u64().unwrap_or(0) as u32,
    }
}

fn decode_symbol(v: &Value) -> SymbolRecord {
    SymbolRecord {
        symbol_id: v["symbol_id"].as_u64().unwrap_or(0),
        address: v["address"].as_u64().unwrap_or(0),
        name: take_str(v, "name"),
        full_name: take_str(v, "full_name"),
        r#type: take_str(v, "type"),
        namespace_name: take_str(v, "namespace_name"),
        source: take_str(v, "source"),
        is_primary: v["is_primary"].as_bool().unwrap_or(false),
        is_external: v["is_external"].as_bool().unwrap_or(false),
        is_dynamic: v["is_dynamic"].as_bool().unwrap_or(false),
    }
}

fn decode_instruction(v: &Value) -> InstructionRecord {
    InstructionRecord {
        address: v["address"].as_u64().unwrap_or(0),
        mnemonic: take_str(v, "mnemonic"),
        operand_text: take_str(v, "operand_text"),
        disassembly: take_str(v, "disassembly"),
        length: v["length"].as_u64().unwrap_or(0) as u32,
    }
}

fn decode_memory_block(v: &Value) -> MemoryBlockRecord {
    MemoryBlockRecord {
        name: take_str(v, "name"),
        start_address: v["start_address"].as_u64().unwrap_or(0),
        end_address: v["end_address"].as_u64().unwrap_or(0),
        size: v["size"].as_u64().unwrap_or(0),
        is_read: v["is_read"].as_bool().unwrap_or(false),
        is_write: v["is_write"].as_bool().unwrap_or(false),
        is_execute: v["is_execute"].as_bool().unwrap_or(false),
        is_volatile: v["is_volatile"].as_bool().unwrap_or(false),
        is_initialized: v["is_initialized"].as_bool().unwrap_or(false),
        source_name: take_str(v, "source_name"),
        comment: take_str(v, "comment"),
    }
}

fn decode_xref(v: &Value) -> XrefRecord {
    XrefRecord {
        from_address: v["from_address"].as_u64().unwrap_or(0),
        to_address: v["to_address"].as_u64().unwrap_or(0),
        operand_index: v["operand_index"].as_i64().unwrap_or(0) as i32,
        ref_type: take_str(v, "ref_type"),
        is_primary: v["is_primary"].as_bool().unwrap_or(false),
        source: take_str(v, "source"),
        symbol_id: v["symbol_id"].as_i64().unwrap_or(0),
        is_external: v["is_external"].as_bool().unwrap_or(false),
        is_memory: v["is_memory"].as_bool().unwrap_or(false),
        is_flow: v["is_flow"].as_bool().unwrap_or(false),
    }
}

fn decode_type(v: &Value) -> TypeRecord {
    TypeRecord {
        type_id: v["type_id"].as_u64().unwrap_or(0),
        name: take_str(v, "name"),
        path_name: take_str(v, "path_name"),
        category_path: take_str(v, "category_path"),
        display_name: take_str(v, "display_name"),
        kind: take_str(v, "kind"),
        length: v["length"].as_i64().unwrap_or(0) as i32,
        is_not_yet_defined: v["is_not_yet_defined"].as_bool().unwrap_or(false),
        source_archive: take_str(v, "source_archive"),
        universal_id: take_str(v, "universal_id"),
    }
}

fn decode_type_member(v: &Value) -> TypeMemberRecord {
    TypeMemberRecord {
        parent_type_id: v["parent_type_id"].as_u64().unwrap_or(0),
        parent_type_path_name: take_str(v, "parent_type_path_name"),
        parent_type_name: take_str(v, "parent_type_name"),
        ordinal: v["ordinal"].as_u64().unwrap_or(0),
        name: take_str(v, "name"),
        member_type: take_str(v, "member_type"),
        offset: v["offset"].as_i64().unwrap_or(0),
        size: v["size"].as_u64().unwrap_or(0),
    }
}

fn decode_basic_block(v: &Value) -> BasicBlockRecord {
    BasicBlockRecord {
        function_entry: v["function_entry"].as_u64().unwrap_or(0),
        start_address: v["start_address"].as_u64().unwrap_or(0),
        end_address: v["end_address"].as_u64().unwrap_or(0),
        in_degree: v["in_degree"].as_u64().unwrap_or(0) as u32,
        out_degree: v["out_degree"].as_u64().unwrap_or(0) as u32,
    }
}

fn decode_cfg_edge(v: &Value) -> CFGEdgeRecord {
    CFGEdgeRecord {
        function_entry: v["function_entry"].as_u64().unwrap_or(0),
        src_block_start: v["src_block_start"].as_u64().unwrap_or(0),
        dst_block_start: v["dst_block_start"].as_u64().unwrap_or(0),
        edge_kind: take_str(v, "edge_kind"),
    }
}

fn decode_defined_string(v: &Value) -> DefinedStringRecord {
    DefinedStringRecord {
        address: v["address"].as_u64().unwrap_or(0),
        value: take_str(v, "value"),
        length: v["length"].as_u64().unwrap_or(0) as u32,
        data_type: take_str(v, "data_type"),
        encoding: take_str(v, "encoding"),
    }
}

fn decode_decompilation(v: &Value) -> DecompilationRecord {
    let locals = v["locals"]
        .as_array()
        .map(|arr| arr.iter().map(decode_decompile_local).collect())
        .unwrap_or_default();
    let tokens = v["tokens"]
        .as_array()
        .map(|arr| arr.iter().map(decode_decompile_token).collect())
        .unwrap_or_default();
    DecompilationRecord {
        function_entry_address: v["function_entry_address"].as_u64().unwrap_or(0),
        function_name: take_str(v, "function_name"),
        prototype: take_str(v, "prototype"),
        pseudocode: take_str(v, "pseudocode"),
        completed: v["completed"].as_bool().unwrap_or(false),
        is_fallback: v["is_fallback"].as_bool().unwrap_or(false),
        error_message: take_str(v, "error_message"),
        locals,
        tokens,
    }
}

fn decode_decompile_local(v: &Value) -> DecompileLocalRecord {
    DecompileLocalRecord {
        local_id: take_str(v, "local_id"),
        kind: decompile_local_kind_from_int(v["kind"].as_i64().unwrap_or(0)),
        name: take_str(v, "name"),
        data_type: take_str(v, "data_type"),
        storage: take_str(v, "storage"),
        ordinal: v["ordinal"].as_i64().unwrap_or(0) as i32,
    }
}

fn decode_decompile_token(v: &Value) -> DecompileTokenRecord {
    DecompileTokenRecord {
        text: take_str(v, "text"),
        kind: decompile_token_kind_from_int(v["kind"].as_i64().unwrap_or(0)),
        line_number: v["line_number"].as_i64().unwrap_or(0) as i32,
        column_offset: v["column_offset"].as_i64().unwrap_or(0) as i32,
        var_name: take_str(v, "var_name"),
        var_type: take_str(v, "var_type"),
        var_storage: take_str(v, "var_storage"),
    }
}

fn decompile_local_kind_from_int(i: i64) -> DecompileLocalKind {
    match i {
        1 => DecompileLocalKind::Param,
        2 => DecompileLocalKind::Local,
        3 => DecompileLocalKind::Temp,
        _ => DecompileLocalKind::Unspecified,
    }
}

fn decompile_token_kind_from_int(i: i64) -> DecompileTokenKind {
    match i {
        1 => DecompileTokenKind::Keyword,
        2 => DecompileTokenKind::Comment,
        3 => DecompileTokenKind::Type,
        4 => DecompileTokenKind::Function,
        5 => DecompileTokenKind::Variable,
        6 => DecompileTokenKind::Const,
        7 => DecompileTokenKind::Parameter,
        8 => DecompileTokenKind::Global,
        9 => DecompileTokenKind::Default,
        10 => DecompileTokenKind::Error,
        11 => DecompileTokenKind::Special,
        _ => DecompileTokenKind::Unspecified,
    }
}
