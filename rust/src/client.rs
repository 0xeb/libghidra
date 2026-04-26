// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

use prost::Message;

use crate::error::{Error, ErrorCode, Result};
use crate::models::*;
use crate::proto;
use crate::proto::libghidra as pb;
use crate::retry::compute_backoff;

/// Options for configuring the HTTP client.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub base_url: String,
    pub auth_token: String,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub jitter: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:18080".to_string(),
            auth_token: String::new(),
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(120),
            max_retries: 0,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            jitter: true,
        }
    }
}

/// Synchronous HTTP client for the Ghidra RPC API.
pub struct GhidraClient {
    agent: ureq::Agent,
    options: ClientOptions,
    rpc_url: String,
}

impl GhidraClient {
    pub fn new(options: ClientOptions) -> Self {
        let rpc_url = format!("{}/rpc", options.base_url.trim_end_matches('/'));
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_connect(Some(options.connect_timeout))
                .timeout_recv_body(Some(options.read_timeout))
                .timeout_send_body(Some(options.read_timeout))
                .build(),
        );
        Self {
            agent,
            options,
            rpc_url,
        }
    }

    // -- Core transport -------------------------------------------------------

    fn call_rpc<Req: Message, Resp: Message + Default>(
        &self,
        method: &str,
        request: &Req,
        type_name: &str,
    ) -> Result<Resp> {
        let rpc_request = pb::RpcRequest {
            method: method.to_string(),
            payload: Some(proto::pack_any(request, type_name)),
        };
        let encoded = rpc_request.encode_to_vec();

        let max_attempts = self.options.max_retries + 1;
        let mut last_err = Error::new(ErrorCode::TransportError, "no attempts made");

        for attempt in 0..max_attempts {
            match self.post_raw(&encoded) {
                Ok(body) => {
                    return self.parse_rpc_response::<Resp>(&body, method);
                }
                Err(e) => {
                    last_err = e;
                    if !last_err.code.is_retryable() || attempt + 1 >= max_attempts {
                        break;
                    }
                    std::thread::sleep(compute_backoff(
                        attempt,
                        self.options.initial_backoff,
                        self.options.max_backoff,
                        self.options.jitter,
                    ));
                }
            }
        }
        Err(last_err)
    }

    fn parse_rpc_response<Resp: Message + Default>(
        &self,
        body: &[u8],
        method: &str,
    ) -> Result<Resp> {
        let rpc_response = pb::RpcResponse::decode(body).map_err(|e| {
            Error::new(
                ErrorCode::ParseError,
                format!("failed to parse RpcResponse: {e}"),
            )
        })?;

        if !rpc_response.success {
            let code = if rpc_response.error_code.is_empty() {
                ErrorCode::ApiError
            } else {
                ErrorCode::from_rpc_code(&rpc_response.error_code)
            };
            let message = if rpc_response.error_message.is_empty() {
                "RPC returned success=false".to_string()
            } else {
                rpc_response.error_message
            };
            return Err(Error::new(code, message));
        }

        if let Some(payload) = &rpc_response.payload {
            proto::unpack_any::<Resp>(payload).map_err(|e| {
                Error::new(
                    ErrorCode::ParseError,
                    format!("failed to unpack RPC payload for method {method}: {e}"),
                )
            })
        } else {
            Ok(Resp::default())
        }
    }

    fn post_raw(&self, body: &[u8]) -> Result<Vec<u8>> {
        let mut req = self
            .agent
            .post(&self.rpc_url)
            .header("Content-Type", "application/x-protobuf");

        if !self.options.auth_token.is_empty() {
            req = req.header(
                "Authorization",
                &format!("Bearer {}", self.options.auth_token),
            );
        }

        let response = req.send(body).map_err(|e| {
            let (code, message) = map_ureq_error(&e);
            Error::new(code, message)
        })?;

        let status: u16 = response.status().into();
        if !(200..300).contains(&status) {
            return Err(Error::new(
                ErrorCode::from_http_status(status),
                format!("HTTP status {} for /rpc", status),
            ));
        }

        let buf = response
            .into_body()
            .read_to_vec()
            .map_err(|e| Error::new(ErrorCode::TransportError, format!("read body: {e}")))?;
        Ok(buf)
    }

    fn pagination(limit: i32, offset: i32) -> Option<pb::Pagination> {
        Some(pb::Pagination {
            limit: limit.max(0) as u32,
            offset: offset.max(0) as u32,
        })
    }

    fn address_range(start: u64, end: u64) -> Option<pb::AddressRange> {
        Some(pb::AddressRange { start, end })
    }

    // -- Health ---------------------------------------------------------------

    pub fn get_status(&self) -> Result<HealthStatus> {
        let resp: pb::HealthStatusResponse = self.call_rpc(
            "libghidra.HealthService/GetStatus",
            &pb::HealthStatusRequest {},
            "libghidra.HealthStatusRequest",
        )?;
        Ok(HealthStatus {
            ok: resp.ok,
            service_name: resp.service_name,
            service_version: resp.service_version,
            host_mode: resp.host_mode,
            program_revision: resp.program_revision,
            warnings: resp.warnings,
        })
    }

    pub fn get_capabilities(&self) -> Result<Vec<Capability>> {
        let resp: pb::CapabilityResponse = self.call_rpc(
            "libghidra.HealthService/GetCapabilities",
            &pb::CapabilityRequest {},
            "libghidra.CapabilityRequest",
        )?;
        Ok(resp.capabilities.into_iter().map(Into::into).collect())
    }

    // -- Session --------------------------------------------------------------

    pub fn open_program(&self, request: &OpenProgramRequest) -> Result<OpenProgramResponse> {
        let req = pb::OpenProgramRequest {
            project_path: request.project_path.clone(),
            project_name: request.project_name.clone(),
            program_path: request.program_path.clone(),
            analyze: request.analyze,
            read_only: request.read_only,
            language_id: request.language_id.clone(),
            compiler_spec_id: request.compiler_spec_id.clone(),
            format: request.format.clone(),
            base_address: request.base_address,
        };
        let resp: pb::OpenProgramResponse = self.call_rpc(
            "libghidra.SessionService/OpenProgram",
            &req,
            "libghidra.OpenProgramRequest",
        )?;
        let out = OpenProgramResponse {
            program_name: resp.program_name,
            language_id: resp.language_id,
            compiler_spec: resp.compiler_spec,
            image_base: resp.image_base,
        };
        Ok(out)
    }

    pub fn close_program(&self, policy: ShutdownPolicy) -> Result<CloseProgramResponse> {
        let req = pb::CloseProgramRequest {
            shutdown_policy: i32::from(policy),
        };
        let resp: pb::CloseProgramResponse = self.call_rpc(
            "libghidra.SessionService/CloseProgram",
            &req,
            "libghidra.CloseProgramRequest",
        )?;
        Ok(CloseProgramResponse {
            closed: resp.closed,
        })
    }

    pub fn save_program(&self) -> Result<SaveProgramResponse> {
        let req = pb::SaveProgramRequest {};
        let resp: pb::SaveProgramResponse = self.call_rpc(
            "libghidra.SessionService/SaveProgram",
            &req,
            "libghidra.SaveProgramRequest",
        )?;
        Ok(SaveProgramResponse { saved: resp.saved })
    }

    pub fn discard_program(&self) -> Result<DiscardProgramResponse> {
        let req = pb::DiscardProgramRequest {};
        let resp: pb::DiscardProgramResponse = self.call_rpc(
            "libghidra.SessionService/DiscardProgram",
            &req,
            "libghidra.DiscardProgramRequest",
        )?;
        Ok(DiscardProgramResponse {
            discarded: resp.discarded,
        })
    }

    pub fn get_revision(&self) -> Result<RevisionResponse> {
        let req = pb::GetRevisionRequest {};
        let resp: pb::GetRevisionResponse = self.call_rpc(
            "libghidra.SessionService/GetRevision",
            &req,
            "libghidra.GetRevisionRequest",
        )?;
        Ok(RevisionResponse {
            revision: resp.revision,
        })
    }

    pub fn shutdown(&self, policy: ShutdownPolicy) -> Result<ShutdownResponse> {
        let req = pb::ShutdownRequest {
            shutdown_policy: i32::from(policy),
        };
        let resp: pb::ShutdownResponse = self.call_rpc(
            "libghidra.SessionService/Shutdown",
            &req,
            "libghidra.ShutdownRequest",
        )?;
        Ok(ShutdownResponse {
            accepted: resp.accepted,
        })
    }

    // -- Memory ---------------------------------------------------------------

    pub fn read_bytes(&self, address: u64, length: u32) -> Result<ReadBytesResponse> {
        let req = pb::ReadBytesRequest { address, length };
        let resp: pb::ReadBytesResponse = self.call_rpc(
            "libghidra.MemoryService/ReadBytes",
            &req,
            "libghidra.ReadBytesRequest",
        )?;
        Ok(ReadBytesResponse { data: resp.data })
    }

    pub fn write_bytes(&self, address: u64, data: &[u8]) -> Result<WriteBytesResponse> {
        let req = pb::WriteBytesRequest {
            address,
            data: data.to_vec(),
        };
        let resp: pb::WriteBytesResponse = self.call_rpc(
            "libghidra.MemoryService/WriteBytes",
            &req,
            "libghidra.WriteBytesRequest",
        )?;
        Ok(WriteBytesResponse {
            bytes_written: resp.bytes_written,
        })
    }

    pub fn patch_bytes_batch(&self, patches: &[BytePatch]) -> Result<PatchBytesBatchResponse> {
        let req = pb::PatchBytesBatchRequest {
            patches: patches
                .iter()
                .map(|p| pb::BytePatch {
                    address: p.address,
                    data: p.data.clone(),
                })
                .collect(),
        };
        let resp: pb::PatchBytesBatchResponse = self.call_rpc(
            "libghidra.MemoryService/PatchBytesBatch",
            &req,
            "libghidra.PatchBytesBatchRequest",
        )?;
        Ok(PatchBytesBatchResponse {
            patch_count: resp.patch_count,
            bytes_written: resp.bytes_written,
        })
    }

    pub fn list_memory_blocks(&self, limit: i32, offset: i32) -> Result<ListMemoryBlocksResponse> {
        let req = pb::ListMemoryBlocksRequest {
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListMemoryBlocksResponse = self.call_rpc(
            "libghidra.MemoryService/ListMemoryBlocks",
            &req,
            "libghidra.ListMemoryBlocksRequest",
        )?;
        Ok(ListMemoryBlocksResponse {
            blocks: resp.blocks.into_iter().map(Into::into).collect(),
        })
    }

    // -- Functions -------------------------------------------------------------

    pub fn get_function(&self, address: u64) -> Result<GetFunctionResponse> {
        let req = pb::GetFunctionRequest { address };
        let resp: pb::GetFunctionResponse = self.call_rpc(
            "libghidra.FunctionsService/GetFunction",
            &req,
            "libghidra.GetFunctionRequest",
        )?;
        Ok(GetFunctionResponse {
            function: resp.function.map(Into::into),
        })
    }

    pub fn list_functions(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListFunctionsResponse> {
        let req = pb::ListFunctionsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListFunctionsResponse = self.call_rpc(
            "libghidra.FunctionsService/ListFunctions",
            &req,
            "libghidra.ListFunctionsRequest",
        )?;
        Ok(ListFunctionsResponse {
            functions: resp.functions.into_iter().map(Into::into).collect(),
        })
    }

    pub fn rename_function(&self, address: u64, new_name: &str) -> Result<RenameFunctionResponse> {
        let req = pb::RenameFunctionRequest {
            address,
            new_name: new_name.to_string(),
        };
        let resp: pb::RenameFunctionResponse = self.call_rpc(
            "libghidra.FunctionsService/RenameFunction",
            &req,
            "libghidra.RenameFunctionRequest",
        )?;
        Ok(RenameFunctionResponse {
            renamed: resp.renamed,
            name: resp.name,
        })
    }

    pub fn list_basic_blocks(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListBasicBlocksResponse> {
        let req = pb::ListBasicBlocksRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListBasicBlocksResponse = self.call_rpc(
            "libghidra.FunctionsService/ListBasicBlocks",
            &req,
            "libghidra.ListBasicBlocksRequest",
        )?;
        Ok(ListBasicBlocksResponse {
            blocks: resp.blocks.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_cfg_edges(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListCFGEdgesResponse> {
        let req = pb::ListCfgEdgesRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListCfgEdgesResponse = self.call_rpc(
            "libghidra.FunctionsService/ListCFGEdges",
            &req,
            "libghidra.ListCFGEdgesRequest",
        )?;
        Ok(ListCFGEdgesResponse {
            edges: resp.edges.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_switch_tables(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListSwitchTablesResponse> {
        let req = pb::ListSwitchTablesRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListSwitchTablesResponse = self.call_rpc(
            "libghidra.FunctionsService/ListSwitchTables",
            &req,
            "libghidra.ListSwitchTablesRequest",
        )?;
        Ok(ListSwitchTablesResponse {
            switch_tables: resp.switch_tables.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_dominators(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListDominatorsResponse> {
        let req = pb::ListDominatorsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListDominatorsResponse = self.call_rpc(
            "libghidra.FunctionsService/ListDominators",
            &req,
            "libghidra.ListDominatorsRequest",
        )?;
        Ok(ListDominatorsResponse {
            dominators: resp.dominators.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_post_dominators(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListPostDominatorsResponse> {
        let req = pb::ListPostDominatorsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListPostDominatorsResponse = self.call_rpc(
            "libghidra.FunctionsService/ListPostDominators",
            &req,
            "libghidra.ListPostDominatorsRequest",
        )?;
        Ok(ListPostDominatorsResponse {
            post_dominators: resp.post_dominators.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_loops(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListLoopsResponse> {
        let req = pb::ListLoopsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListLoopsResponse = self.call_rpc(
            "libghidra.FunctionsService/ListLoops",
            &req,
            "libghidra.ListLoopsRequest",
        )?;
        Ok(ListLoopsResponse {
            loops: resp.loops.into_iter().map(Into::into).collect(),
        })
    }

    // -- Symbols --------------------------------------------------------------

    pub fn get_symbol(&self, address: u64) -> Result<GetSymbolResponse> {
        let req = pb::GetSymbolRequest { address };
        let resp: pb::GetSymbolResponse = self.call_rpc(
            "libghidra.SymbolsService/GetSymbol",
            &req,
            "libghidra.GetSymbolRequest",
        )?;
        Ok(GetSymbolResponse {
            symbol: resp.symbol.map(Into::into),
        })
    }

    pub fn list_symbols(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListSymbolsResponse> {
        let req = pb::ListSymbolsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListSymbolsResponse = self.call_rpc(
            "libghidra.SymbolsService/ListSymbols",
            &req,
            "libghidra.ListSymbolsRequest",
        )?;
        Ok(ListSymbolsResponse {
            symbols: resp.symbols.into_iter().map(Into::into).collect(),
        })
    }

    pub fn rename_symbol(&self, address: u64, new_name: &str) -> Result<RenameSymbolResponse> {
        let req = pb::RenameSymbolRequest {
            address,
            new_name: new_name.to_string(),
        };
        let resp: pb::RenameSymbolResponse = self.call_rpc(
            "libghidra.SymbolsService/RenameSymbol",
            &req,
            "libghidra.RenameSymbolRequest",
        )?;
        Ok(RenameSymbolResponse {
            renamed: resp.renamed,
            name: resp.name,
        })
    }

    pub fn delete_symbol(&self, address: u64, name_filter: &str) -> Result<DeleteSymbolResponse> {
        let req = pb::DeleteSymbolRequest {
            address,
            name: name_filter.to_string(),
        };
        let resp: pb::DeleteSymbolResponse = self.call_rpc(
            "libghidra.SymbolsService/DeleteSymbol",
            &req,
            "libghidra.DeleteSymbolRequest",
        )?;
        Ok(DeleteSymbolResponse {
            deleted: resp.deleted,
            deleted_count: resp.deleted_count,
        })
    }

    // -- Xrefs ----------------------------------------------------------------

    pub fn list_xrefs(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListXrefsResponse> {
        let req = pb::ListXrefsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListXrefsResponse = self.call_rpc(
            "libghidra.XrefsService/ListXrefs",
            &req,
            "libghidra.ListXrefsRequest",
        )?;
        Ok(ListXrefsResponse {
            xrefs: resp.xrefs.into_iter().map(Into::into).collect(),
        })
    }

    // -- Types ----------------------------------------------------------------

    pub fn get_type(&self, path: &str) -> Result<GetTypeResponse> {
        let req = pb::GetTypeRequest {
            path: path.to_string(),
        };
        let resp: pb::GetTypeResponse = self.call_rpc(
            "libghidra.TypesService/GetType",
            &req,
            "libghidra.GetTypeRequest",
        )?;
        Ok(GetTypeResponse {
            r#type: resp.r#type.map(Into::into),
        })
    }

    pub fn list_types(&self, query: &str, limit: i32, offset: i32) -> Result<ListTypesResponse> {
        let req = pb::ListTypesRequest {
            query: query.to_string(),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListTypesResponse = self.call_rpc(
            "libghidra.TypesService/ListTypes",
            &req,
            "libghidra.ListTypesRequest",
        )?;
        Ok(ListTypesResponse {
            types: resp.types.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_type_aliases(
        &self,
        query: &str,
        limit: i32,
        offset: i32,
    ) -> Result<ListTypeAliasesResponse> {
        let req = pb::ListTypeAliasesRequest {
            query: query.to_string(),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListTypeAliasesResponse = self.call_rpc(
            "libghidra.TypesService/ListTypeAliases",
            &req,
            "libghidra.ListTypeAliasesRequest",
        )?;
        Ok(ListTypeAliasesResponse {
            aliases: resp.aliases.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_type_unions(
        &self,
        query: &str,
        limit: i32,
        offset: i32,
    ) -> Result<ListTypeUnionsResponse> {
        let req = pb::ListTypeUnionsRequest {
            query: query.to_string(),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListTypeUnionsResponse = self.call_rpc(
            "libghidra.TypesService/ListTypeUnions",
            &req,
            "libghidra.ListTypeUnionsRequest",
        )?;
        Ok(ListTypeUnionsResponse {
            unions: resp.unions.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_type_enums(
        &self,
        query: &str,
        limit: i32,
        offset: i32,
    ) -> Result<ListTypeEnumsResponse> {
        let req = pb::ListTypeEnumsRequest {
            query: query.to_string(),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListTypeEnumsResponse = self.call_rpc(
            "libghidra.TypesService/ListTypeEnums",
            &req,
            "libghidra.ListTypeEnumsRequest",
        )?;
        Ok(ListTypeEnumsResponse {
            enums: resp.enums.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_type_enum_members(
        &self,
        type_id_or_path: &str,
        limit: i32,
        offset: i32,
    ) -> Result<ListTypeEnumMembersResponse> {
        let req = pb::ListTypeEnumMembersRequest {
            r#type: type_id_or_path.to_string(),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListTypeEnumMembersResponse = self.call_rpc(
            "libghidra.TypesService/ListTypeEnumMembers",
            &req,
            "libghidra.ListTypeEnumMembersRequest",
        )?;
        Ok(ListTypeEnumMembersResponse {
            members: resp.members.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_type_members(
        &self,
        type_id_or_path: &str,
        limit: i32,
        offset: i32,
    ) -> Result<ListTypeMembersResponse> {
        let req = pb::ListTypeMembersRequest {
            r#type: type_id_or_path.to_string(),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListTypeMembersResponse = self.call_rpc(
            "libghidra.TypesService/ListTypeMembers",
            &req,
            "libghidra.ListTypeMembersRequest",
        )?;
        Ok(ListTypeMembersResponse {
            members: resp.members.into_iter().map(Into::into).collect(),
        })
    }

    pub fn get_function_signature(&self, address: u64) -> Result<GetFunctionSignatureResponse> {
        let req = pb::GetFunctionSignatureRequest { address };
        let resp: pb::GetFunctionSignatureResponse = self.call_rpc(
            "libghidra.TypesService/GetFunctionSignature",
            &req,
            "libghidra.GetFunctionSignatureRequest",
        )?;
        Ok(GetFunctionSignatureResponse {
            signature: resp.signature.map(Into::into),
        })
    }

    pub fn list_function_signatures(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListFunctionSignaturesResponse> {
        let req = pb::ListFunctionSignaturesRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListFunctionSignaturesResponse = self.call_rpc(
            "libghidra.TypesService/ListFunctionSignatures",
            &req,
            "libghidra.ListFunctionSignaturesRequest",
        )?;
        Ok(ListFunctionSignaturesResponse {
            signatures: resp.signatures.into_iter().map(Into::into).collect(),
        })
    }

    pub fn set_function_signature(
        &self,
        address: u64,
        prototype: &str,
        calling_convention: &str,
    ) -> Result<SetFunctionSignatureResponse> {
        let req = pb::SetFunctionSignatureRequest {
            address,
            prototype: prototype.to_string(),
            calling_convention: calling_convention.to_string(),
        };
        let resp: pb::SetFunctionSignatureResponse = self.call_rpc(
            "libghidra.TypesService/SetFunctionSignature",
            &req,
            "libghidra.SetFunctionSignatureRequest",
        )?;
        Ok(SetFunctionSignatureResponse {
            updated: resp.updated,
            function_name: resp.function_name,
            prototype: resp.prototype,
        })
    }

    pub fn rename_function_parameter(
        &self,
        address: u64,
        ordinal: i32,
        new_name: &str,
    ) -> Result<RenameFunctionParameterResponse> {
        let req = pb::RenameFunctionParameterRequest {
            address,
            ordinal,
            new_name: new_name.to_string(),
        };
        let resp: pb::RenameFunctionParameterResponse = self.call_rpc(
            "libghidra.TypesService/RenameFunctionParameter",
            &req,
            "libghidra.RenameFunctionParameterRequest",
        )?;
        Ok(RenameFunctionParameterResponse {
            updated: resp.updated,
            name: resp.name,
        })
    }

    pub fn set_function_parameter_type(
        &self,
        address: u64,
        ordinal: i32,
        data_type: &str,
    ) -> Result<SetFunctionParameterTypeResponse> {
        let req = pb::SetFunctionParameterTypeRequest {
            address,
            ordinal,
            data_type: data_type.to_string(),
        };
        let resp: pb::SetFunctionParameterTypeResponse = self.call_rpc(
            "libghidra.TypesService/SetFunctionParameterType",
            &req,
            "libghidra.SetFunctionParameterTypeRequest",
        )?;
        Ok(SetFunctionParameterTypeResponse {
            updated: resp.updated,
            data_type: resp.data_type,
        })
    }

    pub fn rename_function_local(
        &self,
        address: u64,
        local_id: &str,
        new_name: &str,
    ) -> Result<RenameFunctionLocalResponse> {
        let req = pb::RenameFunctionLocalRequest {
            address,
            local_id: local_id.to_string(),
            new_name: new_name.to_string(),
        };
        let resp: pb::RenameFunctionLocalResponse = self.call_rpc(
            "libghidra.TypesService/RenameFunctionLocal",
            &req,
            "libghidra.RenameFunctionLocalRequest",
        )?;
        Ok(RenameFunctionLocalResponse {
            updated: resp.updated,
            local_id: resp.local_id,
            name: resp.name,
        })
    }

    pub fn set_function_local_type(
        &self,
        address: u64,
        local_id: &str,
        data_type: &str,
    ) -> Result<SetFunctionLocalTypeResponse> {
        let req = pb::SetFunctionLocalTypeRequest {
            address,
            local_id: local_id.to_string(),
            data_type: data_type.to_string(),
        };
        let resp: pb::SetFunctionLocalTypeResponse = self.call_rpc(
            "libghidra.TypesService/SetFunctionLocalType",
            &req,
            "libghidra.SetFunctionLocalTypeRequest",
        )?;
        Ok(SetFunctionLocalTypeResponse {
            updated: resp.updated,
            local_id: resp.local_id,
            data_type: resp.data_type,
        })
    }

    pub fn apply_data_type(&self, address: u64, data_type: &str) -> Result<ApplyDataTypeResponse> {
        let req = pb::ApplyDataTypeRequest {
            address,
            data_type: data_type.to_string(),
        };
        let resp: pb::ApplyDataTypeResponse = self.call_rpc(
            "libghidra.TypesService/ApplyDataType",
            &req,
            "libghidra.ApplyDataTypeRequest",
        )?;
        Ok(ApplyDataTypeResponse {
            updated: resp.updated,
            data_type: resp.data_type,
        })
    }

    pub fn create_type(&self, name: &str, kind: &str, size: u64) -> Result<CreateTypeResponse> {
        let req = pb::CreateTypeRequest {
            name: name.to_string(),
            kind: kind.to_string(),
            size,
        };
        let resp: pb::CreateTypeResponse = self.call_rpc(
            "libghidra.TypesService/CreateType",
            &req,
            "libghidra.CreateTypeRequest",
        )?;
        Ok(CreateTypeResponse {
            updated: resp.updated,
        })
    }

    pub fn delete_type(&self, type_id_or_path: &str) -> Result<DeleteTypeResponse> {
        let req = pb::DeleteTypeRequest {
            r#type: type_id_or_path.to_string(),
        };
        let resp: pb::DeleteTypeResponse = self.call_rpc(
            "libghidra.TypesService/DeleteType",
            &req,
            "libghidra.DeleteTypeRequest",
        )?;
        Ok(DeleteTypeResponse {
            deleted: resp.deleted,
        })
    }

    pub fn rename_type(&self, type_id_or_path: &str, new_name: &str) -> Result<RenameTypeResponse> {
        let req = pb::RenameTypeRequest {
            r#type: type_id_or_path.to_string(),
            new_name: new_name.to_string(),
        };
        let resp: pb::RenameTypeResponse = self.call_rpc(
            "libghidra.TypesService/RenameType",
            &req,
            "libghidra.RenameTypeRequest",
        )?;
        Ok(RenameTypeResponse {
            updated: resp.updated,
            name: resp.name,
        })
    }

    pub fn create_type_alias(
        &self,
        name: &str,
        target_type: &str,
    ) -> Result<CreateTypeAliasResponse> {
        let req = pb::CreateTypeAliasRequest {
            name: name.to_string(),
            target_type: target_type.to_string(),
        };
        let resp: pb::CreateTypeAliasResponse = self.call_rpc(
            "libghidra.TypesService/CreateTypeAlias",
            &req,
            "libghidra.CreateTypeAliasRequest",
        )?;
        Ok(CreateTypeAliasResponse {
            updated: resp.updated,
        })
    }

    pub fn delete_type_alias(&self, type_id_or_path: &str) -> Result<DeleteTypeAliasResponse> {
        let req = pb::DeleteTypeAliasRequest {
            r#type: type_id_or_path.to_string(),
        };
        let resp: pb::DeleteTypeAliasResponse = self.call_rpc(
            "libghidra.TypesService/DeleteTypeAlias",
            &req,
            "libghidra.DeleteTypeAliasRequest",
        )?;
        Ok(DeleteTypeAliasResponse {
            deleted: resp.deleted,
        })
    }

    pub fn set_type_alias_target(
        &self,
        type_id_or_path: &str,
        target_type: &str,
    ) -> Result<SetTypeAliasTargetResponse> {
        let req = pb::SetTypeAliasTargetRequest {
            r#type: type_id_or_path.to_string(),
            target_type: target_type.to_string(),
        };
        let resp: pb::SetTypeAliasTargetResponse = self.call_rpc(
            "libghidra.TypesService/SetTypeAliasTarget",
            &req,
            "libghidra.SetTypeAliasTargetRequest",
        )?;
        Ok(SetTypeAliasTargetResponse {
            updated: resp.updated,
        })
    }

    pub fn create_type_enum(
        &self,
        name: &str,
        width: u64,
        is_signed: bool,
    ) -> Result<CreateTypeEnumResponse> {
        let req = pb::CreateTypeEnumRequest {
            name: name.to_string(),
            width,
            signed: is_signed,
        };
        let resp: pb::CreateTypeEnumResponse = self.call_rpc(
            "libghidra.TypesService/CreateTypeEnum",
            &req,
            "libghidra.CreateTypeEnumRequest",
        )?;
        Ok(CreateTypeEnumResponse {
            updated: resp.updated,
        })
    }

    pub fn delete_type_enum(&self, type_id_or_path: &str) -> Result<DeleteTypeEnumResponse> {
        let req = pb::DeleteTypeEnumRequest {
            r#type: type_id_or_path.to_string(),
        };
        let resp: pb::DeleteTypeEnumResponse = self.call_rpc(
            "libghidra.TypesService/DeleteTypeEnum",
            &req,
            "libghidra.DeleteTypeEnumRequest",
        )?;
        Ok(DeleteTypeEnumResponse {
            deleted: resp.deleted,
        })
    }

    pub fn add_type_enum_member(
        &self,
        type_id_or_path: &str,
        name: &str,
        value: i64,
    ) -> Result<AddTypeEnumMemberResponse> {
        let req = pb::AddTypeEnumMemberRequest {
            r#type: type_id_or_path.to_string(),
            name: name.to_string(),
            value,
        };
        let resp: pb::AddTypeEnumMemberResponse = self.call_rpc(
            "libghidra.TypesService/AddTypeEnumMember",
            &req,
            "libghidra.AddTypeEnumMemberRequest",
        )?;
        Ok(AddTypeEnumMemberResponse {
            updated: resp.updated,
        })
    }

    pub fn delete_type_enum_member(
        &self,
        type_id_or_path: &str,
        ordinal: u64,
    ) -> Result<DeleteTypeEnumMemberResponse> {
        let req = pb::DeleteTypeEnumMemberRequest {
            r#type: type_id_or_path.to_string(),
            ordinal,
        };
        let resp: pb::DeleteTypeEnumMemberResponse = self.call_rpc(
            "libghidra.TypesService/DeleteTypeEnumMember",
            &req,
            "libghidra.DeleteTypeEnumMemberRequest",
        )?;
        Ok(DeleteTypeEnumMemberResponse {
            deleted: resp.deleted,
        })
    }

    pub fn rename_type_enum_member(
        &self,
        type_id_or_path: &str,
        ordinal: u64,
        new_name: &str,
    ) -> Result<RenameTypeEnumMemberResponse> {
        let req = pb::RenameTypeEnumMemberRequest {
            r#type: type_id_or_path.to_string(),
            ordinal,
            new_name: new_name.to_string(),
        };
        let resp: pb::RenameTypeEnumMemberResponse = self.call_rpc(
            "libghidra.TypesService/RenameTypeEnumMember",
            &req,
            "libghidra.RenameTypeEnumMemberRequest",
        )?;
        Ok(RenameTypeEnumMemberResponse {
            updated: resp.updated,
        })
    }

    pub fn set_type_enum_member_value(
        &self,
        type_id_or_path: &str,
        ordinal: u64,
        value: i64,
    ) -> Result<SetTypeEnumMemberValueResponse> {
        let req = pb::SetTypeEnumMemberValueRequest {
            r#type: type_id_or_path.to_string(),
            ordinal,
            value,
        };
        let resp: pb::SetTypeEnumMemberValueResponse = self.call_rpc(
            "libghidra.TypesService/SetTypeEnumMemberValue",
            &req,
            "libghidra.SetTypeEnumMemberValueRequest",
        )?;
        Ok(SetTypeEnumMemberValueResponse {
            updated: resp.updated,
        })
    }

    pub fn add_type_member(
        &self,
        parent_type_id_or_path: &str,
        member_name: &str,
        member_type: &str,
        size: u64,
    ) -> Result<AddTypeMemberResponse> {
        let req = pb::AddTypeMemberRequest {
            r#type: parent_type_id_or_path.to_string(),
            name: member_name.to_string(),
            member_type: member_type.to_string(),
            size,
        };
        let resp: pb::AddTypeMemberResponse = self.call_rpc(
            "libghidra.TypesService/AddTypeMember",
            &req,
            "libghidra.AddTypeMemberRequest",
        )?;
        Ok(AddTypeMemberResponse {
            updated: resp.updated,
        })
    }

    pub fn delete_type_member(
        &self,
        parent_type_id_or_path: &str,
        ordinal: u64,
    ) -> Result<DeleteTypeMemberResponse> {
        let req = pb::DeleteTypeMemberRequest {
            r#type: parent_type_id_or_path.to_string(),
            ordinal,
        };
        let resp: pb::DeleteTypeMemberResponse = self.call_rpc(
            "libghidra.TypesService/DeleteTypeMember",
            &req,
            "libghidra.DeleteTypeMemberRequest",
        )?;
        Ok(DeleteTypeMemberResponse {
            deleted: resp.deleted,
        })
    }

    pub fn rename_type_member(
        &self,
        parent_type_id_or_path: &str,
        ordinal: u64,
        new_name: &str,
    ) -> Result<RenameTypeMemberResponse> {
        let req = pb::RenameTypeMemberRequest {
            r#type: parent_type_id_or_path.to_string(),
            ordinal,
            new_name: new_name.to_string(),
        };
        let resp: pb::RenameTypeMemberResponse = self.call_rpc(
            "libghidra.TypesService/RenameTypeMember",
            &req,
            "libghidra.RenameTypeMemberRequest",
        )?;
        Ok(RenameTypeMemberResponse {
            updated: resp.updated,
        })
    }

    pub fn set_type_member_type(
        &self,
        parent_type_id_or_path: &str,
        ordinal: u64,
        member_type: &str,
    ) -> Result<SetTypeMemberTypeResponse> {
        let req = pb::SetTypeMemberTypeRequest {
            r#type: parent_type_id_or_path.to_string(),
            ordinal,
            member_type: member_type.to_string(),
        };
        let resp: pb::SetTypeMemberTypeResponse = self.call_rpc(
            "libghidra.TypesService/SetTypeMemberType",
            &req,
            "libghidra.SetTypeMemberTypeRequest",
        )?;
        Ok(SetTypeMemberTypeResponse {
            updated: resp.updated,
        })
    }

    // -- Decompiler -----------------------------------------------------------

    pub fn get_decompilation(
        &self,
        address: u64,
        timeout_ms: u32,
    ) -> Result<GetDecompilationResponse> {
        let req = pb::DecompileFunctionRequest {
            address,
            timeout_ms,
        };
        let resp: pb::DecompileFunctionResponse = self.call_rpc(
            "libghidra.DecompilerService/DecompileFunction",
            &req,
            "libghidra.DecompileFunctionRequest",
        )?;
        Ok(GetDecompilationResponse {
            decompilation: resp.decompilation.map(Into::into),
        })
    }

    pub fn list_decompilations(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
        timeout_ms: u32,
    ) -> Result<ListDecompilationsResponse> {
        let req = pb::ListDecompilationsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
            timeout_ms,
        };
        let resp: pb::ListDecompilationsResponse = self.call_rpc(
            "libghidra.DecompilerService/ListDecompilations",
            &req,
            "libghidra.ListDecompilationsRequest",
        )?;
        Ok(ListDecompilationsResponse {
            decompilations: resp.decompilations.into_iter().map(Into::into).collect(),
        })
    }

    // -- Listing --------------------------------------------------------------

    pub fn get_instruction(&self, address: u64) -> Result<GetInstructionResponse> {
        let req = pb::GetInstructionRequest { address };
        let resp: pb::GetInstructionResponse = self.call_rpc(
            "libghidra.ListingService/GetInstruction",
            &req,
            "libghidra.GetInstructionRequest",
        )?;
        Ok(GetInstructionResponse {
            instruction: resp.instruction.map(Into::into),
        })
    }

    pub fn list_instructions(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListInstructionsResponse> {
        let req = pb::ListInstructionsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListInstructionsResponse = self.call_rpc(
            "libghidra.ListingService/ListInstructions",
            &req,
            "libghidra.ListInstructionsRequest",
        )?;
        Ok(ListInstructionsResponse {
            instructions: resp.instructions.into_iter().map(Into::into).collect(),
        })
    }

    pub fn get_comments(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<GetCommentsResponse> {
        let req = pb::GetCommentsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::GetCommentsResponse = self.call_rpc(
            "libghidra.ListingService/GetComments",
            &req,
            "libghidra.GetCommentsRequest",
        )?;
        Ok(GetCommentsResponse {
            comments: resp.comments.into_iter().map(Into::into).collect(),
        })
    }

    pub fn set_comment(
        &self,
        address: u64,
        kind: CommentKind,
        text: &str,
    ) -> Result<SetCommentResponse> {
        let req = pb::SetCommentRequest {
            address,
            kind: i32::from(kind),
            text: text.to_string(),
        };
        let resp: pb::SetCommentResponse = self.call_rpc(
            "libghidra.ListingService/SetComment",
            &req,
            "libghidra.SetCommentRequest",
        )?;
        Ok(SetCommentResponse {
            updated: resp.updated,
        })
    }

    pub fn delete_comment(&self, address: u64, kind: CommentKind) -> Result<DeleteCommentResponse> {
        let req = pb::DeleteCommentRequest {
            address,
            kind: i32::from(kind),
        };
        let resp: pb::DeleteCommentResponse = self.call_rpc(
            "libghidra.ListingService/DeleteComment",
            &req,
            "libghidra.DeleteCommentRequest",
        )?;
        Ok(DeleteCommentResponse {
            deleted: resp.deleted,
        })
    }

    pub fn rename_data_item(&self, address: u64, new_name: &str) -> Result<RenameDataItemResponse> {
        let req = pb::RenameDataItemRequest {
            address,
            new_name: new_name.to_string(),
        };
        let resp: pb::RenameDataItemResponse = self.call_rpc(
            "libghidra.ListingService/RenameDataItem",
            &req,
            "libghidra.RenameDataItemRequest",
        )?;
        Ok(RenameDataItemResponse {
            updated: resp.updated,
            name: resp.name,
        })
    }

    pub fn delete_data_item(&self, address: u64) -> Result<DeleteDataItemResponse> {
        let req = pb::DeleteDataItemRequest { address };
        let resp: pb::DeleteDataItemResponse = self.call_rpc(
            "libghidra.ListingService/DeleteDataItem",
            &req,
            "libghidra.DeleteDataItemRequest",
        )?;
        Ok(DeleteDataItemResponse {
            deleted: resp.deleted,
        })
    }

    pub fn list_data_items(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListDataItemsResponse> {
        let req = pb::ListDataItemsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListDataItemsResponse = self.call_rpc(
            "libghidra.ListingService/ListDataItems",
            &req,
            "libghidra.ListDataItemsRequest",
        )?;
        Ok(ListDataItemsResponse {
            data_items: resp.data_items.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_bookmarks(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
        type_filter: &str,
        category_filter: &str,
    ) -> Result<ListBookmarksResponse> {
        let req = pb::ListBookmarksRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
            type_filter: type_filter.to_string(),
            category_filter: category_filter.to_string(),
        };
        let resp: pb::ListBookmarksResponse = self.call_rpc(
            "libghidra.ListingService/ListBookmarks",
            &req,
            "libghidra.ListBookmarksRequest",
        )?;
        Ok(ListBookmarksResponse {
            bookmarks: resp.bookmarks.into_iter().map(Into::into).collect(),
        })
    }

    pub fn add_bookmark(
        &self,
        address: u64,
        r#type: &str,
        category: &str,
        comment: &str,
    ) -> Result<AddBookmarkResponse> {
        let req = pb::AddBookmarkRequest {
            address,
            r#type: r#type.to_string(),
            category: category.to_string(),
            comment: comment.to_string(),
        };
        let resp: pb::AddBookmarkResponse = self.call_rpc(
            "libghidra.ListingService/AddBookmark",
            &req,
            "libghidra.AddBookmarkRequest",
        )?;
        Ok(AddBookmarkResponse {
            updated: resp.updated,
        })
    }

    pub fn delete_bookmark(
        &self,
        address: u64,
        r#type: &str,
        category: &str,
    ) -> Result<DeleteBookmarkResponse> {
        let req = pb::DeleteBookmarkRequest {
            address,
            r#type: r#type.to_string(),
            category: category.to_string(),
        };
        let resp: pb::DeleteBookmarkResponse = self.call_rpc(
            "libghidra.ListingService/DeleteBookmark",
            &req,
            "libghidra.DeleteBookmarkRequest",
        )?;
        Ok(DeleteBookmarkResponse {
            deleted: resp.deleted,
        })
    }

    pub fn list_breakpoints(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
        kind_filter: &str,
        group_filter: &str,
    ) -> Result<ListBreakpointsResponse> {
        let req = pb::ListBreakpointsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
            kind_filter: kind_filter.to_string(),
            group_filter: group_filter.to_string(),
        };
        let resp: pb::ListBreakpointsResponse = self.call_rpc(
            "libghidra.ListingService/ListBreakpoints",
            &req,
            "libghidra.ListBreakpointsRequest",
        )?;
        Ok(ListBreakpointsResponse {
            breakpoints: resp.breakpoints.into_iter().map(Into::into).collect(),
        })
    }

    pub fn add_breakpoint(
        &self,
        address: u64,
        kind: &str,
        size: u64,
        enabled: bool,
        condition: &str,
        group: &str,
    ) -> Result<AddBreakpointResponse> {
        let req = pb::AddBreakpointRequest {
            address,
            kind: kind.to_string(),
            size,
            enabled,
            condition: condition.to_string(),
            group: group.to_string(),
        };
        let resp: pb::AddBreakpointResponse = self.call_rpc(
            "libghidra.ListingService/AddBreakpoint",
            &req,
            "libghidra.AddBreakpointRequest",
        )?;
        Ok(AddBreakpointResponse {
            updated: resp.updated,
        })
    }

    pub fn set_breakpoint_enabled(
        &self,
        address: u64,
        enabled: bool,
    ) -> Result<SetBreakpointEnabledResponse> {
        let req = pb::SetBreakpointEnabledRequest { address, enabled };
        let resp: pb::SetBreakpointEnabledResponse = self.call_rpc(
            "libghidra.ListingService/SetBreakpointEnabled",
            &req,
            "libghidra.SetBreakpointEnabledRequest",
        )?;
        Ok(SetBreakpointEnabledResponse {
            updated: resp.updated,
        })
    }

    pub fn set_breakpoint_kind(
        &self,
        address: u64,
        kind: &str,
    ) -> Result<SetBreakpointKindResponse> {
        let req = pb::SetBreakpointKindRequest {
            address,
            kind: kind.to_string(),
        };
        let resp: pb::SetBreakpointKindResponse = self.call_rpc(
            "libghidra.ListingService/SetBreakpointKind",
            &req,
            "libghidra.SetBreakpointKindRequest",
        )?;
        Ok(SetBreakpointKindResponse {
            updated: resp.updated,
        })
    }

    pub fn set_breakpoint_size(
        &self,
        address: u64,
        size: u64,
    ) -> Result<SetBreakpointSizeResponse> {
        let req = pb::SetBreakpointSizeRequest { address, size };
        let resp: pb::SetBreakpointSizeResponse = self.call_rpc(
            "libghidra.ListingService/SetBreakpointSize",
            &req,
            "libghidra.SetBreakpointSizeRequest",
        )?;
        Ok(SetBreakpointSizeResponse {
            updated: resp.updated,
        })
    }

    pub fn set_breakpoint_condition(
        &self,
        address: u64,
        condition: &str,
    ) -> Result<SetBreakpointConditionResponse> {
        let req = pb::SetBreakpointConditionRequest {
            address,
            condition: condition.to_string(),
        };
        let resp: pb::SetBreakpointConditionResponse = self.call_rpc(
            "libghidra.ListingService/SetBreakpointCondition",
            &req,
            "libghidra.SetBreakpointConditionRequest",
        )?;
        Ok(SetBreakpointConditionResponse {
            updated: resp.updated,
        })
    }

    pub fn set_breakpoint_group(
        &self,
        address: u64,
        group: &str,
    ) -> Result<SetBreakpointGroupResponse> {
        let req = pb::SetBreakpointGroupRequest {
            address,
            group: group.to_string(),
        };
        let resp: pb::SetBreakpointGroupResponse = self.call_rpc(
            "libghidra.ListingService/SetBreakpointGroup",
            &req,
            "libghidra.SetBreakpointGroupRequest",
        )?;
        Ok(SetBreakpointGroupResponse {
            updated: resp.updated,
        })
    }

    pub fn delete_breakpoint(&self, address: u64) -> Result<DeleteBreakpointResponse> {
        let req = pb::DeleteBreakpointRequest { address };
        let resp: pb::DeleteBreakpointResponse = self.call_rpc(
            "libghidra.ListingService/DeleteBreakpoint",
            &req,
            "libghidra.DeleteBreakpointRequest",
        )?;
        Ok(DeleteBreakpointResponse {
            deleted: resp.deleted,
        })
    }

    pub fn list_defined_strings(
        &self,
        range_start: u64,
        range_end: u64,
        limit: i32,
        offset: i32,
    ) -> Result<ListDefinedStringsResponse> {
        let req = pb::ListDefinedStringsRequest {
            range: Self::address_range(range_start, range_end),
            page: Self::pagination(limit, offset),
        };
        let resp: pb::ListDefinedStringsResponse = self.call_rpc(
            "libghidra.ListingService/ListDefinedStrings",
            &req,
            "libghidra.ListDefinedStringsRequest",
        )?;
        Ok(ListDefinedStringsResponse {
            strings: resp.strings.into_iter().map(Into::into).collect(),
        })
    }

    pub fn list_function_tags(&self) -> Result<ListFunctionTagsResponse> {
        let req = pb::ListFunctionTagsRequest {};
        let resp: pb::ListFunctionTagsResponse = self.call_rpc(
            "libghidra.FunctionsService/ListFunctionTags",
            &req,
            "libghidra.ListFunctionTagsRequest",
        )?;
        Ok(ListFunctionTagsResponse {
            tags: resp.tags.into_iter().map(Into::into).collect(),
        })
    }

    pub fn create_function_tag(
        &self,
        name: &str,
        comment: &str,
    ) -> Result<CreateFunctionTagResponse> {
        let req = pb::CreateFunctionTagRequest {
            name: name.to_string(),
            comment: comment.to_string(),
        };
        let resp: pb::CreateFunctionTagResponse = self.call_rpc(
            "libghidra.FunctionsService/CreateFunctionTag",
            &req,
            "libghidra.CreateFunctionTagRequest",
        )?;
        Ok(CreateFunctionTagResponse {
            created: resp.created,
        })
    }

    pub fn delete_function_tag(&self, name: &str) -> Result<DeleteFunctionTagResponse> {
        let req = pb::DeleteFunctionTagRequest {
            name: name.to_string(),
        };
        let resp: pb::DeleteFunctionTagResponse = self.call_rpc(
            "libghidra.FunctionsService/DeleteFunctionTag",
            &req,
            "libghidra.DeleteFunctionTagRequest",
        )?;
        Ok(DeleteFunctionTagResponse {
            deleted: resp.deleted,
        })
    }

    pub fn list_function_tag_mappings(
        &self,
        function_entry: u64,
    ) -> Result<ListFunctionTagMappingsResponse> {
        let req = pb::ListFunctionTagMappingsRequest { function_entry };
        let resp: pb::ListFunctionTagMappingsResponse = self.call_rpc(
            "libghidra.FunctionsService/ListFunctionTagMappings",
            &req,
            "libghidra.ListFunctionTagMappingsRequest",
        )?;
        Ok(ListFunctionTagMappingsResponse {
            mappings: resp.mappings.into_iter().map(Into::into).collect(),
        })
    }

    pub fn tag_function(&self, function_entry: u64, tag_name: &str) -> Result<TagFunctionResponse> {
        let req = pb::TagFunctionRequest {
            function_entry,
            tag_name: tag_name.to_string(),
        };
        let resp: pb::TagFunctionResponse = self.call_rpc(
            "libghidra.FunctionsService/TagFunction",
            &req,
            "libghidra.TagFunctionRequest",
        )?;
        Ok(TagFunctionResponse {
            updated: resp.updated,
        })
    }

    pub fn untag_function(
        &self,
        function_entry: u64,
        tag_name: &str,
    ) -> Result<UntagFunctionResponse> {
        let req = pb::UntagFunctionRequest {
            function_entry,
            tag_name: tag_name.to_string(),
        };
        let resp: pb::UntagFunctionResponse = self.call_rpc(
            "libghidra.FunctionsService/UntagFunction",
            &req,
            "libghidra.UntagFunctionRequest",
        )?;
        Ok(UntagFunctionResponse {
            updated: resp.updated,
        })
    }

    pub fn parse_declarations(&self, source_text: &str) -> Result<ParseDeclarationsResponse> {
        let req = pb::ParseDeclarationsRequest {
            source_text: source_text.to_string(),
        };
        let resp: pb::ParseDeclarationsResponse = self.call_rpc(
            "libghidra.TypesService/ParseDeclarations",
            &req,
            "libghidra.ParseDeclarationsRequest",
        )?;
        Ok(ParseDeclarationsResponse {
            types_created: resp.types_created,
            type_names: resp.type_names,
            errors: resp.errors,
        })
    }
}

fn map_ureq_error(e: &ureq::Error) -> (ErrorCode, String) {
    let msg = format!("{e}");
    match e {
        ureq::Error::StatusCode(status) => (
            ErrorCode::from_http_status(*status),
            format!("HTTP status {} for /rpc", status),
        ),
        ureq::Error::Timeout(_) => (ErrorCode::Timeout, format!("timeout: {msg}")),
        ureq::Error::ConnectionFailed => (
            ErrorCode::ConnectionFailed,
            format!("connection failed: {msg}"),
        ),
        _ => {
            // Check if the error message hints at connection issues
            let lower = msg.to_lowercase();
            if lower.contains("connect") || lower.contains("dns") || lower.contains("refused") {
                (
                    ErrorCode::ConnectionFailed,
                    format!("connection failed: {msg}"),
                )
            } else {
                (ErrorCode::TransportError, format!("transport error: {msg}"))
            }
        }
    }
}
