// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "libghidra/api.hpp"

namespace libghidra::client {

struct HttpClientOptions {
  std::string base_url = "http://127.0.0.1:18080";
  std::string auth_token;
  std::chrono::milliseconds connect_timeout{3000};
  std::chrono::milliseconds read_timeout{120000};
  std::chrono::milliseconds write_timeout{15000};
  int max_retries = 0;                             // 0 = no retry (opt-in)
  std::chrono::milliseconds initial_backoff{100};
  std::chrono::milliseconds max_backoff{5000};
  bool jitter = true;
};

class HttpClient final : public IClient {
 public:
  explicit HttpClient(HttpClientOptions options);
  ~HttpClient();

  HttpClient(HttpClient&&) noexcept;
  HttpClient& operator=(HttpClient&&) noexcept;

  HttpClient(const HttpClient&) = delete;
  HttpClient& operator=(const HttpClient&) = delete;

  StatusOr<HealthStatus> GetStatus() override;
  StatusOr<std::vector<Capability>> GetCapabilities() override;

  StatusOr<OpenProgramResponse> OpenProgram(const OpenProgramRequest& request) override;
  StatusOr<CloseProgramResponse> CloseProgram(ShutdownPolicy policy) override;
  StatusOr<SaveProgramResponse> SaveProgram() override;
  StatusOr<DiscardProgramResponse> DiscardProgram() override;
  StatusOr<RevisionResponse> GetRevision() override;
  StatusOr<ShutdownResponse> Shutdown(ShutdownPolicy policy) override;

  StatusOr<ReadBytesResponse> ReadBytes(std::uint64_t address, std::uint32_t length) override;
  StatusOr<WriteBytesResponse> WriteBytes(std::uint64_t address,
                                          const std::vector<std::uint8_t>& data) override;
  StatusOr<PatchBytesBatchResponse> PatchBytesBatch(
      const std::vector<BytePatch>& patches) override;
  StatusOr<ListMemoryBlocksResponse> ListMemoryBlocks(int limit, int offset) override;

  StatusOr<GetFunctionResponse> GetFunction(std::uint64_t address) override;
  StatusOr<ListFunctionsResponse> ListFunctions(std::uint64_t range_start,
                                                std::uint64_t range_end,
                                                int limit,
                                                int offset) override;
  StatusOr<RenameFunctionResponse> RenameFunction(std::uint64_t address,
                                                  const std::string& new_name) override;
  StatusOr<ListBasicBlocksResponse> ListBasicBlocks(std::uint64_t range_start,
                                                     std::uint64_t range_end,
                                                     int limit,
                                                     int offset) override;
  StatusOr<ListCFGEdgesResponse> ListCFGEdges(std::uint64_t range_start,
                                               std::uint64_t range_end,
                                               int limit,
                                               int offset) override;
  StatusOr<ListSwitchTablesResponse> ListSwitchTables(std::uint64_t range_start,
                                                       std::uint64_t range_end,
                                                       int limit,
                                                       int offset) override;
  StatusOr<ListDominatorsResponse> ListDominators(std::uint64_t range_start,
                                                   std::uint64_t range_end,
                                                   int limit,
                                                   int offset) override;
  StatusOr<ListPostDominatorsResponse> ListPostDominators(std::uint64_t range_start,
                                                           std::uint64_t range_end,
                                                           int limit,
                                                           int offset) override;
  StatusOr<ListLoopsResponse> ListLoops(std::uint64_t range_start,
                                         std::uint64_t range_end,
                                         int limit,
                                         int offset) override;
  StatusOr<ListFunctionTagsResponse> ListFunctionTags() override;
  StatusOr<CreateFunctionTagResponse> CreateFunctionTag(
      const std::string& name, const std::string& comment) override;
  StatusOr<DeleteFunctionTagResponse> DeleteFunctionTag(const std::string& name) override;
  StatusOr<ListFunctionTagMappingsResponse> ListFunctionTagMappings(
      std::uint64_t function_entry) override;
  StatusOr<TagFunctionResponse> TagFunction(std::uint64_t function_entry,
                                             const std::string& tag_name) override;
  StatusOr<UntagFunctionResponse> UntagFunction(std::uint64_t function_entry,
                                                 const std::string& tag_name) override;
  StatusOr<GetSymbolResponse> GetSymbol(std::uint64_t address) override;
  StatusOr<ListSymbolsResponse> ListSymbols(std::uint64_t range_start,
                                            std::uint64_t range_end,
                                            int limit,
                                            int offset) override;
  StatusOr<RenameSymbolResponse> RenameSymbol(std::uint64_t address,
                                              const std::string& new_name) override;
  StatusOr<DeleteSymbolResponse> DeleteSymbol(std::uint64_t address,
                                              const std::string& name_filter) override;
  StatusOr<ListXrefsResponse> ListXrefs(std::uint64_t range_start,
                                        std::uint64_t range_end,
                                        int limit,
                                        int offset) override;
  StatusOr<GetTypeResponse> GetType(const std::string& path) override;
  StatusOr<ListTypesResponse> ListTypes(const std::string& query,
                                        int limit,
                                        int offset) override;
  StatusOr<ListTypeAliasesResponse> ListTypeAliases(const std::string& query,
                                                    int limit,
                                                    int offset) override;
  StatusOr<ListTypeUnionsResponse> ListTypeUnions(const std::string& query,
                                                  int limit,
                                                  int offset) override;
  StatusOr<ListTypeEnumsResponse> ListTypeEnums(const std::string& query,
                                                int limit,
                                                int offset) override;
  StatusOr<ListTypeEnumMembersResponse> ListTypeEnumMembers(const std::string& type_id_or_path,
                                                            int limit,
                                                            int offset) override;
  StatusOr<ListTypeMembersResponse> ListTypeMembers(const std::string& type_id_or_path,
                                                    int limit,
                                                    int offset) override;
  StatusOr<GetFunctionSignatureResponse> GetFunctionSignature(std::uint64_t address) override;
  StatusOr<ListFunctionSignaturesResponse> ListFunctionSignatures(std::uint64_t range_start,
                                                                  std::uint64_t range_end,
                                                                  int limit,
                                                                  int offset) override;
  StatusOr<SetFunctionSignatureResponse> SetFunctionSignature(
      std::uint64_t address,
      const std::string& prototype) override;
  StatusOr<RenameFunctionParameterResponse> RenameFunctionParameter(
      std::uint64_t address,
      int ordinal,
      const std::string& new_name) override;
  StatusOr<SetFunctionParameterTypeResponse> SetFunctionParameterType(
      std::uint64_t address,
      int ordinal,
      const std::string& data_type) override;
  StatusOr<RenameFunctionLocalResponse> RenameFunctionLocal(
      std::uint64_t address,
      const std::string& local_id,
      const std::string& new_name) override;
  StatusOr<SetFunctionLocalTypeResponse> SetFunctionLocalType(
      std::uint64_t address,
      const std::string& local_id,
      const std::string& data_type) override;
  StatusOr<ApplyDataTypeResponse> ApplyDataType(std::uint64_t address,
                                                const std::string& data_type) override;
  StatusOr<CreateTypeResponse> CreateType(const std::string& name,
                                          const std::string& kind,
                                          std::uint64_t size) override;
  StatusOr<DeleteTypeResponse> DeleteType(const std::string& type_id_or_path) override;
  StatusOr<RenameTypeResponse> RenameType(const std::string& type_id_or_path,
                                          const std::string& new_name) override;
  StatusOr<CreateTypeAliasResponse> CreateTypeAlias(const std::string& name,
                                                    const std::string& target_type) override;
  StatusOr<DeleteTypeAliasResponse> DeleteTypeAlias(const std::string& type_id_or_path) override;
  StatusOr<SetTypeAliasTargetResponse> SetTypeAliasTarget(const std::string& type_id_or_path,
                                                          const std::string& target_type) override;
  StatusOr<CreateTypeEnumResponse> CreateTypeEnum(const std::string& name,
                                                  std::uint64_t width,
                                                  bool is_signed) override;
  StatusOr<DeleteTypeEnumResponse> DeleteTypeEnum(const std::string& type_id_or_path) override;
  StatusOr<AddTypeEnumMemberResponse> AddTypeEnumMember(const std::string& type_id_or_path,
                                                        const std::string& name,
                                                        std::int64_t value) override;
  StatusOr<DeleteTypeEnumMemberResponse> DeleteTypeEnumMember(
      const std::string& type_id_or_path,
      std::uint64_t ordinal) override;
  StatusOr<RenameTypeEnumMemberResponse> RenameTypeEnumMember(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      const std::string& new_name) override;
  StatusOr<SetTypeEnumMemberValueResponse> SetTypeEnumMemberValue(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      std::int64_t value) override;
  StatusOr<AddTypeMemberResponse> AddTypeMember(const std::string& parent_type_id_or_path,
                                                const std::string& member_name,
                                                const std::string& member_type,
                                                std::uint64_t size) override;
  StatusOr<DeleteTypeMemberResponse> DeleteTypeMember(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal) override;
  StatusOr<RenameTypeMemberResponse> RenameTypeMember(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& new_name) override;
  StatusOr<SetTypeMemberTypeResponse> SetTypeMemberType(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& member_type) override;
  StatusOr<SetTypeMemberCommentResponse> SetTypeMemberComment(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& comment) override;
  StatusOr<SetTypeEnumMemberCommentResponse> SetTypeEnumMemberComment(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      const std::string& comment) override;
  StatusOr<ParseDeclarationsResponse> ParseDeclarations(
      const std::string& source_text) override;
  StatusOr<GetDecompilationResponse> GetDecompilation(std::uint64_t address,
                                                      int timeout_ms) override;
  StatusOr<ListDecompilationsResponse> ListDecompilations(std::uint64_t range_start,
                                                          std::uint64_t range_end,
                                                          int limit,
                                                          int offset,
                                                          int timeout_ms) override;

  StatusOr<GetInstructionResponse> GetInstruction(std::uint64_t address) override;
  StatusOr<ListInstructionsResponse> ListInstructions(std::uint64_t range_start,
                                                      std::uint64_t range_end,
                                                      int limit,
                                                      int offset) override;
  StatusOr<GetCommentsResponse> GetComments(std::uint64_t range_start,
                                            std::uint64_t range_end,
                                            int limit,
                                            int offset) override;
  StatusOr<SetCommentResponse> SetComment(std::uint64_t address,
                                          CommentKind kind,
                                          const std::string& text) override;
  StatusOr<DeleteCommentResponse> DeleteComment(std::uint64_t address,
                                                CommentKind kind) override;
  StatusOr<RenameDataItemResponse> RenameDataItem(std::uint64_t address,
                                                  const std::string& new_name) override;
  StatusOr<DeleteDataItemResponse> DeleteDataItem(std::uint64_t address) override;
  StatusOr<ListDataItemsResponse> ListDataItems(std::uint64_t range_start,
                                                std::uint64_t range_end,
                                                int limit,
                                                int offset) override;
  StatusOr<ListBookmarksResponse> ListBookmarks(std::uint64_t range_start,
                                                std::uint64_t range_end,
                                                int limit,
                                                int offset,
                                                const std::string& type_filter,
                                                const std::string& category_filter) override;
  StatusOr<AddBookmarkResponse> AddBookmark(std::uint64_t address,
                                            const std::string& type,
                                            const std::string& category,
                                            const std::string& comment) override;
  StatusOr<DeleteBookmarkResponse> DeleteBookmark(std::uint64_t address,
                                                  const std::string& type,
                                                  const std::string& category) override;
  StatusOr<ListBreakpointsResponse> ListBreakpoints(std::uint64_t range_start,
                                                    std::uint64_t range_end,
                                                    int limit,
                                                    int offset,
                                                    const std::string& kind_filter,
                                                    const std::string& group_filter) override;
  StatusOr<AddBreakpointResponse> AddBreakpoint(std::uint64_t address,
                                                const std::string& kind,
                                                std::uint64_t size,
                                                bool enabled,
                                                const std::string& condition,
                                                const std::string& group) override;
  StatusOr<SetBreakpointEnabledResponse> SetBreakpointEnabled(std::uint64_t address,
                                                              bool enabled) override;
  StatusOr<SetBreakpointKindResponse> SetBreakpointKind(std::uint64_t address,
                                                        const std::string& kind) override;
  StatusOr<SetBreakpointSizeResponse> SetBreakpointSize(std::uint64_t address,
                                                        std::uint64_t size) override;
  StatusOr<SetBreakpointConditionResponse> SetBreakpointCondition(
      std::uint64_t address,
      const std::string& condition) override;
  StatusOr<SetBreakpointGroupResponse> SetBreakpointGroup(std::uint64_t address,
                                                          const std::string& group) override;
  StatusOr<DeleteBreakpointResponse> DeleteBreakpoint(std::uint64_t address) override;
  StatusOr<ListDefinedStringsResponse> ListDefinedStrings(std::uint64_t range_start,
                                                           std::uint64_t range_end,
                                                           int limit,
                                                           int offset) override;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

/// Factory for the HTTP backend (returns IClient*).
std::unique_ptr<IClient> CreateHttpClient(HttpClientOptions options);

}  // namespace libghidra::client
