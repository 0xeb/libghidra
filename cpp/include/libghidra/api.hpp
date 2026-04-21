// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>

#include "libghidra/decompiler.hpp"
#include "libghidra/functions.hpp"
#include "libghidra/health.hpp"
#include "libghidra/listing.hpp"
#include "libghidra/memory.hpp"
#include "libghidra/session.hpp"
#include "libghidra/symbols.hpp"
#include "libghidra/types.hpp"
#include "libghidra/xrefs.hpp"

namespace libghidra::client {

/// Composite interface unifying all service interfaces behind a single pointer.
///
/// Every pure virtual inherits a default NOT_SUPPORTED stub so that backends
/// only need to override the subset they actually implement.  HttpClient
/// overrides everything; LocalClient overrides its supported subset.
class IClient : public IHealthClient,
                public ISessionClient,
                public IMemoryClient,
                public IFunctionsClient,
                public ISymbolsClient,
                public IXrefsClient,
                public ITypesClient,
                public IDecompilerClient,
                public IListingClient {
 public:
  ~IClient() override = default;

  // -- IHealthClient defaults ------------------------------------------------

  StatusOr<HealthStatus> GetStatus() override {
    return StatusOr<HealthStatus>::FromError("NOT_SUPPORTED",
                                             "not implemented by this backend");
  }
  StatusOr<std::vector<Capability>> GetCapabilities() override {
    return StatusOr<std::vector<Capability>>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }

  // -- ISessionClient defaults -----------------------------------------------

  StatusOr<OpenProgramResponse> OpenProgram(const OpenProgramRequest&) override {
    return StatusOr<OpenProgramResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<CloseProgramResponse> CloseProgram(ShutdownPolicy) override {
    return StatusOr<CloseProgramResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SaveProgramResponse> SaveProgram() override {
    return StatusOr<SaveProgramResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<DiscardProgramResponse> DiscardProgram() override {
    return StatusOr<DiscardProgramResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<RevisionResponse> GetRevision() override {
    return StatusOr<RevisionResponse>::FromError("NOT_SUPPORTED",
                                                 "not implemented by this backend");
  }
  StatusOr<ShutdownResponse> Shutdown(ShutdownPolicy) override {
    return StatusOr<ShutdownResponse>::FromError("NOT_SUPPORTED",
                                                 "not implemented by this backend");
  }

  // -- IMemoryClient defaults ------------------------------------------------

  StatusOr<ReadBytesResponse> ReadBytes(std::uint64_t, std::uint32_t) override {
    return StatusOr<ReadBytesResponse>::FromError("NOT_SUPPORTED",
                                                  "not implemented by this backend");
  }
  StatusOr<WriteBytesResponse> WriteBytes(std::uint64_t,
                                          const std::vector<std::uint8_t>&) override {
    return StatusOr<WriteBytesResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<PatchBytesBatchResponse> PatchBytesBatch(
      const std::vector<BytePatch>&) override {
    return StatusOr<PatchBytesBatchResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListMemoryBlocksResponse> ListMemoryBlocks(int, int) override {
    return StatusOr<ListMemoryBlocksResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }

  // -- IFunctionsClient defaults ---------------------------------------------

  StatusOr<GetFunctionResponse> GetFunction(std::uint64_t) override {
    return StatusOr<GetFunctionResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListFunctionsResponse> ListFunctions(std::uint64_t, std::uint64_t, int,
                                                int) override {
    return StatusOr<ListFunctionsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<RenameFunctionResponse> RenameFunction(std::uint64_t,
                                                  const std::string&) override {
    return StatusOr<RenameFunctionResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListBasicBlocksResponse> ListBasicBlocks(std::uint64_t, std::uint64_t, int,
                                                    int) override {
    return StatusOr<ListBasicBlocksResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListCFGEdgesResponse> ListCFGEdges(std::uint64_t, std::uint64_t, int,
                                              int) override {
    return StatusOr<ListCFGEdgesResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListSwitchTablesResponse> ListSwitchTables(std::uint64_t, std::uint64_t,
                                                      int, int) override {
    return StatusOr<ListSwitchTablesResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListDominatorsResponse> ListDominators(std::uint64_t, std::uint64_t,
                                                  int, int) override {
    return StatusOr<ListDominatorsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListPostDominatorsResponse> ListPostDominators(std::uint64_t, std::uint64_t,
                                                          int, int) override {
    return StatusOr<ListPostDominatorsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListLoopsResponse> ListLoops(std::uint64_t, std::uint64_t,
                                        int, int) override {
    return StatusOr<ListLoopsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }

  StatusOr<ListFunctionTagsResponse> ListFunctionTags() override {
    return StatusOr<ListFunctionTagsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<CreateFunctionTagResponse> CreateFunctionTag(const std::string&,
                                                        const std::string&) override {
    return StatusOr<CreateFunctionTagResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<DeleteFunctionTagResponse> DeleteFunctionTag(const std::string&) override {
    return StatusOr<DeleteFunctionTagResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListFunctionTagMappingsResponse> ListFunctionTagMappings(
      std::uint64_t) override {
    return StatusOr<ListFunctionTagMappingsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<TagFunctionResponse> TagFunction(std::uint64_t, const std::string&) override {
    return StatusOr<TagFunctionResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<UntagFunctionResponse> UntagFunction(std::uint64_t,
                                                const std::string&) override {
    return StatusOr<UntagFunctionResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }

  // -- ISymbolsClient defaults -----------------------------------------------

  StatusOr<GetSymbolResponse> GetSymbol(std::uint64_t) override {
    return StatusOr<GetSymbolResponse>::FromError("NOT_SUPPORTED",
                                                  "not implemented by this backend");
  }
  StatusOr<ListSymbolsResponse> ListSymbols(std::uint64_t, std::uint64_t, int,
                                            int) override {
    return StatusOr<ListSymbolsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<RenameSymbolResponse> RenameSymbol(std::uint64_t,
                                              const std::string&) override {
    return StatusOr<RenameSymbolResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<DeleteSymbolResponse> DeleteSymbol(std::uint64_t,
                                              const std::string&) override {
    return StatusOr<DeleteSymbolResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }

  // -- IXrefsClient defaults -------------------------------------------------

  StatusOr<ListXrefsResponse> ListXrefs(std::uint64_t, std::uint64_t, int,
                                        int) override {
    return StatusOr<ListXrefsResponse>::FromError("NOT_SUPPORTED",
                                                  "not implemented by this backend");
  }

  // -- ITypesClient defaults -------------------------------------------------

  StatusOr<GetTypeResponse> GetType(const std::string&) override {
    return StatusOr<GetTypeResponse>::FromError("NOT_SUPPORTED",
                                                "not implemented by this backend");
  }
  StatusOr<ListTypesResponse> ListTypes(const std::string&, int, int) override {
    return StatusOr<ListTypesResponse>::FromError("NOT_SUPPORTED",
                                                  "not implemented by this backend");
  }
  StatusOr<ListTypeAliasesResponse> ListTypeAliases(const std::string&, int,
                                                    int) override {
    return StatusOr<ListTypeAliasesResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListTypeUnionsResponse> ListTypeUnions(const std::string&, int,
                                                  int) override {
    return StatusOr<ListTypeUnionsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListTypeEnumsResponse> ListTypeEnums(const std::string&, int,
                                                int) override {
    return StatusOr<ListTypeEnumsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListTypeEnumMembersResponse> ListTypeEnumMembers(const std::string&, int,
                                                            int) override {
    return StatusOr<ListTypeEnumMembersResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListTypeMembersResponse> ListTypeMembers(const std::string&, int,
                                                    int) override {
    return StatusOr<ListTypeMembersResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<GetFunctionSignatureResponse> GetFunctionSignature(std::uint64_t) override {
    return StatusOr<GetFunctionSignatureResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListFunctionSignaturesResponse> ListFunctionSignatures(
      std::uint64_t, std::uint64_t, int, int) override {
    return StatusOr<ListFunctionSignaturesResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetFunctionSignatureResponse> SetFunctionSignature(
      std::uint64_t, const std::string&) override {
    return StatusOr<SetFunctionSignatureResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<RenameFunctionParameterResponse> RenameFunctionParameter(
      std::uint64_t, int, const std::string&) override {
    return StatusOr<RenameFunctionParameterResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetFunctionParameterTypeResponse> SetFunctionParameterType(
      std::uint64_t, int, const std::string&) override {
    return StatusOr<SetFunctionParameterTypeResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<RenameFunctionLocalResponse> RenameFunctionLocal(
      std::uint64_t, const std::string&, const std::string&) override {
    return StatusOr<RenameFunctionLocalResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetFunctionLocalTypeResponse> SetFunctionLocalType(
      std::uint64_t, const std::string&, const std::string&) override {
    return StatusOr<SetFunctionLocalTypeResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ApplyDataTypeResponse> ApplyDataType(std::uint64_t,
                                                const std::string&) override {
    return StatusOr<ApplyDataTypeResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<CreateTypeResponse> CreateType(const std::string&, const std::string&,
                                          std::uint64_t) override {
    return StatusOr<CreateTypeResponse>::FromError("NOT_SUPPORTED",
                                                   "not implemented by this backend");
  }
  StatusOr<DeleteTypeResponse> DeleteType(const std::string&) override {
    return StatusOr<DeleteTypeResponse>::FromError("NOT_SUPPORTED",
                                                   "not implemented by this backend");
  }
  StatusOr<RenameTypeResponse> RenameType(const std::string&,
                                          const std::string&) override {
    return StatusOr<RenameTypeResponse>::FromError("NOT_SUPPORTED",
                                                   "not implemented by this backend");
  }
  StatusOr<CreateTypeAliasResponse> CreateTypeAlias(const std::string&,
                                                    const std::string&) override {
    return StatusOr<CreateTypeAliasResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<DeleteTypeAliasResponse> DeleteTypeAlias(const std::string&) override {
    return StatusOr<DeleteTypeAliasResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetTypeAliasTargetResponse> SetTypeAliasTarget(const std::string&,
                                                          const std::string&) override {
    return StatusOr<SetTypeAliasTargetResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<CreateTypeEnumResponse> CreateTypeEnum(const std::string&, std::uint64_t,
                                                  bool) override {
    return StatusOr<CreateTypeEnumResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<DeleteTypeEnumResponse> DeleteTypeEnum(const std::string&) override {
    return StatusOr<DeleteTypeEnumResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<AddTypeEnumMemberResponse> AddTypeEnumMember(const std::string&,
                                                        const std::string&,
                                                        std::int64_t) override {
    return StatusOr<AddTypeEnumMemberResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<DeleteTypeEnumMemberResponse> DeleteTypeEnumMember(const std::string&,
                                                              std::uint64_t) override {
    return StatusOr<DeleteTypeEnumMemberResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<RenameTypeEnumMemberResponse> RenameTypeEnumMember(
      const std::string&, std::uint64_t, const std::string&) override {
    return StatusOr<RenameTypeEnumMemberResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetTypeEnumMemberValueResponse> SetTypeEnumMemberValue(
      const std::string&, std::uint64_t, std::int64_t) override {
    return StatusOr<SetTypeEnumMemberValueResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<AddTypeMemberResponse> AddTypeMember(const std::string&, const std::string&,
                                                const std::string&,
                                                std::uint64_t) override {
    return StatusOr<AddTypeMemberResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<DeleteTypeMemberResponse> DeleteTypeMember(const std::string&,
                                                      std::uint64_t) override {
    return StatusOr<DeleteTypeMemberResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<RenameTypeMemberResponse> RenameTypeMember(const std::string&, std::uint64_t,
                                                      const std::string&) override {
    return StatusOr<RenameTypeMemberResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetTypeMemberTypeResponse> SetTypeMemberType(const std::string&,
                                                        std::uint64_t,
                                                        const std::string&) override {
    return StatusOr<SetTypeMemberTypeResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetTypeMemberCommentResponse> SetTypeMemberComment(const std::string&,
                                                               std::uint64_t,
                                                               const std::string&) override {
    return StatusOr<SetTypeMemberCommentResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetTypeEnumMemberCommentResponse> SetTypeEnumMemberComment(
      const std::string&, std::uint64_t, const std::string&) override {
    return StatusOr<SetTypeEnumMemberCommentResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ParseDeclarationsResponse> ParseDeclarations(const std::string&) override {
    return StatusOr<ParseDeclarationsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }

  // -- IDecompilerClient defaults --------------------------------------------

  StatusOr<GetDecompilationResponse> GetDecompilation(std::uint64_t, int) override {
    return StatusOr<GetDecompilationResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListDecompilationsResponse> ListDecompilations(std::uint64_t, std::uint64_t,
                                                          int, int, int) override {
    return StatusOr<ListDecompilationsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }

  // -- IListingClient defaults -----------------------------------------------

  StatusOr<GetInstructionResponse> GetInstruction(std::uint64_t) override {
    return StatusOr<GetInstructionResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListInstructionsResponse> ListInstructions(std::uint64_t, std::uint64_t, int,
                                                      int) override {
    return StatusOr<ListInstructionsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<GetCommentsResponse> GetComments(std::uint64_t, std::uint64_t, int,
                                            int) override {
    return StatusOr<GetCommentsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetCommentResponse> SetComment(std::uint64_t, CommentKind,
                                          const std::string&) override {
    return StatusOr<SetCommentResponse>::FromError("NOT_SUPPORTED",
                                                   "not implemented by this backend");
  }
  StatusOr<DeleteCommentResponse> DeleteComment(std::uint64_t, CommentKind) override {
    return StatusOr<DeleteCommentResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<RenameDataItemResponse> RenameDataItem(std::uint64_t,
                                                  const std::string&) override {
    return StatusOr<RenameDataItemResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<DeleteDataItemResponse> DeleteDataItem(std::uint64_t) override {
    return StatusOr<DeleteDataItemResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListDataItemsResponse> ListDataItems(std::uint64_t, std::uint64_t, int,
                                                int) override {
    return StatusOr<ListDataItemsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListBookmarksResponse> ListBookmarks(std::uint64_t, std::uint64_t, int, int,
                                                const std::string&,
                                                const std::string&) override {
    return StatusOr<ListBookmarksResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<AddBookmarkResponse> AddBookmark(std::uint64_t, const std::string&,
                                            const std::string&,
                                            const std::string&) override {
    return StatusOr<AddBookmarkResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<DeleteBookmarkResponse> DeleteBookmark(std::uint64_t, const std::string&,
                                                  const std::string&) override {
    return StatusOr<DeleteBookmarkResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListBreakpointsResponse> ListBreakpoints(std::uint64_t, std::uint64_t, int,
                                                    int, const std::string&,
                                                    const std::string&) override {
    return StatusOr<ListBreakpointsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<AddBreakpointResponse> AddBreakpoint(std::uint64_t, const std::string&,
                                                std::uint64_t, bool,
                                                const std::string&,
                                                const std::string&) override {
    return StatusOr<AddBreakpointResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetBreakpointEnabledResponse> SetBreakpointEnabled(std::uint64_t,
                                                              bool) override {
    return StatusOr<SetBreakpointEnabledResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetBreakpointKindResponse> SetBreakpointKind(std::uint64_t,
                                                        const std::string&) override {
    return StatusOr<SetBreakpointKindResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetBreakpointSizeResponse> SetBreakpointSize(std::uint64_t,
                                                        std::uint64_t) override {
    return StatusOr<SetBreakpointSizeResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetBreakpointConditionResponse> SetBreakpointCondition(
      std::uint64_t, const std::string&) override {
    return StatusOr<SetBreakpointConditionResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<SetBreakpointGroupResponse> SetBreakpointGroup(std::uint64_t,
                                                          const std::string&) override {
    return StatusOr<SetBreakpointGroupResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<DeleteBreakpointResponse> DeleteBreakpoint(std::uint64_t) override {
    return StatusOr<DeleteBreakpointResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
  StatusOr<ListDefinedStringsResponse> ListDefinedStrings(std::uint64_t, std::uint64_t,
                                                          int, int) override {
    return StatusOr<ListDefinedStringsResponse>::FromError(
        "NOT_SUPPORTED", "not implemented by this backend");
  }
};

}  // namespace libghidra::client
