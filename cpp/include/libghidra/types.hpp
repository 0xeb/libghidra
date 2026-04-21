// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <cstdint>
#include <string>

#include "libghidra/status.hpp"
#include "libghidra/models.hpp"

namespace libghidra::client {

class ITypesClient {
 public:
  virtual ~ITypesClient() = default;

  virtual StatusOr<GetTypeResponse> GetType(const std::string& path) = 0;
  virtual StatusOr<ListTypesResponse> ListTypes(const std::string& query,
                                                int limit,
                                                int offset) = 0;
  virtual StatusOr<ListTypeAliasesResponse> ListTypeAliases(const std::string& query,
                                                            int limit,
                                                            int offset) = 0;
  virtual StatusOr<ListTypeUnionsResponse> ListTypeUnions(const std::string& query,
                                                          int limit,
                                                          int offset) = 0;
  virtual StatusOr<ListTypeEnumsResponse> ListTypeEnums(const std::string& query,
                                                        int limit,
                                                        int offset) = 0;
  virtual StatusOr<ListTypeEnumMembersResponse> ListTypeEnumMembers(
      const std::string& type_id_or_path,
      int limit,
      int offset) = 0;
  virtual StatusOr<ListTypeMembersResponse> ListTypeMembers(
      const std::string& type_id_or_path,
      int limit,
      int offset) = 0;
  virtual StatusOr<GetFunctionSignatureResponse> GetFunctionSignature(std::uint64_t address) = 0;
  virtual StatusOr<ListFunctionSignaturesResponse> ListFunctionSignatures(
      std::uint64_t range_start,
      std::uint64_t range_end,
      int limit,
      int offset) = 0;
  virtual StatusOr<SetFunctionSignatureResponse> SetFunctionSignature(
      std::uint64_t address,
      const std::string& prototype) = 0;
  virtual StatusOr<RenameFunctionParameterResponse> RenameFunctionParameter(
      std::uint64_t address,
      int ordinal,
      const std::string& new_name) = 0;
  virtual StatusOr<SetFunctionParameterTypeResponse> SetFunctionParameterType(
      std::uint64_t address,
      int ordinal,
      const std::string& data_type) = 0;
  virtual StatusOr<RenameFunctionLocalResponse> RenameFunctionLocal(
      std::uint64_t address,
      const std::string& local_id,
      const std::string& new_name) = 0;
  virtual StatusOr<SetFunctionLocalTypeResponse> SetFunctionLocalType(
      std::uint64_t address,
      const std::string& local_id,
      const std::string& data_type) = 0;
  virtual StatusOr<ApplyDataTypeResponse> ApplyDataType(
      std::uint64_t address,
      const std::string& data_type) = 0;
  virtual StatusOr<CreateTypeResponse> CreateType(const std::string& name,
                                                  const std::string& kind,
                                                  std::uint64_t size) = 0;
  virtual StatusOr<DeleteTypeResponse> DeleteType(const std::string& type_id_or_path) = 0;
  virtual StatusOr<RenameTypeResponse> RenameType(const std::string& type_id_or_path,
                                                  const std::string& new_name) = 0;
  virtual StatusOr<CreateTypeAliasResponse> CreateTypeAlias(const std::string& name,
                                                            const std::string& target_type) = 0;
  virtual StatusOr<DeleteTypeAliasResponse> DeleteTypeAlias(
      const std::string& type_id_or_path) = 0;
  virtual StatusOr<SetTypeAliasTargetResponse> SetTypeAliasTarget(
      const std::string& type_id_or_path,
      const std::string& target_type) = 0;
  virtual StatusOr<CreateTypeEnumResponse> CreateTypeEnum(const std::string& name,
                                                          std::uint64_t width,
                                                          bool is_signed) = 0;
  virtual StatusOr<DeleteTypeEnumResponse> DeleteTypeEnum(const std::string& type_id_or_path) = 0;
  virtual StatusOr<AddTypeEnumMemberResponse> AddTypeEnumMember(const std::string& type_id_or_path,
                                                                const std::string& name,
                                                                std::int64_t value) = 0;
  virtual StatusOr<DeleteTypeEnumMemberResponse> DeleteTypeEnumMember(
      const std::string& type_id_or_path,
      std::uint64_t ordinal) = 0;
  virtual StatusOr<RenameTypeEnumMemberResponse> RenameTypeEnumMember(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      const std::string& new_name) = 0;
  virtual StatusOr<SetTypeEnumMemberValueResponse> SetTypeEnumMemberValue(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      std::int64_t value) = 0;
  virtual StatusOr<AddTypeMemberResponse> AddTypeMember(const std::string& parent_type_id_or_path,
                                                        const std::string& member_name,
                                                        const std::string& member_type,
                                                        std::uint64_t size) = 0;
  virtual StatusOr<DeleteTypeMemberResponse> DeleteTypeMember(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal) = 0;
  virtual StatusOr<RenameTypeMemberResponse> RenameTypeMember(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& new_name) = 0;
  virtual StatusOr<SetTypeMemberTypeResponse> SetTypeMemberType(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& member_type) = 0;
  virtual StatusOr<SetTypeMemberCommentResponse> SetTypeMemberComment(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& comment) = 0;
  virtual StatusOr<SetTypeEnumMemberCommentResponse> SetTypeEnumMemberComment(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      const std::string& comment) = 0;
  virtual StatusOr<ParseDeclarationsResponse> ParseDeclarations(
      const std::string& source_text) = 0;
};

}  // namespace libghidra::client
