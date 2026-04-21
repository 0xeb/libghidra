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

class IFunctionsClient {
 public:
  virtual ~IFunctionsClient() = default;

  virtual StatusOr<GetFunctionResponse> GetFunction(std::uint64_t address) = 0;
  virtual StatusOr<ListFunctionsResponse> ListFunctions(std::uint64_t range_start,
                                                        std::uint64_t range_end,
                                                        int limit,
                                                        int offset) = 0;
  virtual StatusOr<RenameFunctionResponse> RenameFunction(std::uint64_t address,
                                                          const std::string& new_name) = 0;
  virtual StatusOr<ListBasicBlocksResponse> ListBasicBlocks(std::uint64_t range_start,
                                                             std::uint64_t range_end,
                                                             int limit,
                                                             int offset) = 0;
  virtual StatusOr<ListCFGEdgesResponse> ListCFGEdges(std::uint64_t range_start,
                                                       std::uint64_t range_end,
                                                       int limit,
                                                       int offset) = 0;

  virtual StatusOr<ListSwitchTablesResponse> ListSwitchTables(
      std::uint64_t range_start, std::uint64_t range_end,
      int limit, int offset) = 0;
  virtual StatusOr<ListDominatorsResponse> ListDominators(
      std::uint64_t range_start, std::uint64_t range_end,
      int limit, int offset) = 0;
  virtual StatusOr<ListPostDominatorsResponse> ListPostDominators(
      std::uint64_t range_start, std::uint64_t range_end,
      int limit, int offset) = 0;
  virtual StatusOr<ListLoopsResponse> ListLoops(
      std::uint64_t range_start, std::uint64_t range_end,
      int limit, int offset) = 0;

  // Function tags — Ghidra-native categorization
  virtual StatusOr<ListFunctionTagsResponse> ListFunctionTags() = 0;
  virtual StatusOr<CreateFunctionTagResponse> CreateFunctionTag(
      const std::string& name, const std::string& comment) = 0;
  virtual StatusOr<DeleteFunctionTagResponse> DeleteFunctionTag(const std::string& name) = 0;
  virtual StatusOr<ListFunctionTagMappingsResponse> ListFunctionTagMappings(
      std::uint64_t function_entry) = 0;
  virtual StatusOr<TagFunctionResponse> TagFunction(std::uint64_t function_entry,
                                                     const std::string& tag_name) = 0;
  virtual StatusOr<UntagFunctionResponse> UntagFunction(std::uint64_t function_entry,
                                                         const std::string& tag_name) = 0;
};

}  // namespace libghidra::client
