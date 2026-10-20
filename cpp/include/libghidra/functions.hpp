// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstdint>
#include <optional>
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
  virtual StatusOr<ListFunctionsResponse> ListLeafFunctions(std::uint64_t range_start,
                                                            std::uint64_t range_end,
                                                            int limit,
                                                            int offset) = 0;
  // Define a function whose entry is `address`; an unset `name` takes the
  // backend's default (FUN_<address>). Errors: unmapped_address, duplicate_name
  // (a function already starts there), invalid_argument (not code / cannot start
  // a function), not_loaded.
  virtual StatusOr<CreateFunctionResponse> CreateFunction(
      std::uint64_t address, const std::optional<std::string>& name) = 0;
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
  virtual StatusOr<ListFunctionFramesResponse> ListFunctionFrames(
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
