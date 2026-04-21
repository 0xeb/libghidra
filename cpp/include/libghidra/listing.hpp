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

class IListingClient {
 public:
  virtual ~IListingClient() = default;

  virtual StatusOr<GetInstructionResponse> GetInstruction(std::uint64_t address) = 0;
  virtual StatusOr<ListInstructionsResponse> ListInstructions(std::uint64_t range_start,
                                                              std::uint64_t range_end, int limit,
                                                              int offset) = 0;
  virtual StatusOr<GetCommentsResponse> GetComments(std::uint64_t range_start,
                                                    std::uint64_t range_end, int limit,
                                                    int offset) = 0;
  virtual StatusOr<SetCommentResponse> SetComment(std::uint64_t address, CommentKind kind,
                                                  const std::string& text) = 0;
  virtual StatusOr<DeleteCommentResponse> DeleteComment(std::uint64_t address,
                                                        CommentKind kind) = 0;
  virtual StatusOr<RenameDataItemResponse> RenameDataItem(std::uint64_t address,
                                                          const std::string& new_name) = 0;
  virtual StatusOr<DeleteDataItemResponse> DeleteDataItem(std::uint64_t address) = 0;
  virtual StatusOr<ListDataItemsResponse> ListDataItems(std::uint64_t range_start,
                                                        std::uint64_t range_end,
                                                        int limit,
                                                        int offset) = 0;
  virtual StatusOr<ListBookmarksResponse> ListBookmarks(std::uint64_t range_start,
                                                        std::uint64_t range_end,
                                                        int limit,
                                                        int offset,
                                                        const std::string& type_filter,
                                                        const std::string& category_filter) = 0;
  virtual StatusOr<AddBookmarkResponse> AddBookmark(std::uint64_t address,
                                                    const std::string& type,
                                                    const std::string& category,
                                                    const std::string& comment) = 0;
  virtual StatusOr<DeleteBookmarkResponse> DeleteBookmark(std::uint64_t address,
                                                          const std::string& type,
                                                          const std::string& category) = 0;
  virtual StatusOr<ListBreakpointsResponse> ListBreakpoints(std::uint64_t range_start,
                                                            std::uint64_t range_end,
                                                            int limit,
                                                            int offset,
                                                            const std::string& kind_filter,
                                                            const std::string& group_filter) = 0;
  virtual StatusOr<AddBreakpointResponse> AddBreakpoint(std::uint64_t address,
                                                        const std::string& kind,
                                                        std::uint64_t size,
                                                        bool enabled,
                                                        const std::string& condition,
                                                        const std::string& group) = 0;
  virtual StatusOr<SetBreakpointEnabledResponse> SetBreakpointEnabled(std::uint64_t address,
                                                                      bool enabled) = 0;
  virtual StatusOr<SetBreakpointKindResponse> SetBreakpointKind(std::uint64_t address,
                                                                const std::string& kind) = 0;
  virtual StatusOr<SetBreakpointSizeResponse> SetBreakpointSize(std::uint64_t address,
                                                                std::uint64_t size) = 0;
  virtual StatusOr<SetBreakpointConditionResponse> SetBreakpointCondition(
      std::uint64_t address,
      const std::string& condition) = 0;
  virtual StatusOr<SetBreakpointGroupResponse> SetBreakpointGroup(std::uint64_t address,
                                                                  const std::string& group) = 0;
  virtual StatusOr<DeleteBreakpointResponse> DeleteBreakpoint(std::uint64_t address) = 0;
  virtual StatusOr<ListDefinedStringsResponse> ListDefinedStrings(std::uint64_t range_start,
                                                                   std::uint64_t range_end,
                                                                   int limit,
                                                                   int offset) = 0;
};

}  // namespace libghidra::client
