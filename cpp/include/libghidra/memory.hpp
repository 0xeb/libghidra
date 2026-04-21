// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <cstdint>
#include <vector>

#include "libghidra/status.hpp"
#include "libghidra/models.hpp"

namespace libghidra::client {

struct BytePatch {
  std::uint64_t address = 0;
  std::vector<std::uint8_t> data;
};

class IMemoryClient {
 public:
  virtual ~IMemoryClient() = default;

  virtual StatusOr<ReadBytesResponse> ReadBytes(std::uint64_t address, std::uint32_t length) = 0;
  virtual StatusOr<WriteBytesResponse> WriteBytes(std::uint64_t address,
                                                  const std::vector<std::uint8_t>& data) = 0;
  virtual StatusOr<PatchBytesBatchResponse> PatchBytesBatch(
      const std::vector<BytePatch>& patches) = 0;
  virtual StatusOr<ListMemoryBlocksResponse> ListMemoryBlocks(int limit, int offset) = 0;
};

}  // namespace libghidra::client
