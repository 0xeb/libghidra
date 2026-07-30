// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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

// Spec for creating a new memory block (the writable memory map).
struct CreateMemoryBlockSpec {
  std::string name;
  std::uint64_t start_address = 0;
  std::uint64_t size = 0;
  bool is_read = true;
  bool is_write = true;
  bool is_execute = false;
  bool initialized = false;  // false => uninitialized block (e.g. SRAM)
  bool overlay = false;
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
  virtual StatusOr<CreateMemoryBlockResponse> CreateMemoryBlock(
      const CreateMemoryBlockSpec& spec) = 0;
  virtual StatusOr<RemoveMemoryBlockResponse> RemoveMemoryBlock(std::uint64_t address) = 0;
  virtual StatusOr<MoveMemoryBlockResponse> MoveMemoryBlock(std::uint64_t address,
                                                            std::uint64_t new_start_address) = 0;
};

}  // namespace libghidra::client
