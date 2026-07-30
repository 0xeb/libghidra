// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstdint>

#include "libghidra/status.hpp"
#include "libghidra/models.hpp"

namespace libghidra::client {

class IXrefsClient {
 public:
  virtual ~IXrefsClient() = default;

  virtual StatusOr<ListXrefsResponse> ListXrefs(std::uint64_t range_start,
                                                std::uint64_t range_end,
                                                int limit,
                                                int offset) = 0;
};

}  // namespace libghidra::client
