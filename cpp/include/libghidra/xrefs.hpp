// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
