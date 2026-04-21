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

class ISymbolsClient {
 public:
  virtual ~ISymbolsClient() = default;

  virtual StatusOr<GetSymbolResponse> GetSymbol(std::uint64_t address) = 0;
  virtual StatusOr<ListSymbolsResponse> ListSymbols(std::uint64_t range_start,
                                                    std::uint64_t range_end,
                                                    int limit,
                                                    int offset) = 0;
  virtual StatusOr<RenameSymbolResponse> RenameSymbol(std::uint64_t address,
                                                      const std::string& new_name) = 0;
  virtual StatusOr<DeleteSymbolResponse> DeleteSymbol(std::uint64_t address,
                                                      const std::string& name_filter) = 0;
};

}  // namespace libghidra::client
