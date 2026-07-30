// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
