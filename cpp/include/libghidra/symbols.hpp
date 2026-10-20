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

class ISymbolsClient {
 public:
  virtual ~ISymbolsClient() = default;

  virtual StatusOr<GetSymbolResponse> GetSymbol(std::uint64_t address) = 0;
  virtual StatusOr<ListSymbolsResponse> ListSymbols(std::uint64_t range_start,
                                                    std::uint64_t range_end,
                                                    int limit,
                                                    int offset) = 0;
  // Add the label `name` at `address`; it never renames. An address that has
  // symbols keeps them (the label is primary only when it had none). Errors:
  // unmapped_address, duplicate_name (that name is already at the address),
  // invalid_argument (blank or invalid name), not_loaded.
  virtual StatusOr<CreateLabelResponse> CreateLabel(std::uint64_t address,
                                                    const std::string& name) = 0;
  // Rename a symbol at `address`. Set `old_name`: exactly the symbol of that
  // name (not_found if the address has none). Unset: the primary symbol.
  virtual StatusOr<RenameSymbolResponse> RenameSymbol(
      std::uint64_t address, const std::string& new_name,
      const std::optional<std::string>& old_name = std::nullopt) = 0;
  virtual StatusOr<DeleteSymbolResponse> DeleteSymbol(std::uint64_t address,
                                                      const std::string& name_filter) = 0;
};

}  // namespace libghidra::client
