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

  virtual StatusOr<ListXrefsResponse> ListXrefsTo(std::uint64_t to_address,
                                                  int limit,
                                                  int offset) {
    return StatusOr<ListXrefsResponse>::FromError(
        error_codes::kNotSupported, "exact destination xrefs are not implemented by this backend");
  }

  // The references to an external symbol, named by its EXTERNAL-space offset
  // (SymbolRecord.address of an external symbol): the calls and jumps through
  // an import.
  virtual StatusOr<ListXrefsResponse> ListXrefsToExternal(std::uint64_t external_address,
                                                          int limit,
                                                          int offset) {
    return StatusOr<ListXrefsResponse>::FromError(
        error_codes::kNotSupported, "external destination xrefs are not implemented by this backend");
  }

  virtual StatusOr<ListXrefsResponse> ListXrefsFromFunction(
      std::uint64_t function_address,
      int limit,
      int offset) {
    return StatusOr<ListXrefsResponse>::FromError(
        error_codes::kNotSupported, "exact function xrefs are not implemented by this backend");
  }

  virtual StatusOr<ListXrefsResponse> ListXrefsToFunction(
      std::uint64_t function_address,
      int limit,
      int offset) {
    return StatusOr<ListXrefsResponse>::FromError(
        error_codes::kNotSupported, "exact destination-function xrefs are not implemented by this backend");
  }
};

}  // namespace libghidra::client
