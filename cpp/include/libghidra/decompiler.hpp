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

class IDecompilerClient {
 public:
  virtual ~IDecompilerClient() = default;

  virtual StatusOr<GetDecompilationResponse> GetDecompilation(std::uint64_t address,
                                                              int timeout_ms) = 0;
  virtual StatusOr<ListDecompilationsResponse> ListDecompilations(std::uint64_t range_start,
                                                                  std::uint64_t range_end,
                                                                  int limit,
                                                                  int offset,
                                                                  int timeout_ms) = 0;
  // P-code for one function at the requested maturity rung (High=refined SSA, Raw=per-instr).
  virtual StatusOr<GetPcodeResponse> GetPcode(std::uint64_t address,
                                              PcodeMaturity maturity, int timeout_ms) = 0;
};

}  // namespace libghidra::client
