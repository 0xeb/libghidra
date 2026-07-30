// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <vector>

#include "libghidra/status.hpp"
#include "libghidra/models.hpp"

namespace libghidra::client {

class IHealthClient {
 public:
  virtual ~IHealthClient() = default;

  virtual StatusOr<HealthStatus> GetStatus() = 0;
  virtual StatusOr<std::vector<Capability>> GetCapabilities() = 0;
};

}  // namespace libghidra::client
