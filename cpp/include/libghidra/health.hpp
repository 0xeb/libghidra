// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
