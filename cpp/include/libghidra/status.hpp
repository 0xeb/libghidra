// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <optional>
#include <string>

namespace libghidra::client {

struct Status {
  std::string code;
  std::string message;

  [[nodiscard]] bool ok() const { return code.empty(); }

  static Status Ok() { return {}; }
  static Status Error(std::string code_value, std::string message_value) {
    return Status{std::move(code_value), std::move(message_value)};
  }
};

template <typename T>
struct StatusOr {
  Status status;
  std::optional<T> value;

  [[nodiscard]] bool ok() const { return status.ok() && value.has_value(); }

  static StatusOr<T> FromValue(T v) { return StatusOr<T>{Status::Ok(), std::move(v)}; }

  static StatusOr<T> FromError(std::string code, std::string message) {
    return StatusOr<T>{Status::Error(std::move(code), std::move(message)), std::nullopt};
  }
};

}  // namespace libghidra::client
