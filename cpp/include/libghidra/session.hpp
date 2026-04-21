// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include "libghidra/status.hpp"
#include "libghidra/models.hpp"

namespace libghidra::client {

struct OpenProgramRequest {
  std::string project_path;
  std::string project_name;
  std::string program_path;
  bool analyze = false;
  bool read_only = false;
};

class ISessionClient {
 public:
  virtual ~ISessionClient() = default;

  virtual StatusOr<OpenProgramResponse> OpenProgram(const OpenProgramRequest& request) = 0;
  virtual StatusOr<CloseProgramResponse> CloseProgram(ShutdownPolicy policy) = 0;
  virtual StatusOr<SaveProgramResponse> SaveProgram() = 0;
  virtual StatusOr<DiscardProgramResponse> DiscardProgram() = 0;
  virtual StatusOr<RevisionResponse> GetRevision() = 0;
  virtual StatusOr<ShutdownResponse> Shutdown(ShutdownPolicy policy) = 0;
};

}  // namespace libghidra::client
