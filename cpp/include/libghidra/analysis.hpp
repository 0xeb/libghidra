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

// Background auto-analysis. StartAnalysis returns immediately with a job; the job
// then owns the program exclusively, and every other program RPC fails fast with
// "analysis_running" until it finishes. Follow it with ListAnalysisJobs; stop it
// with CancelAnalysis. One job at a time.
class IAnalysisClient {
 public:
  virtual ~IAnalysisClient() = default;

  // mode: "changed" (default when empty) runs the analysis queued for edits made
  // since the program was opened; "all" re-runs every enabled analyzer.
  virtual StatusOr<StartAnalysisResponse> StartAnalysis(const std::string& mode) = 0;
  // Jobs of the current program, oldest first.
  virtual StatusOr<ListAnalysisJobsResponse> ListAnalysisJobs() = 0;
  // job_id 0 cancels the running job, whatever its id.
  virtual StatusOr<CancelAnalysisResponse> CancelAnalysis(std::uint64_t job_id) = 0;
};

}  // namespace libghidra::client
