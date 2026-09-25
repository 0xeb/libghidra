// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import libghidra.host.contract.AnalysisContract;

public interface AnalysisOperations {

	AnalysisContract.StartAnalysisResponse startAnalysis(AnalysisContract.StartAnalysisRequest request);

	AnalysisContract.ListAnalysisJobsResponse listAnalysisJobs(
		AnalysisContract.ListAnalysisJobsRequest request);

	AnalysisContract.CancelAnalysisResponse cancelAnalysis(
		AnalysisContract.CancelAnalysisRequest request);
}
