// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.service;

import libghidra.host.contract.AnalysisContract;
import libghidra.host.runtime.AnalysisOperations;

public final class AnalysisServiceHandler {

	private final AnalysisOperations runtime;

	public AnalysisServiceHandler(AnalysisOperations runtime) {
		this.runtime = runtime;
	}

	public AnalysisContract.StartAnalysisResponse startAnalysis(
			AnalysisContract.StartAnalysisRequest request) {
		if (request == null) {
			request = new AnalysisContract.StartAnalysisRequest("");
		}
		return runtime.startAnalysis(request);
	}

	public AnalysisContract.ListAnalysisJobsResponse listAnalysisJobs(
			AnalysisContract.ListAnalysisJobsRequest request) {
		if (request == null) {
			request = new AnalysisContract.ListAnalysisJobsRequest();
		}
		return runtime.listAnalysisJobs(request);
	}

	public AnalysisContract.CancelAnalysisResponse cancelAnalysis(
			AnalysisContract.CancelAnalysisRequest request) {
		if (request == null) {
			request = new AnalysisContract.CancelAnalysisRequest(0L);
		}
		return runtime.cancelAnalysis(request);
	}
}
