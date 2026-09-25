// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.contract;

import java.util.List;

public final class AnalysisContract {

	private AnalysisContract() {
	}

	/** state is running | done | error | cancelled; times are Unix epoch milliseconds. */
	public record AnalysisJobRecord(
		long jobId,
		String mode,
		String state,
		long startedUnixMs,
		long endedUnixMs,
		long elapsedMs,
		String message) {
	}

	public record StartAnalysisRequest(String mode) {
	}

	public record StartAnalysisResponse(AnalysisJobRecord job) {
	}

	public record ListAnalysisJobsRequest() {
	}

	public record ListAnalysisJobsResponse(List<AnalysisJobRecord> jobs) {
	}

	public record CancelAnalysisRequest(long jobId) {
	}

	public record CancelAnalysisResponse(boolean cancelled) {
	}
}
