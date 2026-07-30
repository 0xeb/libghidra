// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import libghidra.host.contract.SessionContract;

public interface SessionOperations {

	SessionContract.OpenProjectResponse openProject(SessionContract.OpenProjectRequest request);

	SessionContract.CloseProjectResponse closeProject(SessionContract.CloseProjectRequest request);

	SessionContract.ListProjectFilesResponse listProjectFiles(
		SessionContract.ListProjectFilesRequest request);

	SessionContract.ImportProgramResponse importProgram(SessionContract.ImportProgramRequest request);

	SessionContract.OpenProgramResponse openProgram(SessionContract.OpenProgramRequest request);

	SessionContract.CloseProgramResponse closeProgram(SessionContract.CloseProgramRequest request);

	SessionContract.SaveProgramResponse saveProgram(SessionContract.SaveProgramRequest request);

	SessionContract.DiscardProgramResponse discardProgram(SessionContract.DiscardProgramRequest request);

	SessionContract.GetRevisionResponse getRevision(SessionContract.GetRevisionRequest request);

	SessionContract.ShutdownResponse shutdown(SessionContract.ShutdownRequest request);

	SessionContract.AddPerfBenchmarkResponse addPerfBenchmark(
		SessionContract.AddPerfBenchmarkRequest request);

	SessionContract.ListPerfBenchmarksResponse listPerfBenchmarks(
		SessionContract.ListPerfBenchmarksRequest request);

	SessionContract.ClearPerfBenchmarksResponse clearPerfBenchmarks(
		SessionContract.ClearPerfBenchmarksRequest request);

	SessionContract.DeletePerfBenchmarkResponse deletePerfBenchmark(
		SessionContract.DeletePerfBenchmarkRequest request);
}
