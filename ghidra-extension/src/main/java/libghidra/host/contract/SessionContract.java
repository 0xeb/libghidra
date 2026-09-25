// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.contract;

public final class SessionContract {

	private SessionContract() {
	}

	public enum ShutdownPolicy {
		UNSPECIFIED,
		SAVE,
		DISCARD,
		NONE
	}

	public record OpenProgramRequest(
		String projectPath,
		String projectName,
		String programPath,
		boolean readOnly,
		String languageId,
		String compilerSpecId,
		String format,
		long baseAddress) {
	}

	public record OpenProgramResponse(
		String programName,
		String languageId,
		String compilerSpec,
		long imageBase,
		String md5,
		String sha256,
		String executableFormat,
		long entryPoint,
		boolean hasEntryPoint) {
	}

	public record OpenProjectRequest(
		String projectPath,
		String projectName,
		boolean create,
		boolean readOnly) {
	}

	public record OpenProjectResponse(
		String projectPath,
		String projectName,
		boolean created) {
	}

	public record CloseProjectRequest(ShutdownPolicy shutdownPolicy) {
	}

	public record CloseProjectResponse(boolean closed) {
	}

	public record ProjectFile(
		String path,
		String name,
		String folderPath,
		String contentType,
		String domainObjectClass,
		boolean isFolder,
		boolean isProgram) {
	}

	public record ListProjectFilesRequest(
		boolean includeFolders,
		boolean programsOnly) {
	}

	public record ListProjectFilesResponse(
		java.util.List<ProjectFile> files) {
	}

	public record LoaderArg(String name, String value) {
	}

	public record ImportProgramRequest(
		String sourcePath,
		String projectFolderPath,
		String programName,
		boolean overwrite,
		boolean analyze,
		String languageId,
		String compilerSpecId,
		String loaderClass,
		java.util.List<LoaderArg> loaderArgs,
		java.util.List<String> analyzersOff,
		java.util.List<String> analyzersOn) {
	}

	/** Which analyzer toggles one import pattern matched, across every loaded program. */
	public record AnalyzerPatternMatch(
		String pattern,
		boolean enabled,
		java.util.List<String> options) {
	}

	public record ImportProgramResponse(
		java.util.List<String> programPaths,
		String primaryProgramPath,
		java.util.List<AnalyzerPatternMatch> analyzerMatches) {
	}

	public record CloseProgramRequest(
		ShutdownPolicy shutdownPolicy) {
	}

	public record CloseProgramResponse(boolean closed) {
	}

	public record SaveProgramRequest() {
	}

	public record SaveProgramResponse(boolean saved) {
	}

	public record DiscardProgramRequest() {
	}

	public record DiscardProgramResponse(boolean discarded) {
	}

	public record GetRevisionRequest() {
	}

	public record GetRevisionResponse(
		long programId,
		long modificationNumber,
		String programPath,
		String fileId,
		int fileVersion,
		long fileLastModifiedTime) {
	}

	public record ShutdownRequest(ShutdownPolicy shutdownPolicy) {
	}

	public record ShutdownResponse(boolean accepted) {
	}

	/**
	 * A performance-benchmark record persisted in the program database. Mirrors
	 * the ten columns of the ghidrasql {@code perf_benchmarks} SQL table.
	 */
	public record PerfBenchmarkRecord(
		String benchId,
		String queryFamily,
		String datasetProfile,
		double coldMsP50,
		double coldMsP95,
		double warmMsP50,
		double warmMsP95,
		double throughputQps,
		double regressionPct,
		String status) {
	}

	public record AddPerfBenchmarkRequest(PerfBenchmarkRecord record) {
	}

	public record AddPerfBenchmarkResponse(boolean added) {
	}

	public record ListPerfBenchmarksRequest() {
	}

	public record ListPerfBenchmarksResponse(
		java.util.List<PerfBenchmarkRecord> records) {
	}

	public record ClearPerfBenchmarksRequest() {
	}

	public record ClearPerfBenchmarksResponse(boolean cleared, int removedCount) {
	}

	public record DeletePerfBenchmarkRequest(String benchId) {
	}

	public record DeletePerfBenchmarkResponse(boolean deleted) {
	}

	/**
	 * One entry of the current program's options. {@code type} is the Ghidra OptionType in
	 * lower case without its _TYPE suffix; ENUM values are constant names, listed in
	 * {@code allowedValues}.
	 */
	public record ProgramOptionRecord(
		String category,
		String name,
		String value,
		String type,
		String description,
		String defaultValue,
		boolean settable,
		java.util.List<String> allowedValues) {
	}

	public record ListProgramOptionsRequest(String category, String nameFilter) {
	}

	public record ListProgramOptionsResponse(java.util.List<ProgramOptionRecord> options) {
	}

	public record SetProgramOptionRequest(String category, String name, String value) {
	}

	public record SetProgramOptionResponse(boolean applied, String previousValue) {
	}

	/** kind is "undo", "redo" or "open"; see session.proto TransactionRecord. */
	public record TransactionRecord(
		int position,
		String name,
		String kind,
		java.util.List<String> openSubtransactions) {
	}

	public record ListTransactionsRequest() {
	}

	public record ListTransactionsResponse(java.util.List<TransactionRecord> transactions) {
	}
}
