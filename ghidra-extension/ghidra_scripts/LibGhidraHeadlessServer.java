/* ###
 * Copyright (c) 2024-2026 Elias Bachaalany
 * SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
 *
 * This file is licensed under the Human-Origin Source License v1.0.
 * See LICENSE.
 */
// Starts live libghidra HTTP host in analyzeHeadless postScript context.
//
// Usage examples:
//   -postScript LibGhidraHeadlessServer.java bind=127.0.0.1 port=18080 shutdown=save
//   -postScript LibGhidraHeadlessServer.java --bind 127.0.0.1 --port 18080 --auth token --shutdown discard --max_runtime_ms 600000
//   -postScript LibGhidraHeadlessServer.java --bind 127.0.0.1 --port 18080 --bind_attempts 10 --bind_retry_initial_ms 100 --bind_retry_max_ms 1000
//   -postScript LibGhidraHeadlessServer.java --program_path /loader.elf
//
// @category libghidra

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import libghidra.host.LibGhidraHeadlessHost;
import libghidra.host.HeadlessScriptArgs;
import libghidra.host.runtime.ManagedProgramSupport;

public class LibGhidraHeadlessServer extends GhidraScript {

	@Override
	public void run() throws Exception {
		Program ambientProgram = currentProgram;
		// Ghidra executes scripts inside a long-lived FlatProgramAPI transaction.
		// If we keep that ambient transaction open for the whole RPC server lifetime,
		// nested RPC mutations cannot be saved or undone until the script exits.
		if (ambientProgram != null) {
			end(true);
		}

		Map<String, String> args = HeadlessScriptArgs.parse(getScriptArgs());
		String bind = HeadlessScriptArgs.valueOrDefault(args.get("bind"), "127.0.0.1");
		int port = HeadlessScriptArgs.parseInt(args.get("port"), 18080);
		String auth = HeadlessScriptArgs.valueOrDefault(args.get("auth"), "");
		String shutdown = HeadlessScriptArgs.valueOrDefault(args.get("shutdown"), "save");
		long pollMillis = HeadlessScriptArgs.parseLong(args.get("poll_ms"), 200L);
		long maxRuntimeMs = HeadlessScriptArgs.parseLong(args.get("max_runtime_ms"), 0L);
		int bindAttempts = Math.max(1, HeadlessScriptArgs.parseInt(args.get("bind_attempts"), 1));
		long bindRetryInitialMs =
			Math.max(1L, HeadlessScriptArgs.parseLong(args.get("bind_retry_initial_ms"), 100L));
		long bindRetryMaxMs = Math.max(
			bindRetryInitialMs,
			HeadlessScriptArgs.parseLong(args.get("bind_retry_max_ms"), 1000L));
		long startedAt = System.currentTimeMillis();
		Project project = state != null ? state.getProject() : null;
		ProjectData projectData = project != null ? project.getProjectData() : null;
		if (projectData == null) {
			throw new IllegalStateException("LibGhidraHeadlessServer requires project data");
		}
		String projectPath = projectData.getProjectLocator() != null
				? projectData.getProjectLocator().getLocation()
				: "";
		String projectName = projectData.getProjectLocator() != null
				? projectData.getProjectLocator().getName()
				: "";
		List<String> declaredPrograms =
			combinedList(args, "program_paths", "program_path", "LIBGHIDRA_PROGRAM_PATHS");
		for (String declaredProgram : declaredPrograms) {
			String normalized = ManagedProgramSupport.normalizeProgramPath(declaredProgram);
			if (!normalized.isBlank() && projectData.getFile(normalized) == null) {
				throw new IllegalArgumentException("program not found in project: " + normalized);
			}
		}
		String programPath = HeadlessScriptArgs.valueOrDefault(
			args.get("program_path"),
			!declaredPrograms.isEmpty()
					? declaredPrograms.get(0)
					: ManagedProgramSupport.inferProgramPath(ambientProgram));
		String normalizedProgramPath = ManagedProgramSupport.normalizeProgramPath(programPath);
		Program program = null;
		if (!normalizedProgramPath.isBlank()) {
			DomainFile programFile = projectData.getFile(normalizedProgramPath);
			if (programFile == null &&
				ambientProgram != null &&
				ambientProgram.getDomainFile() != null &&
				ManagedProgramSupport.inferProgramPath(ambientProgram).equals(
					normalizedProgramPath)) {
				programFile = ambientProgram.getDomainFile();
			}
			program = ManagedProgramSupport.openDomainFile(
				programFile,
				this,
				monitor,
				false);
		}

		LibGhidraHeadlessHost.ShutdownPolicy policy =
			LibGhidraHeadlessHost.parseShutdownPolicy(shutdown);

		LibGhidraHeadlessHost host = program != null
			? new LibGhidraHeadlessHost(
				project,
				this,
				monitor,
				projectPath,
				projectName,
				program,
				normalizedProgramPath,
				bind,
				port,
				auth,
				policy)
			: new LibGhidraHeadlessHost(
				project,
				this,
				monitor,
				projectPath,
				projectName,
				bind,
				port,
				auth,
				policy);
		try {
			int boundPort = host.startServerWithRetry(
				bindAttempts,
				bindRetryInitialMs,
				bindRetryMaxMs);
			println("LIBGHIDRA_HEADLESS_READY bind=" + bind
				+ " port=" + boundPort
				+ " program=" + (program != null ? program.getName() : "<none>")
				+ " max_runtime_ms=" + maxRuntimeMs
				+ " bind_attempts=" + bindAttempts
				+ " shutdown=" + policy.name().toLowerCase());
			while (host.isRunning()) {
				if (monitor != null && monitor.isCancelled()) {
					println("LIBGHIDRA_HEADLESS_CANCELLED");
					host.stopServer();
					break;
				}
				if (maxRuntimeMs > 0 && (System.currentTimeMillis() - startedAt) >= maxRuntimeMs) {
					println("LIBGHIDRA_HEADLESS_MAX_RUNTIME_REACHED");
					host.stopServer();
					break;
				}
				Thread.sleep(Math.max(20L, pollMillis));
			}
		}
		finally {
			host.close();
			println("LIBGHIDRA_HEADLESS_LIFECYCLE shutdown_policy=" + host.getShutdownPolicyName());
			println("LIBGHIDRA_HEADLESS_EXIT");
		}
	}

	private List<String> combinedList(
			Map<String, String> args,
			String pluralKey,
			String singularKey,
			String envKey) {
		List<String> out = new ArrayList<>();
		out.addAll(HeadlessScriptArgs.listValue(args, pluralKey, envKey));
		out.addAll(HeadlessScriptArgs.listValue(args, singularKey, null));
		return out;
	}
}
