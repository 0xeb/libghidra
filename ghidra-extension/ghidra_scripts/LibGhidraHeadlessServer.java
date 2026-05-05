// Starts live libghidra HTTP host in analyzeHeadless postScript context.
//
// Usage examples:
//   -postScript LibGhidraHeadlessServer.java bind=127.0.0.1 port=18080 shutdown=save
//   -postScript LibGhidraHeadlessServer.java --bind 127.0.0.1 --port 18080 --auth token --shutdown discard --max_runtime_ms 600000
//   -postScript LibGhidraHeadlessServer.java --bind 127.0.0.1 --port 18080 --bind_attempts 10 --bind_retry_initial_ms 100 --bind_retry_max_ms 1000
//   -postScript LibGhidraHeadlessServer.java --initial_program /loader.elf --program_paths /loader.elf;/payload.elf
//
// @category libghidra

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
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
		if (ambientProgram == null) {
			throw new IllegalStateException("LibGhidraHeadlessServer requires currentProgram");
		}
		// Ghidra executes scripts inside a long-lived FlatProgramAPI transaction.
		// If we keep that ambient transaction open for the whole RPC server lifetime,
		// nested RPC mutations cannot be saved or undone until the script exits.
		end(true);

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
		List<String> importedPrograms = importStartupBinaries(
			project,
			combinedList(args, "binary_paths", "binary_path", "LIBGHIDRA_BINARY_PATHS"));
		List<String> declaredPrograms =
			combinedList(args, "program_paths", "program_path", "LIBGHIDRA_PROGRAM_PATHS");
		declaredPrograms.addAll(importedPrograms);
		for (String declaredProgram : declaredPrograms) {
			String normalized = ManagedProgramSupport.normalizeProgramPath(declaredProgram);
			if (!normalized.isBlank() && projectData.getFile(normalized) == null) {
				throw new IllegalArgumentException("program not found in project: " + normalized);
			}
		}
		String initialProgram = HeadlessScriptArgs.valueOrDefault(
			args.get("initial_program"),
			System.getenv("LIBGHIDRA_INITIAL_PROGRAM"));
		String programPath = HeadlessScriptArgs.valueOrDefault(
			initialProgram,
			HeadlessScriptArgs.valueOrDefault(
				args.get("program_path"),
				!declaredPrograms.isEmpty()
						? declaredPrograms.get(0)
						: ManagedProgramSupport.inferProgramPath(ambientProgram)));
		String normalizedProgramPath = ManagedProgramSupport.normalizeProgramPath(programPath);
		DomainFile programFile = projectData.getFile(normalizedProgramPath);
		if (programFile == null &&
			ambientProgram.getDomainFile() != null &&
			ManagedProgramSupport.inferProgramPath(ambientProgram).equals(
				normalizedProgramPath)) {
			programFile = ambientProgram.getDomainFile();
		}
		Program program = ManagedProgramSupport.openDomainFile(
			programFile,
			this,
			monitor,
			false);

		LibGhidraHeadlessHost.ShutdownPolicy policy =
			LibGhidraHeadlessHost.parseShutdownPolicy(shutdown);

		LibGhidraHeadlessHost host =
			new LibGhidraHeadlessHost(
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
				policy);
		try {
			int boundPort = host.startServerWithRetry(
				bindAttempts,
				bindRetryInitialMs,
				bindRetryMaxMs);
			println("LIBGHIDRA_HEADLESS_READY bind=" + bind
				+ " port=" + boundPort
				+ " program=" + program.getName()
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

	private List<String> importStartupBinaries(Project project, List<String> binaryPaths) throws Exception {
		List<String> imported = new ArrayList<>();
		for (String binaryPath : binaryPaths) {
			File source = new File(binaryPath);
			if (!source.isFile()) {
				throw new IllegalArgumentException("startup binary not found: " + binaryPath);
			}
			try (LoadResults<Program> results = ProgramLoader.builder()
					.source(source)
					.project(project)
					.monitor(monitor)
					.load()) {
				for (Loaded<Program> loaded : results) {
					Program loadedProgram = loaded.getDomainObject(this);
					try {
						DomainFile saved = loaded.save(monitor);
						imported.add(ManagedProgramSupport.normalizeProgramPath(saved.getPathname()));
					}
					finally {
						loadedProgram.release(this);
					}
				}
			}
		}
		return imported;
	}
}
