package libghidra.host.runtime;

import java.io.File;
import java.util.Locale;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class ManagedProgramSupport {

	private ManagedProgramSupport() {
	}

	public static String normalizeProgramPath(String programPath) {
		if (programPath == null || programPath.isBlank()) {
			return "";
		}
		String normalized = programPath.trim().replace('\\', '/');
		if (!normalized.startsWith("/")) {
			normalized = "/" + normalized;
		}
		return normalized;
	}

	public static String inferProgramPath(Program program) {
		if (program == null || program.getDomainFile() == null) {
			return "";
		}
		return normalizeProgramPath(program.getDomainFile().getPathname());
	}

	public static String normalizeProjectPath(String projectPath) {
		if (projectPath == null || projectPath.isBlank()) {
			return "";
		}
		String normalized = projectPath.trim().replace('\\', '/');
		if (normalized.matches("^[A-Za-z]:($|/.*)")) {
			normalized = "/" + normalized;
		}
		while (normalized.endsWith("/")) {
			normalized = normalized.substring(0, normalized.length() - 1);
		}
		if (File.separatorChar == '\\') {
			return normalized.toLowerCase(Locale.ROOT);
		}
		return normalized;
	}

	public static Program openProjectProgram(
			ProjectData projectData,
			String programPath,
			Object consumer,
			TaskMonitor monitor,
			boolean readOnly) throws Exception {
		if (projectData == null) {
			throw new IllegalArgumentException("project data is not available");
		}
		String normalizedPath = normalizeProgramPath(programPath);
		if (normalizedPath.isBlank()) {
			throw new IllegalArgumentException("program_path is required");
		}
		DomainFile file = projectData.getFile(normalizedPath);
		if (file == null) {
			throw new IllegalArgumentException("program not found in project: " + normalizedPath);
		}
		return openDomainFile(file, consumer, monitor, readOnly);
	}

	public static Program openDomainFile(
			DomainFile file,
			Object consumer,
			TaskMonitor monitor,
			boolean readOnly) throws Exception {
		if (file == null) {
			throw new IllegalArgumentException("domain file is required");
		}
		if (readOnly) {
			return (Program) file.getReadOnlyDomainObject(
				consumer,
				DomainFile.DEFAULT_VERSION,
				monitor != null ? monitor : TaskMonitor.DUMMY);
		}
		return (Program) file.getDomainObject(
			consumer,
			false,
			false,
			monitor != null ? monitor : TaskMonitor.DUMMY);
	}
}
