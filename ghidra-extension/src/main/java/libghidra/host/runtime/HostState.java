package libghidra.host.runtime;

import java.util.concurrent.locks.ReentrantReadWriteLock;

import ghidra.program.model.listing.Program;

public final class HostState {

	private final ReentrantReadWriteLock stateLock = new ReentrantReadWriteLock(false);
	private volatile Program currentProgram;
	private volatile String currentProgramPath;
	private volatile String hostMode;
	private volatile long revision;

	public HostState(String initialHostMode) {
		hostMode = normalizeHostMode(initialHostMode);
		revision = 1L;
	}

	public LockScope readLock() {
		return new LockScope(stateLock.readLock());
	}

	public LockScope writeLock() {
		return new LockScope(stateLock.writeLock());
	}

	public void bindProgram(Program program, String mode) {
		bindProgram(program, mode, ManagedProgramSupport.inferProgramPath(program));
	}

	public void bindProgram(Program program, String mode, String programPath) {
		try (LockScope ignored = writeLock()) {
			currentProgram = program;
			currentProgramPath = ManagedProgramSupport.normalizeProgramPath(programPath);
			hostMode = normalizeHostMode(mode);
			revision++;
		}
	}

	public void unbindProgram(Program program) {
		try (LockScope ignored = writeLock()) {
			if (currentProgram == null || currentProgram != program) {
				return;
			}
			currentProgram = null;
			currentProgramPath = "";
			revision++;
		}
	}

	public Program getCurrentProgram() {
		return currentProgram;
	}

	public String getHostMode() {
		return hostMode;
	}

	public String getCurrentProgramPath() {
		return currentProgramPath != null ? currentProgramPath : "";
	}

	public long getRevision() {
		return revision;
	}

	public void bumpRevision() {
		revision++;
	}

	private static String normalizeHostMode(String mode) {
		if (mode == null || mode.isBlank()) {
			return "unknown";
		}
		return mode.trim().toLowerCase();
	}
}
