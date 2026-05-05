package libghidra.host.runtime;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;

public final class HostState {

	private final ReentrantReadWriteLock stateLock = new ReentrantReadWriteLock(false);
	private volatile Program currentProgram;
	private volatile String currentProgramPath;
	private volatile String hostMode;
	private volatile boolean closing;

	public HostState(String initialHostMode) {
		hostMode = normalizeHostMode(initialHostMode);
	}

	public LockScope readLock() {
		throwIfClosing();
		LockScope scope = new LockScope(stateLock.readLock());
		if (closing) {
			scope.close();
			throw hostClosingException();
		}
		return scope;
	}

	public LockScope writeLock() {
		throwIfClosing();
		LockScope scope = new LockScope(stateLock.writeLock());
		if (closing) {
			scope.close();
			throw hostClosingException();
		}
		return scope;
	}

	public void bindProgram(Program program, String mode) {
		bindProgram(program, mode, ManagedProgramSupport.inferProgramPath(program));
	}

	public void bindProgram(Program program, String mode, String programPath) {
		stateLock.writeLock().lock();
		try {
			currentProgram = program;
			currentProgramPath = ManagedProgramSupport.normalizeProgramPath(programPath);
			hostMode = normalizeHostMode(mode);
			closing = false;
		}
		finally {
			stateLock.writeLock().unlock();
		}
	}

	public void unbindProgram(Program program) {
		stateLock.writeLock().lock();
		try {
			unbindProgramLocked(program);
			closing = false;
		}
		finally {
			stateLock.writeLock().unlock();
		}
	}

	public boolean tryBeginUnbindProgram(Program program, long timeoutMillis) throws InterruptedException {
		closing = true;
		boolean acquired = stateLock.writeLock().tryLock(Math.max(0L, timeoutMillis), TimeUnit.MILLISECONDS);
		if (!acquired) {
			return false;
		}
		try {
			unbindProgramLocked(program);
			closing = false;
			return true;
		}
		finally {
			stateLock.writeLock().unlock();
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

	public long getProgramId() {
		Program program = currentProgram;
		return program != null ? program.getUniqueProgramID() : 0L;
	}

	public long getModificationNumber() {
		Program program = currentProgram;
		return program != null ? program.getModificationNumber() : 0L;
	}

	public String getFileId() {
		DomainFile file = currentDomainFile();
		if (file == null) {
			return "";
		}
		String id = file.getFileID();
		return id != null ? id : "";
	}

	public int getFileVersion() {
		DomainFile file = currentDomainFile();
		return file != null ? file.getVersion() : 0;
	}

	public long getFileLastModifiedTime() {
		DomainFile file = currentDomainFile();
		return file != null ? file.getLastModifiedTime() : 0L;
	}

	public boolean isClosing() {
		return closing;
	}

	private void unbindProgramLocked(Program program) {
		if (currentProgram == null || currentProgram != program) {
			return;
		}
		currentProgram = null;
		currentProgramPath = "";
	}

	private DomainFile currentDomainFile() {
		Program program = currentProgram;
		if (program != null) {
			return program.getDomainFile();
		}
		return null;
	}

	private void throwIfClosing() {
		if (closing) {
			throw hostClosingException();
		}
	}

	private static SessionRpcException hostClosingException() {
		return new SessionRpcException(
			"host_closing",
			"libghidra host is closing or switching programs; retry after the UI settles");
	}

	private static String normalizeHostMode(String mode) {
		if (mode == null || mode.isBlank()) {
			return "unknown";
		}
		return mode.trim().toLowerCase();
	}
}
