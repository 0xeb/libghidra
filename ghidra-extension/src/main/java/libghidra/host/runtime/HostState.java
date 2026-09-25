// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class HostState {

	private final ReentrantReadWriteLock stateLock = new ReentrantReadWriteLock(false);
	private volatile Program currentProgram;
	private volatile String currentProgramPath;
	private volatile String hostMode;
	private volatile boolean closing;

	// Ghidra's DecompInterface is documented persistent (new -> setOptions -> openProgram
	// once -> decompileFunction many -> dispose once). Hold ONE per open program instead
	// of building/disposing one per RPC. Guarded by its OWN lock, not the RW lock:
	// decompiler-backed reads run under the READ lock (multiple concurrent readers), and a
	// single DecompInterface is not thread-safe, so access must be serialized here. Owned
	// by HostState and disposed on program-switch.
	private final ReentrantLock decompilerLock = new ReentrantLock();
	private DecompInterface warmDecompiler;    // guarded by decompilerLock
	private Program warmDecompilerProgram;     // guarded by decompilerLock

	// An analysis job owns the program exclusively: its worker thread holds the write lock
	// for the whole run, and every OTHER thread's readLock()/writeLock() fails fast with
	// analysis_running instead of queueing behind it for minutes. Lock-free RPCs (health,
	// GetRevision, ListAnalysisJobs, CancelAnalysis) stay available throughout.
	private static final long LOCK_POLL_MILLIS = 25L;
	private static final long ANALYSIS_STOP_TIMEOUT_MILLIS = 30_000L;
	private final AtomicReference<Thread> analysisThread = new AtomicReference<>();
	private volatile long analysisJobId;
	private volatile TaskMonitor analysisMonitor;

	public HostState(String initialHostMode) {
		hostMode = normalizeHostMode(initialHostMode);
	}

	public LockScope readLock() {
		return acquireGated(stateLock.readLock());
	}

	public LockScope writeLock() {
		return acquireGated(stateLock.writeLock());
	}

	// Poll rather than block so a caller already waiting when a job claims the program (or
	// when the host starts closing) is released with a clean error instead of stalling.
	private LockScope acquireGated(Lock lock) {
		throwIfClosing();
		throwIfAnalysisBlocks();
		try {
			while (!lock.tryLock(LOCK_POLL_MILLIS, TimeUnit.MILLISECONDS)) {
				throwIfClosing();
				throwIfAnalysisBlocks();
			}
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new SessionRpcException("cancelled", "interrupted while waiting for the host lock");
		}
		LockScope scope = LockScope.adopt(lock);
		if (closing) {
			scope.close();
			throw hostClosingException();
		}
		if (analysisBlocksCurrentThread()) {
			scope.close();
			throw analysisRunningException();
		}
		return scope;
	}

	/**
	 * Claim the program for an analysis job run by {@code worker}. Returns false when another
	 * job already owns it. The worker must then take {@link #analysisWriteLock()} and call
	 * {@link #releaseAnalysis(Thread)} when done.
	 */
	boolean claimAnalysis(Thread worker, long jobId, TaskMonitor monitor) {
		if (!analysisThread.compareAndSet(null, worker)) {
			return false;
		}
		analysisJobId = jobId;
		analysisMonitor = monitor;
		return true;
	}

	/** The job worker's exclusive lock. Waits for in-flight readers; new callers fail fast. */
	LockScope analysisWriteLock() {
		return new LockScope(stateLock.writeLock());
	}

	void releaseAnalysis(Thread worker) {
		if (analysisThread.compareAndSet(worker, null)) {
			analysisMonitor = null;
			analysisJobId = 0L;
		}
	}

	public boolean isAnalysisRunning() {
		return analysisThread.get() != null;
	}

	/** Cancel the running job ({@code jobId} 0 matches any); true if one was signalled. */
	boolean cancelAnalysis(long jobId) {
		TaskMonitor monitor = analysisMonitor;
		if (analysisThread.get() == null || monitor == null) {
			return false;
		}
		if (jobId != 0L && jobId != analysisJobId) {
			return false;
		}
		monitor.cancel();
		return true;
	}

	/**
	 * Cancel any running job and wait for its worker to release the program. Called before
	 * shutdown, close and program switches so they never race (or wait minutes behind) a job.
	 */
	public void cancelAnalysisAndWait() {
		Thread worker = analysisThread.get();
		if (worker == null || worker == Thread.currentThread()) {
			return;
		}
		cancelAnalysis(0L);
		try {
			worker.join(ANALYSIS_STOP_TIMEOUT_MILLIS);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	public void bindProgram(Program program, String mode) {
		bindProgram(program, mode, ManagedProgramSupport.inferProgramPath(program));
	}

	public void bindProgram(Program program, String mode, String programPath) {
		cancelAnalysisAndWait();
		stateLock.writeLock().lock();
		try {
			disposeWarmDecompiler();
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
		cancelAnalysisAndWait();
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
		cancelAnalysisAndWait();
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

	/**
	 * Lease the single persistent decompiler for {@code program}, opening it lazily and
	 * re-opening it if the program changed. The returned lease holds the decompiler lock
	 * until closed (use try-with-resources); {@link DecompilerLease#get()} is null if none
	 * could be opened. The caller must NOT dispose the interface — HostState owns it.
	 */
	public DecompilerLease leaseDecompiler(Program program) {
		decompilerLock.lock();
		try {
			if (warmDecompiler == null || warmDecompilerProgram != program) {
				disposeWarmDecompilerLocked();
				if (program != null) {
					warmDecompiler = DecompilerSupport.createDecompiler(program);
					warmDecompilerProgram = warmDecompiler != null ? program : null;
				}
			}
			return new DecompilerLease(decompilerLock, warmDecompiler);
		}
		catch (RuntimeException e) {
			decompilerLock.unlock();
			throw e;
		}
	}

	// Caller must hold decompilerLock.
	private void disposeWarmDecompilerLocked() {
		if (warmDecompiler != null) {
			warmDecompiler.dispose();
			warmDecompiler = null;
			warmDecompilerProgram = null;
		}
	}

	private void disposeWarmDecompiler() {
		decompilerLock.lock();
		try {
			disposeWarmDecompilerLocked();
		}
		finally {
			decompilerLock.unlock();
		}
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
		disposeWarmDecompiler();
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

	private boolean analysisBlocksCurrentThread() {
		Thread worker = analysisThread.get();
		return worker != null && worker != Thread.currentThread();
	}

	private void throwIfAnalysisBlocks() {
		if (analysisBlocksCurrentThread()) {
			throw analysisRunningException();
		}
	}

	private SessionRpcException analysisRunningException() {
		return new SessionRpcException(
			"analysis_running",
			"analysis job " + analysisJobId +
				" owns the program; poll ListAnalysisJobs until it finishes, or CancelAnalysis");
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
