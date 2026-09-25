// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import libghidra.host.contract.AnalysisContract;

/**
 * Background auto-analysis jobs.
 *
 * <p>A full analysis of a large program runs for minutes, far past any RPC read timeout, so
 * {@link #startAnalysis} returns at once and a worker thread does the work. The worker owns
 * the program exclusively (it holds the host write lock for the whole run, and every other
 * program RPC fails fast with {@code analysis_running}), so no reader ever sees a
 * half-analyzed program and no write, save or program switch races the analyzers. Jobs run
 * with a real cancellable monitor: {@link #cancelAnalysis}, shutdown and close stop them in
 * well under a second (measured: 40-120 ms after cancel on a full re-analysis). A cancelled
 * job keeps the work already done, as Ghidra's own cancel does.
 *
 * <p>Starting analysis is only supported without a PluginTool: with a tool,
 * AutoAnalysisManager hands the run to the tool's background task and returns immediately,
 * so completion is not observable here.
 */
public final class AnalysisRuntime extends RuntimeSupport implements AnalysisOperations {

	static final String STATE_RUNNING = "running";
	static final String STATE_DONE = "done";
	static final String STATE_ERROR = "error";
	static final String STATE_CANCELLED = "cancelled";
	static final String MODE_CHANGED = "changed";
	static final String MODE_ALL = "all";
	private static final int MAX_HISTORY = 64;

	private static final class Job {
		final long id;
		final String mode;
		final long programId;
		final long startedUnixMs = System.currentTimeMillis();
		final long startedNanos = System.nanoTime();
		volatile String state = STATE_RUNNING;
		volatile String message = "";
		volatile long endedUnixMs;
		volatile long elapsedMs = -1L;

		Job(long id, String mode, long programId) {
			this.id = id;
			this.mode = mode;
			this.programId = programId;
		}

		AnalysisContract.AnalysisJobRecord toRecord() {
			long elapsed = elapsedMs >= 0 ? elapsedMs : (System.nanoTime() - startedNanos) / 1_000_000L;
			return new AnalysisContract.AnalysisJobRecord(
				id, mode, state, startedUnixMs, endedUnixMs, elapsed, message);
		}
	}

	private final boolean startSupported;
	private final AtomicLong nextJobId = new AtomicLong();
	private final Deque<Job> history = new ArrayDeque<>();   // guarded by history

	AnalysisRuntime(HostState state, boolean startSupported) {
		super(state);
		this.startSupported = startSupported;
	}

	@Override
	public AnalysisContract.StartAnalysisResponse startAnalysis(
			AnalysisContract.StartAnalysisRequest request) {
		if (!startSupported) {
			throw new SessionRpcException(
				"NOT_SUPPORTED",
				"start_analysis() is not supported for an attached GUI host; use Analysis > Auto Analyze");
		}
		String mode = normalizeMode(request != null ? request.mode() : "");
		final Program program;
		try (LockScope ignored = readLock()) {
			program = requireProgram();
		}
		long id = nextJobId.incrementAndGet();
		Job job = new Job(id, mode, program.getUniqueProgramID());
		TaskMonitor monitor = new TaskMonitorAdapter(true);
		Thread worker = new Thread(() -> run(program, job, monitor), "libghidra-analysis-" + id);
		worker.setDaemon(true);
		if (!state.claimAnalysis(worker, id, monitor)) {
			throw new SessionRpcException(
				"analysis_running",
				"an analysis job is already running; poll ListAnalysisJobs or CancelAnalysis");
		}
		synchronized (history) {
			history.addLast(job);
			while (history.size() > MAX_HISTORY) {
				history.removeFirst();
			}
		}
		worker.start();
		return new AnalysisContract.StartAnalysisResponse(job.toRecord());
	}

	@Override
	public AnalysisContract.ListAnalysisJobsResponse listAnalysisJobs(
			AnalysisContract.ListAnalysisJobsRequest request) {
		// Lock-free on purpose: it is how a caller follows a job that owns the program.
		long programId = state.getProgramId();
		List<AnalysisContract.AnalysisJobRecord> out = new ArrayList<>();
		synchronized (history) {
			for (Job job : history) {
				if (job.programId == programId) {
					out.add(job.toRecord());
				}
			}
		}
		return new AnalysisContract.ListAnalysisJobsResponse(out);
	}

	@Override
	public AnalysisContract.CancelAnalysisResponse cancelAnalysis(
			AnalysisContract.CancelAnalysisRequest request) {
		long jobId = request != null ? request.jobId() : 0L;
		return new AnalysisContract.CancelAnalysisResponse(state.cancelAnalysis(jobId));
	}

	private void run(Program program, Job job, TaskMonitor monitor) {
		String outcome = STATE_ERROR;
		String message = "";
		try {
			try (LockScope ignored = state.analysisWriteLock()) {
				if (state.getCurrentProgram() != program) {
					message = "the program was closed or switched before analysis started";
				}
				else {
					int tx = program.startTransaction("libghidra analysis (" + job.mode + ")");
					boolean commit = false;
					try {
						ProgramOptionsSupport.analyze(program, MODE_ALL.equals(job.mode), monitor);
						commit = true;
						outcome = STATE_DONE;
					}
					catch (SessionRpcException e) {
						if (monitor.isCancelled()) {
							// Keep what the analyzers finished, like Ghidra's own cancel.
							commit = true;
							outcome = STATE_CANCELLED;
						}
						message = e.getMessage();
					}
					finally {
						program.endTransaction(tx, commit);
						flushProgramEvents(program);
					}
				}
			}
		}
		catch (Throwable t) {
			outcome = STATE_ERROR;
			message = t.getClass().getSimpleName() + ": " + nullableString(t.getMessage());
			Msg.error(this, "analysis job " + job.id + " failed", t);
		}
		finally {
			// Lift the gate before publishing the outcome, so a caller that sees "done" can
			// query the program immediately.
			state.releaseAnalysis(Thread.currentThread());
			job.elapsedMs = (System.nanoTime() - job.startedNanos) / 1_000_000L;
			job.endedUnixMs = System.currentTimeMillis();
			job.message = message != null ? message : "";
			job.state = outcome;
		}
	}

	private static String normalizeMode(String mode) {
		String value = mode != null ? mode.trim().toLowerCase(Locale.ROOT) : "";
		if (value.isEmpty() || MODE_CHANGED.equals(value)) {
			return MODE_CHANGED;
		}
		if (MODE_ALL.equals(value)) {
			return MODE_ALL;
		}
		throw new SessionRpcException(
			"invalid_argument", "analysis mode must be 'changed' or 'all', not '" + mode + "'");
	}
}
