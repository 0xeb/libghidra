// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.function.BooleanSupplier;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Request-local cooperative cancellation propagated by the HTTP transport. */
public final class RequestCancellation {
	private static final ThreadLocal<BooleanSupplier> CURRENT = new ThreadLocal<>();

	private RequestCancellation() {
	}

	public static Scope begin(BooleanSupplier predicate) {
		BooleanSupplier previous = CURRENT.get();
		CURRENT.set(predicate != null ? predicate : () -> false);
		return new Scope(previous);
	}

	public static boolean isCancelled() {
		BooleanSupplier predicate = CURRENT.get();
		return predicate != null && predicate.getAsBoolean();
	}

	public static void throwIfCancelled() {
		if (isCancelled()) {
			throw new SessionRpcException("cancelled", "request cancelled");
		}
	}

	/**
	 * Create a request-scoped Ghidra monitor backed by the live cancellation
	 * predicate. Long Ghidra algorithms must receive this monitor rather than
	 * {@link TaskMonitor#DUMMY}; otherwise the HTTP control endpoint can advance
	 * its cancellation epoch while the algorithm remains blind to it.
	 */
	public static TaskMonitor taskMonitor() {
		return new TaskMonitorAdapter() {
			@Override
			public boolean isCancelled() {
				return RequestCancellation.isCancelled() || super.isCancelled();
			}

			// Only the two-l spelling is overridden. The handoff also overrode the
			// deprecated single-l checkCanceled(), which existed in Ghidra 12.1.2
			// where this was written; the Ghidra bump to 12.1.3 removed it from
			// TaskMonitor entirely, so that @Override no longer compiles.
			@Override
			public void checkCancelled() throws CancelledException {
				if (RequestCancellation.isCancelled()) {
					throw new CancelledException();
				}
				super.checkCancelled();
			}
		};
	}

	public static final class Scope implements AutoCloseable {
		private final BooleanSupplier previous;
		private boolean closed;

		private Scope(BooleanSupplier previous) {
			this.previous = previous;
		}

		@Override
		public void close() {
			if (closed) {
				return;
			}
			closed = true;
			if (previous == null) {
				CURRENT.remove();
			}
			else {
				CURRENT.set(previous);
			}
		}
	}
}
