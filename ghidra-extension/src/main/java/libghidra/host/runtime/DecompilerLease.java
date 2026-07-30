// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.concurrent.locks.ReentrantLock;

import ghidra.app.decompiler.DecompInterface;

/**
 * RAII lease over {@link HostState}'s single persistent {@link DecompInterface}.
 *
 * <p>Ghidra documents {@code DecompInterface} as a persistent object — instantiate once,
 * {@code openProgram} once, then {@code decompileFunction} many times — so libghidra holds
 * ONE per open program on {@link HostState} instead of building/disposing one per RPC. That
 * single instance is NOT thread-safe, and decompiler-backed reads run under the host READ
 * lock (multiple concurrent readers), so access is serialized by a dedicated lock: a lease
 * holds that lock for the duration of a decompile and releases it on {@link #close()}.
 *
 * <p>Use with try-with-resources:
 * <pre>
 *   try (DecompilerLease lease = state.leaseDecompiler(program)) {
 *       DecompInterface ifc = lease.get();
 *       if (ifc == null) { ... report error ... }
 *       DecompileResults r = ifc.decompileFunction(func, timeout, monitor);
 *   }
 * </pre>
 * Do NOT dispose the returned interface — {@link HostState} owns it and disposes it on
 * program-switch.
 */
public final class DecompilerLease implements AutoCloseable {

	private final ReentrantLock lock;
	private final DecompInterface decompiler;
	private boolean closed;

	DecompilerLease(ReentrantLock lock, DecompInterface decompiler) {
		this.lock = lock;
		this.decompiler = decompiler;
	}

	/** The leased persistent decompiler, or {@code null} if none could be opened. */
	public DecompInterface get() {
		return decompiler;
	}

	@Override
	public void close() {
		if (!closed) {
			closed = true;
			lock.unlock();
		}
	}
}
