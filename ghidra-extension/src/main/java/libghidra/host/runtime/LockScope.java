// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.concurrent.locks.Lock;

public final class LockScope implements AutoCloseable {

	private final Lock lock;

	public LockScope(Lock lock) {
		this.lock = lock;
		lock.lock();
	}

	private LockScope(Lock lock, boolean alreadyHeld) {
		this.lock = lock;
	}

	/** Wrap a lock the caller has already acquired; {@link #close()} releases it. */
	static LockScope adopt(Lock lock) {
		return new LockScope(lock, true);
	}

	@Override
	public void close() {
		lock.unlock();
	}
}
