package libghidra.host.runtime;

import java.util.concurrent.locks.Lock;

public final class LockScope implements AutoCloseable {

	private final Lock lock;

	public LockScope(Lock lock) {
		this.lock = lock;
		lock.lock();
	}

	@Override
	public void close() {
		lock.unlock();
	}
}
