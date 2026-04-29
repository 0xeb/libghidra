package libghidra.host.service;

import libghidra.host.contract.SessionContract;
import libghidra.host.runtime.SessionOperations;

public final class SessionServiceHandler {

	private final SessionOperations runtime;

	public SessionServiceHandler(SessionOperations runtime) {
		this.runtime = runtime;
	}

	public SessionContract.OpenProgramResponse openProgram(
			SessionContract.OpenProgramRequest request) {
		if (request == null) {
			request = new SessionContract.OpenProgramRequest(
				"", "", "", false, false, "", "", "", 0L);
		}
		return runtime.openProgram(request);
	}

	public SessionContract.CloseProgramResponse closeProgram(
			SessionContract.CloseProgramRequest request) {
		if (request == null) {
			request = new SessionContract.CloseProgramRequest(
				SessionContract.ShutdownPolicy.UNSPECIFIED);
		}
		return runtime.closeProgram(request);
	}

	public SessionContract.SaveProgramResponse saveProgram(
			SessionContract.SaveProgramRequest request) {
		if (request == null) {
			request = new SessionContract.SaveProgramRequest();
		}
		return runtime.saveProgram(request);
	}

	public SessionContract.DiscardProgramResponse discardProgram(
			SessionContract.DiscardProgramRequest request) {
		if (request == null) {
			request = new SessionContract.DiscardProgramRequest();
		}
		return runtime.discardProgram(request);
	}

	public SessionContract.GetRevisionResponse getRevision(
			SessionContract.GetRevisionRequest request) {
		if (request == null) {
			request = new SessionContract.GetRevisionRequest();
		}
		return runtime.getRevision(request);
	}

	public SessionContract.ShutdownResponse shutdown(SessionContract.ShutdownRequest request) {
		if (request == null) {
			request = new SessionContract.ShutdownRequest(SessionContract.ShutdownPolicy.UNSPECIFIED);
		}
		// Test-only wedge hook: when LIBGHIDRA_DEBUG_WEDGE_MS is set, sleep
		// before delegating to the real shutdown path. This lets the
		// close-timeout regression test under tests/ghidrasql/private/
		// drive a deterministic Java-side wedge without depending on
		// Ghidra parser quirks. Inert when the env var is unset (no cost
		// on the production path beyond a single getenv() check).
		applyDebugWedge();
		return runtime.shutdown(request);
	}

	/**
	 * Honours the {@code LIBGHIDRA_DEBUG_WEDGE_MS} env var by sleeping for
	 * the specified number of milliseconds before returning. Used only by
	 * regression tests that need to drive a deterministic shutdown wedge.
	 *
	 * Package-visible so tests can call it directly if needed.
	 */
	static void applyDebugWedge() {
		final String raw = System.getenv("LIBGHIDRA_DEBUG_WEDGE_MS");
		if (raw == null || raw.isEmpty()) {
			return;
		}
		final long ms;
		try {
			ms = Long.parseLong(raw);
		}
		catch (NumberFormatException ignored) {
			return;
		}
		if (ms <= 0) {
			return;
		}
		try {
			Thread.sleep(ms);
		}
		catch (InterruptedException ignored) {
			Thread.currentThread().interrupt();
		}
	}
}
