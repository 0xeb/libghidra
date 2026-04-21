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
			request = new SessionContract.OpenProgramRequest("", "", "", false, false);
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
		return runtime.shutdown(request);
	}
}
