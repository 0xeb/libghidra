package libghidra.host.service;

import libghidra.host.contract.DecompilerContract;
import libghidra.host.runtime.DecompilerOperations;

public final class DecompilerServiceHandler {

	private final DecompilerOperations runtime;

	public DecompilerServiceHandler(DecompilerOperations runtime) {
		this.runtime = runtime;
	}

	public DecompilerContract.DecompileFunctionResponse decompileFunction(
			DecompilerContract.DecompileFunctionRequest request) {
		if (request == null) {
			request = new DecompilerContract.DecompileFunctionRequest(
				0L,
				0);
		}
		return runtime.decompileFunction(request);
	}

	public DecompilerContract.ListDecompilationsResponse listDecompilations(
			DecompilerContract.ListDecompilationsRequest request) {
		if (request == null) {
			request = new DecompilerContract.ListDecompilationsRequest(
				0L,
				0L,
				0,
				0,
				0);
		}
		return runtime.listDecompilations(request);
	}
}
