package libghidra.host.service;

import libghidra.host.contract.XrefsContract;
import libghidra.host.runtime.XrefsOperations;

public final class XrefsServiceHandler {

	private final XrefsOperations runtime;

	public XrefsServiceHandler(XrefsOperations runtime) {
		this.runtime = runtime;
	}

	public XrefsContract.ListXrefsResponse listXrefs(
			XrefsContract.ListXrefsRequest request) {
		if (request == null) {
			request = new XrefsContract.ListXrefsRequest(
				0L,
				0L,
				0,
				0);
		}
		return runtime.listXrefs(request);
	}
}
