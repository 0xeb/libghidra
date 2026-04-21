package libghidra.host.service;

import libghidra.host.contract.HealthContract;
import libghidra.host.runtime.HealthOperations;

public final class HealthServiceHandler {

	private final HealthOperations runtime;

	public HealthServiceHandler(HealthOperations runtime) {
		this.runtime = runtime;
	}

	public HealthContract.HealthStatusResponse getStatus(HealthContract.HealthStatusRequest request) {
		if (request == null) {
			request = new HealthContract.HealthStatusRequest();
		}
		return runtime.getHealthStatus(request);
	}

	public HealthContract.CapabilityResponse getCapabilities(HealthContract.CapabilityRequest request) {
		if (request == null) {
			request = new HealthContract.CapabilityRequest();
		}
		return runtime.getCapabilities(request);
	}
}
