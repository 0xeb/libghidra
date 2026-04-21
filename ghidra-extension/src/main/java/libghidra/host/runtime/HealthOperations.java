package libghidra.host.runtime;

import libghidra.host.contract.HealthContract;

public interface HealthOperations {

	HealthContract.HealthStatusResponse getHealthStatus(HealthContract.HealthStatusRequest request);

	HealthContract.CapabilityResponse getCapabilities(HealthContract.CapabilityRequest request);
}
