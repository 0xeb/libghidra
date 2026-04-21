package libghidra.host.contract;

import java.util.List;

public final class HealthContract {

	private HealthContract() {
	}

	public record Capability(
		String id,
		String status,
		String note) {
	}

	public record HealthStatusRequest() {
	}

	public record HealthStatusResponse(
		boolean ok,
		String serviceName,
		String serviceVersion,
		String hostMode,
		long programRevision,
		List<String> warnings) {
	}

	public record CapabilityRequest() {
	}

	public record CapabilityResponse(
		List<Capability> capabilities) {
	}
}
