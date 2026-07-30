// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
		long modificationNumber,
		List<String> warnings) {
	}

	public record CapabilityRequest() {
	}

	public record CapabilityResponse(
		List<Capability> capabilities) {
	}
}
