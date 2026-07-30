// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
