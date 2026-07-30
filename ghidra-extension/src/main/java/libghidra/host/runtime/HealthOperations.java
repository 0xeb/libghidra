// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import libghidra.host.contract.HealthContract;

public interface HealthOperations {

	HealthContract.HealthStatusResponse getHealthStatus(HealthContract.HealthStatusRequest request);

	HealthContract.CapabilityResponse getCapabilities(HealthContract.CapabilityRequest request);
}
