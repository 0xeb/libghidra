// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
				0,
				false,
				0L,
				false,
				0L,
				false,
				0L);
		}
		return runtime.listXrefs(request);
	}
}
