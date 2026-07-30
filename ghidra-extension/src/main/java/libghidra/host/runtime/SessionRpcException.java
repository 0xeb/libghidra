// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

public final class SessionRpcException extends RuntimeException {

	private final String code;

	public SessionRpcException(String code, String message) {
		super(message);
		this.code = code != null ? code : "internal_error";
	}

	public String code() {
		return code;
	}
}
