// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import ghidra.app.util.cparser.C.ParseException;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;

/**
 * An RPC failure: {@code RpcResponse.success=false} with {@link #code()} as the
 * error code. The dispatcher maps it; a runtime throws it instead of returning a
 * false flag, so a write either succeeds with its effect or fails with a reason.
 *
 * The codes are the vocabulary documented on {@code RpcResponse.error_code} in
 * rpc.proto. Use these constants; never spell a code by hand.
 */
public final class SessionRpcException extends RuntimeException {

	public static final String NOT_FOUND = "not_found";
	public static final String UNMAPPED_ADDRESS = "unmapped_address";
	public static final String NOT_LOADED = "not_loaded";
	public static final String INVALID_ARGUMENT = "invalid_argument";
	public static final String DUPLICATE_NAME = "duplicate_name";
	public static final String NOT_SUPPORTED = "not_supported";
	public static final String PARSE_ERROR = "parse_error";
	public static final String UNINITIALIZED_MEMORY = "uninitialized_memory";
	public static final String ACCESS_CONFLICT = "access_conflict";
	public static final String ANALYSIS_RUNNING = "analysis_running";
	public static final String CANCELLED = "cancelled";
	public static final String INTERNAL_ERROR = "internal_error";
	public static final String UNKNOWN_METHOD = "unknown_method";
	public static final String INVALID_PAYLOAD = "invalid_payload";
	public static final String CONFIG_ERROR = "config_error";
	public static final String UNKNOWN_TYPE = "unknown_type";

	private final String code;

	public SessionRpcException(String code, String message) {
		super(message);
		this.code = code != null ? code : INTERNAL_ERROR;
	}

	public String code() {
		return code;
	}

	public static SessionRpcException notFound(String message) {
		return new SessionRpcException(NOT_FOUND, message);
	}

	public static SessionRpcException invalidArgument(String message) {
		return new SessionRpcException(INVALID_ARGUMENT, message);
	}

	public static SessionRpcException duplicateName(String message) {
		return new SessionRpcException(DUPLICATE_NAME, message);
	}

	public static SessionRpcException unmappedAddress(long address) {
		return new SessionRpcException(UNMAPPED_ADDRESS,
			"no memory block contains 0x" + Long.toHexString(address));
	}

	/** A type named as an argument (not the write's target) does not resolve. */
	public static SessionRpcException unknownType(String typeText) {
		return new SessionRpcException(UNKNOWN_TYPE, "unknown data type '" + typeText + "'");
	}

	public static SessionRpcException internalError(String message) {
		return new SessionRpcException(INTERNAL_ERROR, message);
	}

	/**
	 * Map an exception a Ghidra API threw during {@code operation} onto the vocabulary:
	 * bad input is {@code invalid_argument} / {@code duplicate_name} / {@code parse_error},
	 * anything else is {@code internal_error}.
	 */
	public static SessionRpcException from(String operation, Throwable e) {
		if (e instanceof SessionRpcException session) {
			return session;
		}
		String detail = e.getMessage();
		if (detail == null || detail.isBlank()) {
			detail = e.toString();
		}
		String message = operation + ": " + detail;
		if (e instanceof DuplicateNameException) {
			return new SessionRpcException(DUPLICATE_NAME, message);
		}
		if (e instanceof ParseException) {
			return new SessionRpcException(PARSE_ERROR, message);
		}
		if (e instanceof CancelledException) {
			return new SessionRpcException(CANCELLED, message);
		}
		if (e instanceof NotFoundException) {
			return new SessionRpcException(NOT_FOUND, message);
		}
		if (e instanceof LockException) {
			return new SessionRpcException(ACCESS_CONFLICT, message);
		}
		if (e instanceof InvalidInputException || e instanceof IllegalArgumentException ||
			e instanceof MemoryConflictException || e instanceof AddressOverflowException ||
			e instanceof CodeUnitInsertionException) {
			return new SessionRpcException(INVALID_ARGUMENT, message);
		}
		return new SessionRpcException(INTERNAL_ERROR, message);
	}
}
