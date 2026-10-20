// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import libghidra.host.contract.ListingContract;

abstract class RuntimeSupport {

	protected final HostState state;

	RuntimeSupport(HostState state) {
		this.state = state;
	}

	protected final LockScope readLock() {
		return state.readLock();
	}

	protected final LockScope writeLock() {
		return state.writeLock();
	}

	protected final void checkCancelled() {
		RequestCancellation.throwIfCancelled();
	}

	protected final Program currentProgram() {
		return state.getCurrentProgram();
	}

	/**
	 * Returns the current program, or throws a {@code not_loaded} RPC error when no
	 * program is open. Data-query handlers use this so a query issued with no open
	 * program surfaces a clean error to the client (RpcResponse.success=false)
	 * rather than a silent empty-but-success result — matching the host contract
	 * "query with no open program -> clean error".
	 */
	protected final Program requireProgram() {
		Program program = state.getCurrentProgram();
		if (program == null) {
			throw new SessionRpcException(SessionRpcException.NOT_LOADED, "no current program");
		}
		return program;
	}

	/**
	 * The request a write handler was given. The dispatcher always builds one; a
	 * missing request can only come from an in-process caller and is a bad argument.
	 */
	protected static <T> T requireRequest(T request) {
		if (request == null) {
			throw SessionRpcException.invalidArgument("request is required");
		}
		return request;
	}

	/** {@code value} trimmed, or {@code invalid_argument} naming {@code what} when blank. */
	protected static String requireText(String value, String what) {
		String trimmed = value != null ? value.trim() : "";
		if (trimmed.isEmpty()) {
			throw SessionRpcException.invalidArgument(what + " is required");
		}
		return trimmed;
	}

	/**
	 * The address at {@code offset}, which a memory block must contain. Any write that
	 * names an address answers {@code unmapped_address} when none does, rather than
	 * acting on (or creating something at) an address outside the program.
	 */
	protected static Address requireMappedAddress(Program program, long offset) {
		Address address;
		try {
			address = toAddress(program, offset);
		}
		catch (IllegalArgumentException e) {
			throw SessionRpcException.unmappedAddress(offset);
		}
		if (program.getMemory().getBlock(address) == null) {
			throw SessionRpcException.unmappedAddress(offset);
		}
		return address;
	}

	/**
	 * The function a function-scoped write acts on: the one that starts at, or
	 * contains, {@code offset} (the same rule the reads use). {@code unmapped_address}
	 * when no block contains it, {@code not_found} when no function does.
	 */
	protected static Function requireFunction(Program program, long offset) {
		Address address = requireMappedAddress(program, offset);
		FunctionManager functions = program.getFunctionManager();
		Function function = functions.getFunctionAt(address);
		if (function == null) {
			function = functions.getFunctionContaining(address);
		}
		if (function == null) {
			throw SessionRpcException.notFound("no function at 0x" + Long.toHexString(offset));
		}
		return function;
	}

	/**
	 * The program's minimum address offset, or 0 when the program has no memory
	 * blocks. A blockless program (freshly created, or with every block removed)
	 * returns null from {@link Program#getMinAddress()}; handlers use this as a
	 * default pagination lower bound and must not NPE on that program.
	 */
	protected static long programMinOffset(Program program) {
		var min = program.getMinAddress();
		return min != null ? min.getOffset() : 0L;
	}

	protected final String hostMode() {
		return state.getHostMode();
	}

	protected final String currentProgramPath() {
		return state.getCurrentProgramPath();
	}

	protected final long programId() {
		return state.getProgramId();
	}

	protected final long modificationNumber() {
		return state.getModificationNumber();
	}

	protected final String fileId() {
		return state.getFileId();
	}

	protected final int fileVersion() {
		return state.getFileVersion();
	}

	protected final long fileLastModifiedTime() {
		return state.getFileLastModifiedTime();
	}

	protected static String nullableString(String text) {
		return text != null ? text : "";
	}

	protected static Address toAddress(Program program, long offset) {
		try {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		}
		catch (AddressOutOfBoundsException e) {
			throw new IllegalArgumentException("address out of bounds: 0x" + Long.toHexString(offset), e);
		}
	}

	protected static void writeBytesForceWritable(Program program, Address address, byte[] data)
			throws MemoryAccessException {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(address);
		if (block == null) {
			throw new IllegalArgumentException(
				"no memory block for address 0x" + Long.toHexString(address.getOffset()));
		}
		boolean restoreWrite = false;
		boolean originalWrite = block.isWrite();
		if (!originalWrite) {
			block.setWrite(true);
			restoreWrite = true;
		}
		try {
			memory.setBytes(address, data);
		}
		finally {
			if (restoreWrite) {
				block.setWrite(false);
			}
		}
	}

	protected static void flushProgramEvents(Program program) {
		if (program == null) {
			return;
		}
		try {
			program.flushEvents();
		}
		catch (RuntimeException e) {
			ghidra.util.Msg.warn(
				RuntimeSupport.class,
				"program.flushEvents() failed: " + e.getMessage(),
				e);
		}
	}

	protected static CommentType toCommentType(ListingContract.CommentKind kind) {
		if (kind == null) {
			return null;
		}
		switch (kind) {
			case EOL:
				return CommentType.EOL;
			case PRE:
				return CommentType.PRE;
			case POST:
				return CommentType.POST;
			case PLATE:
				return CommentType.PLATE;
			case REPEATABLE:
				return CommentType.REPEATABLE;
			case UNSPECIFIED:
			default:
				return null;
		}
	}

	protected static String classifyFlowType(ghidra.program.model.symbol.FlowType flowType) {
		if (flowType.isFallthrough()) {
			return "FALL_THROUGH";
		}
		if (flowType.isCall()) {
			return "CALL";
		}
		if (flowType.isConditional()) {
			return "CONDITIONAL_JUMP";
		}
		if (flowType.isJump() || flowType.isUnConditional()) {
			return "UNCONDITIONAL_JUMP";
		}
		return flowType.getName().toUpperCase(java.util.Locale.ROOT).replace(' ', '_');
	}
}
