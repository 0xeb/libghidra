// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.CommentType;
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
			throw new SessionRpcException("not_loaded", "no current program");
		}
		return program;
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
