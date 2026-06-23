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

	protected final Program currentProgram() {
		return state.getCurrentProgram();
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

	/**
	 * Normalize a "list" RPC's range-end offset, treating a non-positive value as unbounded.
	 *
	 * <p>The C++ client encodes an unbounded upper bound as the protobuf {@code uint64}
	 * {@code UINT64_MAX}, which is decoded here into a signed Java {@code long} as {@code -1}.
	 * Earlier code fell back to {@code program.getMaxAddress().getOffset()} for any
	 * non-positive end; for programs whose maximum address lives in a low-offset space (an
	 * EXTERNAL block, or file-backed "OTHER" sections at offset 0) that collapsed the scan
	 * window and made range-filtered tables return no rows. Treating it as
	 * {@link Long#MAX_VALUE} keeps the scan unbounded. See ghidrasql #2/#3/#6.
	 */
	protected static long resolveRangeEnd(long requestedEnd) {
		return requestedEnd <= 0 ? Long.MAX_VALUE : requestedEnd;
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
