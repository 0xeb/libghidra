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

	protected final long revision() {
		return state.getRevision();
	}

	protected final void bumpRevision() {
		state.bumpRevision();
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
