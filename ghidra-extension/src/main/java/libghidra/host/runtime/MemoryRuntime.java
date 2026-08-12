// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import libghidra.host.contract.MemoryContract;

public final class MemoryRuntime extends RuntimeSupport implements MemoryOperations {

	public MemoryRuntime(HostState state) {
		super(state);
	}

	@Override
	public MemoryContract.ReadBytesResponse readBytes(MemoryContract.ReadBytesRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null) {
				throw new SessionRpcException("not_loaded", "no current program");
			}
			if (request == null || request.length() <= 0) {
				return new MemoryContract.ReadBytesResponse(new byte[0]);
			}
			try {
				Address address = toAddress(program, request.address());
				// A read against an address that is not backed by a live memory block
				// (unmapped, or a block that was moved/removed) is an error, not a
				// zero-length success — reading through Memory.getBytes on such an
				// address throws MemoryAccessException, which we surface below. Guard
				// explicitly first so the error code/message is precise.
				Memory memory = program.getMemory();
				if (memory.getBlock(address) == null) {
					throw new SessionRpcException("unmapped_address",
						"no memory block for address 0x" + Long.toHexString(request.address()));
				}
				int length = Math.max(0, request.length());
				byte[] data = new byte[length];
				int bytesRead = memory.getBytes(address, data);
				if (bytesRead <= 0) {
					return new MemoryContract.ReadBytesResponse(new byte[0]);
				}
				if (bytesRead < data.length) {
					data = Arrays.copyOf(data, bytesRead);
				}
				return new MemoryContract.ReadBytesResponse(data);
			}
			catch (MemoryAccessException e) {
				// The block exists (null-block guarded above), but its bytes are
				// not readable — e.g. a present-but-uninitialized block such as
				// .bss (Memory.getBytes throws here). This is distinct from
				// "unmapped": the address IS mapped, it just has no stored bytes.
				throw new SessionRpcException("uninitialized_memory",
					"read failed at 0x" + Long.toHexString(request.address()) + ": " + e.getMessage());
			}
			catch (IllegalArgumentException e) {
				// The requested address does not resolve to any memory space.
				throw new SessionRpcException("unmapped_address",
					"read failed at 0x" + Long.toHexString(request.address()) + ": " + e.getMessage());
			}
		}
	}

	@Override
	public MemoryContract.WriteBytesResponse writeBytes(MemoryContract.WriteBytesRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null) {
				throw new SessionRpcException("not_loaded", "no current program");
			}
			if (request == null || request.data() == null || request.data().length == 0) {
				return new MemoryContract.WriteBytesResponse(0);
			}
			int tx = program.startTransaction("libghidra write bytes");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				writeBytesForceWritable(program, address, request.data());
				commit = true;
				return new MemoryContract.WriteBytesResponse(request.data().length);
			}
			catch (MemoryAccessException e) {
				// The block exists but the write is not permitted here — e.g. it
				// overlaps defined instructions (checkRangeForInstructions throws).
				// Distinct from "unmapped": the address IS backed by a block.
				Msg.error(this, "writeBytes failed at 0x" +
					Long.toHexString(request.address()) + ": " + e.getMessage(), e);
				throw new SessionRpcException("access_conflict",
					"write failed at 0x" + Long.toHexString(request.address()) + ": " + e.getMessage());
			}
			catch (IllegalArgumentException e) {
				// writeBytesForceWritable throws IllegalArgumentException when no
				// block backs the address — a genuine unmapped write, not a
				// zero-bytes-written success.
				Msg.error(this, "writeBytes failed at 0x" +
					Long.toHexString(request.address()) + ": " + e.getMessage(), e);
				throw new SessionRpcException("unmapped_address",
					"write failed at 0x" + Long.toHexString(request.address()) + ": " + e.getMessage());
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public MemoryContract.PatchBytesBatchResponse patchBytesBatch(
			MemoryContract.PatchBytesBatchRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null || request.patches() == null ||
				request.patches().isEmpty()) {
				return new MemoryContract.PatchBytesBatchResponse(0, 0);
			}
			int tx = program.startTransaction("libghidra patch bytes batch");
			boolean commit = false;
			try {
				int patchCount = 0;
				int bytesWritten = 0;
				for (MemoryContract.BytePatch patch : request.patches()) {
					if (patch == null || patch.data() == null || patch.data().length == 0) {
						continue;
					}
					Address address = toAddress(program, patch.address());
					writeBytesForceWritable(program, address, patch.data());
					patchCount++;
					bytesWritten += patch.data().length;
				}
				commit = true;
				return new MemoryContract.PatchBytesBatchResponse(patchCount, bytesWritten);
			}
			catch (MemoryAccessException e) {
				// The batch is atomic (single transaction): one bad patch rolls
				// back ALL valid patches. Returning (0,0) would report that
				// silent rollback as a no-error success, so surface it instead,
				// mirroring the sibling writeBytes contract.
				Msg.error(this, "patchBytesBatch failed: " + e.getMessage(), e);
				throw new SessionRpcException("access_conflict",
					"patch batch failed and was rolled back: " + e.getMessage());
			}
			catch (IllegalArgumentException e) {
				Msg.error(this, "patchBytesBatch failed: " + e.getMessage(), e);
				throw new SessionRpcException("unmapped_address",
					"patch batch failed and was rolled back: " + e.getMessage());
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public MemoryContract.ListMemoryBlocksResponse listMemoryBlocks(
			MemoryContract.ListMemoryBlocksRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			try {
				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 256;

				Memory memory = program.getMemory();
				MemoryBlock[] blocks = memory.getBlocks();
				List<MemoryContract.MemoryBlockRecord> rows = new ArrayList<>();
				int seen = 0;
				for (MemoryBlock block : blocks) {
					if (seen++ < offset) {
						continue;
					}
					rows.add(new MemoryContract.MemoryBlockRecord(
						nullableString(block.getName()),
						block.getStart().getOffset(),
						block.getEnd().getOffset(),
						block.getSize(),
						block.isRead(),
						block.isWrite(),
						block.isExecute(),
						block.isVolatile(),
						block.isInitialized(),
						nullableString(block.getSourceName()),
						nullableString(block.getComment())));
					if (rows.size() >= limit) {
						break;
					}
				}
				return new MemoryContract.ListMemoryBlocksResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new MemoryContract.ListMemoryBlocksResponse(List.of());
			}
		}
	}

	private static MemoryContract.MemoryBlockRecord toRecord(MemoryBlock block) {
		return new MemoryContract.MemoryBlockRecord(
			nullableString(block.getName()),
			block.getStart().getOffset(),
			block.getEnd().getOffset(),
			block.getSize(),
			block.isRead(),
			block.isWrite(),
			block.isExecute(),
			block.isVolatile(),
			block.isInitialized(),
			nullableString(block.getSourceName()),
			nullableString(block.getComment()));
	}

	@Override
	public MemoryContract.CreateMemoryBlockResponse createMemoryBlock(
			MemoryContract.CreateMemoryBlockRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new MemoryContract.CreateMemoryBlockResponse(false, null, "not_loaded",
					"no current program");
			}
			// size is a proto uint64 carried in a Java long: a block >= 2^63 arrives
			// as a negative long, so an unsigned compare is required. Only 0 is invalid.
			if (request.size() == 0L) {
				return new MemoryContract.CreateMemoryBlockResponse(false, null, "invalid_argument",
					"size must be > 0");
			}
			String name = (request.name() != null && !request.name().isBlank())
				? request.name().trim()
				: "mem_" + Long.toHexString(request.startAddress());
			int tx = program.startTransaction("libghidra create memory block");
			boolean commit = false;
			try {
				Memory memory = program.getMemory();
				Address start = toAddress(program, request.startAddress());
				MemoryBlock block = request.initialized()
					? memory.createInitializedBlock(name, start, request.size(), (byte) 0,
						TaskMonitor.DUMMY, request.overlay())
					: memory.createUninitializedBlock(name, start, request.size(), request.overlay());
				block.setRead(request.isRead());
				block.setWrite(request.isWrite());
				block.setExecute(request.isExecute());
				commit = true;
				return new MemoryContract.CreateMemoryBlockResponse(true, toRecord(block), "", "");
			}
			catch (Exception e) {
				Msg.error(this, "createMemoryBlock failed: " + e.getMessage(), e);
				return new MemoryContract.CreateMemoryBlockResponse(false, null, "create_error",
					String.valueOf(e.getMessage()));
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public MemoryContract.RemoveMemoryBlockResponse removeMemoryBlock(
			MemoryContract.RemoveMemoryBlockRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new MemoryContract.RemoveMemoryBlockResponse(false, "not_loaded",
					"no current program");
			}
			int tx = program.startTransaction("libghidra remove memory block");
			boolean commit = false;
			try {
				Memory memory = program.getMemory();
				MemoryBlock block = memory.getBlock(toAddress(program, request.address()));
				if (block == null) {
					return new MemoryContract.RemoveMemoryBlockResponse(false, "not_found",
						"no memory block at 0x" + Long.toHexString(request.address()));
				}
				memory.removeBlock(block, TaskMonitor.DUMMY);
				commit = true;
				return new MemoryContract.RemoveMemoryBlockResponse(true, "", "");
			}
			catch (Exception e) {
				Msg.error(this, "removeMemoryBlock failed: " + e.getMessage(), e);
				return new MemoryContract.RemoveMemoryBlockResponse(false, "remove_error",
					String.valueOf(e.getMessage()));
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public MemoryContract.SetMemoryBlockAttributesResponse setMemoryBlockAttributes(
			MemoryContract.SetMemoryBlockAttributesRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new MemoryContract.SetMemoryBlockAttributesResponse(false, null,
					"not_loaded", "no current program");
			}
			int tx = program.startTransaction("libghidra set memory block attributes");
			boolean commit = false;
			try {
				Memory memory = program.getMemory();
				MemoryBlock block = memory.getBlock(toAddress(program, request.address()));
				if (block == null) {
					return new MemoryContract.SetMemoryBlockAttributesResponse(false, null,
						"not_found",
						"no memory block at 0x" + Long.toHexString(request.address()));
				}
				// Permissions and name are direct setters. Null means "leave alone".
				if (request.isRead() != null) {
					block.setRead(request.isRead());
				}
				if (request.isWrite() != null) {
					block.setWrite(request.isWrite());
				}
				if (request.isExecute() != null) {
					block.setExecute(request.isExecute());
				}
				if (request.name() != null) {
					block.setName(request.name());
				}
				if (request.endAddress() != null) {
					String err = resizeBlock(memory, block, request.endAddress());
					if (err != null) {
						return new MemoryContract.SetMemoryBlockAttributesResponse(false, null,
							"resize_error", err);
					}
					// split/join replace the handle; re-fetch from the (unchanged) start.
					block = memory.getBlock(toAddress(program, block.getStart().getOffset()));
					if (block == null) {
						return new MemoryContract.SetMemoryBlockAttributesResponse(false, null,
							"resize_error", "block vanished after resize");
					}
				}
				commit = true;
				return new MemoryContract.SetMemoryBlockAttributesResponse(true,
					toRecord(block), "", "");
			}
			catch (Exception e) {
				Msg.error(this, "setMemoryBlockAttributes failed: " + e.getMessage(), e);
				return new MemoryContract.SetMemoryBlockAttributesResponse(false, null,
					"set_attributes_error", String.valueOf(e.getMessage()));
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	/**
	 * Resize {@code block} so its INCLUSIVE end becomes {@code newEndInclusive}.
	 *
	 * Ghidra has no "set end" — a block's extent is changed by splitting or joining, so
	 * this expresses shrink as split-then-remove-tail and grow as create-adjacent-then-join.
	 * The appended block must match the original's initialized-ness or {@code join} refuses
	 * it, and it inherits the original's permissions so a grow cannot silently widen access.
	 *
	 * @return null on success, or a human-readable reason it was rejected.
	 */
	private String resizeBlock(Memory memory, MemoryBlock block, long newEndInclusive)
			throws Exception {
		Address start = block.getStart();
		long startOffset = start.getOffset();
		long currentEndInclusive = block.getEnd().getOffset();
		if (newEndInclusive == currentEndInclusive) {
			return null;
		}
		if (Long.compareUnsigned(newEndInclusive, startOffset) < 0) {
			return "end_address 0x" + Long.toHexString(newEndInclusive)
				+ " is below the block start 0x" + Long.toHexString(startOffset);
		}
		if (Long.compareUnsigned(newEndInclusive, currentEndInclusive) < 0) {
			// Shrink: split just past the new end, then drop the tail.
			Address splitAt = start.getNewAddress(newEndInclusive + 1);
			memory.split(block, splitAt);
			MemoryBlock tail = memory.getBlock(splitAt);
			if (tail == null) {
				return "tail block missing after split at 0x"
					+ Long.toHexString(newEndInclusive + 1);
			}
			memory.removeBlock(tail, TaskMonitor.DUMMY);
			return null;
		}
		// Grow: append a same-shaped block covering (currentEnd, newEnd] and join it on.
		Address appendStart = start.getNewAddress(currentEndInclusive + 1);
		if (memory.getBlock(appendStart) != null) {
			return "cannot grow past 0x" + Long.toHexString(currentEndInclusive)
				+ ": address 0x" + Long.toHexString(currentEndInclusive + 1)
				+ " already belongs to another block";
		}
		long added = newEndInclusive - currentEndInclusive;
		MemoryBlock appended;
		if (block.isInitialized()) {
			appended = memory.createInitializedBlock(block.getName() + "_grow", appendStart,
				added, (byte) 0, TaskMonitor.DUMMY, false);
		}
		else {
			appended = memory.createUninitializedBlock(block.getName() + "_grow", appendStart,
				added, false);
		}
		appended.setRead(block.isRead());
		appended.setWrite(block.isWrite());
		appended.setExecute(block.isExecute());
		memory.join(block, appended);
		return null;
	}

	@Override
	public MemoryContract.MoveMemoryBlockResponse moveMemoryBlock(
			MemoryContract.MoveMemoryBlockRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new MemoryContract.MoveMemoryBlockResponse(false, null, "not_loaded",
					"no current program");
			}
			int tx = program.startTransaction("libghidra move memory block");
			boolean commit = false;
			try {
				Memory memory = program.getMemory();
				MemoryBlock block = memory.getBlock(toAddress(program, request.address()));
				if (block == null) {
					return new MemoryContract.MoveMemoryBlockResponse(false, null, "not_found",
						"no memory block at 0x" + Long.toHexString(request.address()));
				}
				Address newStart = toAddress(program, request.newStartAddress());
				memory.moveBlock(block, newStart, TaskMonitor.DUMMY);
				// The pre-move `block` handle is stale once moveBlock relocates it;
				// always re-fetch at the new start rather than serialize the old range.
				MemoryBlock moved = memory.getBlock(newStart);
				if (moved == null) {
					return new MemoryContract.MoveMemoryBlockResponse(false, null, "move_error",
						"block not found at new start 0x" + Long.toHexString(request.newStartAddress())
							+ " after move");
				}
				commit = true;
				return new MemoryContract.MoveMemoryBlockResponse(true,
					toRecord(moved), "", "");
			}
			catch (Exception e) {
				Msg.error(this, "moveMemoryBlock failed: " + e.getMessage(), e);
				return new MemoryContract.MoveMemoryBlockResponse(false, null, "move_error",
					String.valueOf(e.getMessage()));
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}
}
