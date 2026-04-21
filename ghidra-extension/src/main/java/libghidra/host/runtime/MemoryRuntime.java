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
import libghidra.host.contract.MemoryContract;

public final class MemoryRuntime extends RuntimeSupport implements MemoryOperations {

	public MemoryRuntime(HostState state) {
		super(state);
	}

	@Override
	public MemoryContract.ReadBytesResponse readBytes(MemoryContract.ReadBytesRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null || request == null || request.length() <= 0) {
				return new MemoryContract.ReadBytesResponse(new byte[0]);
			}
			try {
				Address address = toAddress(program, request.address());
				int length = Math.max(0, request.length());
				byte[] data = new byte[length];
				int bytesRead = program.getMemory().getBytes(address, data);
				if (bytesRead <= 0) {
					return new MemoryContract.ReadBytesResponse(new byte[0]);
				}
				if (bytesRead < data.length) {
					data = Arrays.copyOf(data, bytesRead);
				}
				return new MemoryContract.ReadBytesResponse(data);
			}
			catch (IllegalArgumentException | MemoryAccessException e) {
				return new MemoryContract.ReadBytesResponse(new byte[0]);
			}
		}
	}

	@Override
	public MemoryContract.WriteBytesResponse writeBytes(MemoryContract.WriteBytesRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null || request.data() == null || request.data().length == 0) {
				return new MemoryContract.WriteBytesResponse(0);
			}
			int tx = program.startTransaction("libghidra write bytes");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				writeBytesForceWritable(program, address, request.data());
				bumpRevision();
				commit = true;
				return new MemoryContract.WriteBytesResponse(request.data().length);
			}
			catch (IllegalArgumentException | MemoryAccessException e) {
				Msg.error(this, "writeBytes failed at 0x" +
					Long.toHexString(request.address()) + ": " + e.getMessage(), e);
				return new MemoryContract.WriteBytesResponse(0);
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
				bumpRevision();
				commit = true;
				return new MemoryContract.PatchBytesBatchResponse(patchCount, bytesWritten);
			}
			catch (IllegalArgumentException | MemoryAccessException e) {
				Msg.error(this, "patchBytesBatch failed: " + e.getMessage(), e);
				return new MemoryContract.PatchBytesBatchResponse(0, 0);
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
			Program program = currentProgram();
			if (program == null) {
				return new MemoryContract.ListMemoryBlocksResponse(List.of());
			}
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
}
