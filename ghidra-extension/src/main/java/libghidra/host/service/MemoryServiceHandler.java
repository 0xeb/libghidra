package libghidra.host.service;

import java.util.List;

import libghidra.host.contract.MemoryContract;
import libghidra.host.runtime.MemoryOperations;

public final class MemoryServiceHandler {

	private final MemoryOperations runtime;

	public MemoryServiceHandler(MemoryOperations runtime) {
		this.runtime = runtime;
	}

	public MemoryContract.ReadBytesResponse readBytes(MemoryContract.ReadBytesRequest request) {
		if (request == null) {
			request = new MemoryContract.ReadBytesRequest(
				0L,
				0);
		}
		return runtime.readBytes(request);
	}

	public MemoryContract.WriteBytesResponse writeBytes(MemoryContract.WriteBytesRequest request) {
		if (request == null) {
			request = new MemoryContract.WriteBytesRequest(
				0L,
				new byte[0]);
		}
		return runtime.writeBytes(request);
	}

	public MemoryContract.PatchBytesBatchResponse patchBytes(
			MemoryContract.PatchBytesBatchRequest request) {
		if (request == null) {
			request = new MemoryContract.PatchBytesBatchRequest(
				List.of());
		}
		return runtime.patchBytesBatch(request);
	}

	public MemoryContract.ListMemoryBlocksResponse listMemoryBlocks(
			MemoryContract.ListMemoryBlocksRequest request) {
		if (request == null) {
			request = new MemoryContract.ListMemoryBlocksRequest(
				0,
				0);
		}
		return runtime.listMemoryBlocks(request);
	}
}
