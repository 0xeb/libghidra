package libghidra.host.runtime;

import libghidra.host.contract.MemoryContract;

public interface MemoryOperations {

	MemoryContract.ReadBytesResponse readBytes(MemoryContract.ReadBytesRequest request);

	MemoryContract.WriteBytesResponse writeBytes(MemoryContract.WriteBytesRequest request);

	MemoryContract.PatchBytesBatchResponse patchBytesBatch(
		MemoryContract.PatchBytesBatchRequest request);

	MemoryContract.ListMemoryBlocksResponse listMemoryBlocks(
		MemoryContract.ListMemoryBlocksRequest request);
}
