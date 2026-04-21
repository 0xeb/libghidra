package libghidra.host.contract;

import java.util.List;

public final class MemoryContract {

	private MemoryContract() {
	}

	public record ReadBytesRequest(
		long address,
		int length) {
	}

	public record ReadBytesResponse(byte[] data) {
	}

	public record WriteBytesRequest(
		long address,
		byte[] data) {
	}

	public record WriteBytesResponse(int bytesWritten) {
	}

	public record BytePatch(
		long address,
		byte[] data) {
	}

	public record PatchBytesBatchRequest(
		List<BytePatch> patches) {
	}

	public record PatchBytesBatchResponse(
		int patchCount,
		int bytesWritten) {
	}

	public record MemoryBlockRecord(
		String name,
		long startAddress,
		long endAddress,
		long size,
		boolean isRead,
		boolean isWrite,
		boolean isExecute,
		boolean isVolatile,
		boolean isInitialized,
		String sourceName,
		String comment) {
	}

	public record ListMemoryBlocksRequest(
		int limit,
		int offset) {
	}

	public record ListMemoryBlocksResponse(List<MemoryBlockRecord> blocks) {
	}
}
