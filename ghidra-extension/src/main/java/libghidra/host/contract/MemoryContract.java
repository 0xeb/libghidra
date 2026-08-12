// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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

	// ---- Writable memory map (create / remove / move blocks) ----

	public record CreateMemoryBlockRequest(
		String name,
		long startAddress,
		long size,
		boolean isRead,
		boolean isWrite,
		boolean isExecute,
		boolean initialized,
		boolean overlay) {
	}

	public record CreateMemoryBlockResponse(
		boolean created,
		MemoryBlockRecord block,
		String errorCode,
		String errorMessage) {
	}

	public record RemoveMemoryBlockRequest(long address) {
	}

	public record RemoveMemoryBlockResponse(
		boolean removed,
		String errorCode,
		String errorMessage) {
	}

	public record MoveMemoryBlockRequest(
		long address,
		long newStartAddress) {
	}

	public record MoveMemoryBlockResponse(
		boolean moved,
		MemoryBlockRecord block,
		String errorCode,
		String errorMessage) {
	}

	/**
	 * Mutate an existing block's attributes. Every mutable field is nullable: null means
	 * "leave alone", so a caller can flip one permission without restating the others.
	 * {@code endAddress} is INCLUSIVE, matching {@link MemoryBlockRecord}.
	 */
	public record SetMemoryBlockAttributesRequest(
		long address,
		String name,
		Boolean isRead,
		Boolean isWrite,
		Boolean isExecute,
		Long endAddress) {
	}

	public record SetMemoryBlockAttributesResponse(
		boolean updated,
		MemoryBlockRecord block,
		String errorCode,
		String errorMessage) {
	}
}
