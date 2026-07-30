// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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

	public MemoryContract.CreateMemoryBlockResponse createMemoryBlock(
			MemoryContract.CreateMemoryBlockRequest request) {
		if (request == null) {
			request = new MemoryContract.CreateMemoryBlockRequest(
				"", 0L, 0L, false, false, false, false, false);
		}
		return runtime.createMemoryBlock(request);
	}

	public MemoryContract.RemoveMemoryBlockResponse removeMemoryBlock(
			MemoryContract.RemoveMemoryBlockRequest request) {
		if (request == null) {
			request = new MemoryContract.RemoveMemoryBlockRequest(0L);
		}
		return runtime.removeMemoryBlock(request);
	}

	public MemoryContract.MoveMemoryBlockResponse moveMemoryBlock(
			MemoryContract.MoveMemoryBlockRequest request) {
		if (request == null) {
			request = new MemoryContract.MoveMemoryBlockRequest(0L, 0L);
		}
		return runtime.moveMemoryBlock(request);
	}
}
