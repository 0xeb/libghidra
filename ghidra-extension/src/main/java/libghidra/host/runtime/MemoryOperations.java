// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import libghidra.host.contract.MemoryContract;

public interface MemoryOperations {

	MemoryContract.ReadBytesResponse readBytes(MemoryContract.ReadBytesRequest request);

	MemoryContract.WriteBytesResponse writeBytes(MemoryContract.WriteBytesRequest request);

	MemoryContract.PatchBytesBatchResponse patchBytesBatch(
		MemoryContract.PatchBytesBatchRequest request);

	MemoryContract.ListMemoryBlocksResponse listMemoryBlocks(
		MemoryContract.ListMemoryBlocksRequest request);

	MemoryContract.CreateMemoryBlockResponse createMemoryBlock(
		MemoryContract.CreateMemoryBlockRequest request);

	MemoryContract.RemoveMemoryBlockResponse removeMemoryBlock(
		MemoryContract.RemoveMemoryBlockRequest request);

	MemoryContract.SetMemoryBlockAttributesResponse setMemoryBlockAttributes(
		MemoryContract.SetMemoryBlockAttributesRequest request);

	MemoryContract.MoveMemoryBlockResponse moveMemoryBlock(
		MemoryContract.MoveMemoryBlockRequest request);
}
