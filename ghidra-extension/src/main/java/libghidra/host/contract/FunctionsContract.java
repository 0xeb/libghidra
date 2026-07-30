// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.contract;

import java.util.List;

public final class FunctionsContract {

	private FunctionsContract() {
	}

	public record FunctionRecord(
		long entryAddress,
		String name,
		long startAddress,
		long endAddress,
		long size,
		String namespaceName,
		String prototype,
		boolean isThunk,
		int parameterCount) {
	}

	public record GetFunctionRequest(
		long address) {
	}

	public record GetFunctionResponse(FunctionRecord function) {
	}

	public record ListFunctionsRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset) {
	}

	public record ListFunctionsResponse(List<FunctionRecord> functions) {
	}

	public record RenameFunctionRequest(
		long address,
		String newName) {
	}

	public record RenameFunctionResponse(
		boolean renamed,
		String name,
		String errorCode,
		String errorMessage) {
	}

	public record BasicBlockRecord(
		long functionEntry,
		long startAddress,
		long endAddress,
		int inDegree,
		int outDegree) {
	}

	public record ListBasicBlocksRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset) {
	}

	public record ListBasicBlocksResponse(List<BasicBlockRecord> blocks) {
	}

	public record CFGEdgeRecord(
		long functionEntry,
		long srcBlockStart,
		long dstBlockStart,
		String edgeKind) {
	}

	public record ListCFGEdgesRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset) {
	}

	public record ListCFGEdgesResponse(List<CFGEdgeRecord> edges) {
	}

	// Function tags — Ghidra-native categorization
	public record FunctionTagRecord(String name, String comment) {
	}

	public record ListFunctionTagsRequest() {
	}

	public record ListFunctionTagsResponse(List<FunctionTagRecord> tags) {
	}

	public record CreateFunctionTagRequest(
		String name,
		String comment) {
	}

	public record CreateFunctionTagResponse(boolean created) {
	}

	public record DeleteFunctionTagRequest(
		String name) {
	}

	public record DeleteFunctionTagResponse(boolean deleted) {
	}

	public record FunctionTagMappingRecord(long functionEntry, String tagName) {
	}

	public record ListFunctionTagMappingsRequest(
		long functionEntry) {
	}

	public record ListFunctionTagMappingsResponse(List<FunctionTagMappingRecord> mappings) {
	}

	public record TagFunctionRequest(
		long functionEntry,
		String tagName) {
	}

	public record TagFunctionResponse(boolean updated) {
	}

	public record UntagFunctionRequest(
		long functionEntry,
		String tagName) {
	}

	public record UntagFunctionResponse(boolean updated) {
	}

	// --- Switch tables ---
	public record SwitchCaseRecord(long value, long targetAddress) {}
	public record SwitchTableRecord(
		long functionEntry,
		long switchAddress,
		int caseCount,
		List<SwitchCaseRecord> cases,
		long defaultAddress) {}
	public record ListSwitchTablesRequest(long rangeStart, long rangeEnd, int limit, int offset) {}
	public record ListSwitchTablesResponse(List<SwitchTableRecord> switchTables) {}

	// --- Dominators ---
	public record DominatorRecord(
		long functionEntry,
		long blockAddress,
		long idomAddress,
		int depth,
		boolean isEntry) {}
	public record ListDominatorsRequest(long rangeStart, long rangeEnd, int limit, int offset) {}
	public record ListDominatorsResponse(List<DominatorRecord> dominators) {}

	// --- Post-dominators ---
	public record PostDominatorRecord(
		long functionEntry,
		long blockAddress,
		long ipdomAddress,
		int depth,
		boolean isExit) {}
	public record ListPostDominatorsRequest(long rangeStart, long rangeEnd, int limit, int offset) {}
	public record ListPostDominatorsResponse(List<PostDominatorRecord> postDominators) {}

	// --- Loops ---
	public record LoopRecord(
		long functionEntry,
		long headerAddress,
		long backEdgeSource,
		String loopKind,
		int blockCount,
		int depth) {}
	public record ListLoopsRequest(long rangeStart, long rangeEnd, int limit, int offset) {}
	public record ListLoopsResponse(List<LoopRecord> loops) {}

	// --- Stack frames (decompiler-free; from Function.getStackFrame()) ---
	public record StackVariableRecord(
		String varId,
		String name,
		String dataType,
		long stackOffset,
		int size,
		boolean isParameter,
		int firstUseOffset,
		String sourceType) {}
	public record FunctionFrameRecord(
		long functionEntry,
		long frameSize,
		long localSize,
		long parameterSize,
		long parameterOffset,
		long returnAddressOffset,
		boolean growsNegative,
		String stackPointerRegister,
		List<StackVariableRecord> stackVariables) {}
	public record ListFunctionFramesRequest(long rangeStart, long rangeEnd, int limit, int offset) {}
	public record ListFunctionFramesResponse(List<FunctionFrameRecord> frames) {}
}
