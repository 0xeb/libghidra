// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.contract;

import java.util.List;

public final class DecompilerContract {

	private DecompilerContract() {
	}

	public enum DecompileLocalKind {
		UNSPECIFIED,
		PARAM,
		LOCAL,
		TEMP
	}

	public enum DecompileTokenKind {
		UNSPECIFIED,
		KEYWORD,
		COMMENT,
		TYPE,
		FUNCTION,
		VARIABLE,
		CONST,
		PARAMETER,
		GLOBAL,
		DEFAULT,
		ERROR,
		SPECIAL
	}

	public record DecompileTokenRecord(
		String text,
		DecompileTokenKind kind,
		int lineNumber,
		int columnOffset,
		String varName,
		String varType,
		String varStorage) {
	}

	public record DecompileLocalRecord(
		String localId,
		DecompileLocalKind kind,
		String name,
		String dataType,
		String storage,
		int ordinal) {
	}

	public record DecompileRecord(
		long functionEntryAddress,
		String functionName,
		String prototype,
		String pseudocode,
		boolean completed,
		boolean isFallback,
		String errorMessage,
		List<DecompileLocalRecord> locals,
		List<DecompileTokenRecord> tokens) {
	}

	public record DecompileFunctionRequest(
		long address,
		int timeoutMs) {
	}

	public record DecompileFunctionResponse(DecompileRecord decompilation) {
	}

	public record ListDecompilationsRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset,
		int timeoutMs) {
	}

	public record ListDecompilationsResponse(List<DecompileRecord> decompilations) {
	}

	// P-code — two maturity rungs: HIGH (refined SSA via HighFunction.getPcodeOps())
	// and RAW (per-instruction, non-SSA, via Instruction.getPcode()).
	public enum PcodeMaturity { HIGH, RAW }

	public record VarnodeRecord(
		String space,
		long offset,
		int size,
		String kind) {
	}

	public record PcodeOpRecord(
		long seq,
		String op,
		long address,
		boolean hasAddress,
		boolean hasOutput,
		VarnodeRecord output,
		List<VarnodeRecord> inputs) {
	}

	public record PcodeRecord(
		long functionEntryAddress,
		List<PcodeOpRecord> ops,
		boolean completed,
		String errorMessage,
		PcodeMaturity maturity) {
	}

	public record GetPcodeRequest(
		long address,
		int timeoutMs,
		PcodeMaturity maturity) {
	}

	public record GetPcodeResponse(PcodeRecord pcode) {
	}
}
