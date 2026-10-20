// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.contract;

import java.util.List;

public final class SymbolsContract {

	private SymbolsContract() {
	}

	public record SymbolRecord(
		long symbolId,
		long address,
		String name,
		String fullName,
		String type,
		String namespaceName,
		String source,
		boolean isPrimary,
		boolean isExternal,
		boolean isDynamic,
		boolean isExternalEntryPoint) {
	}

	public record GetSymbolRequest(
		long address) {
	}

	public record GetSymbolResponse(SymbolRecord symbol) {
	}

	public record ListSymbolsRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset) {
	}

	public record ListSymbolsResponse(List<SymbolRecord> symbols) {
	}

	public record CreateLabelRequest(
		long address,
		String name) {
	}

	public record CreateLabelResponse(
		boolean created,
		SymbolRecord symbol) {
	}

	/**
	 * {@code oldName} is null when the caller left it unset (rename the primary symbol);
	 * set, it names exactly the symbol at the address to rename.
	 */
	public record RenameSymbolRequest(
		long address,
		String newName,
		String oldName) {
	}

	public record RenameSymbolResponse(
		boolean renamed,
		String name) {
	}

	public record DeleteSymbolRequest(
		long address,
		String name) {
	}

	public record DeleteSymbolResponse(
		boolean deleted,
		int deletedCount) {
	}
}
