// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.service;

import libghidra.host.contract.SymbolsContract;
import libghidra.host.runtime.SymbolsOperations;

public final class SymbolsServiceHandler {

	private final SymbolsOperations runtime;

	public SymbolsServiceHandler(SymbolsOperations runtime) {
		this.runtime = runtime;
	}

	public SymbolsContract.GetSymbolResponse getSymbol(
			SymbolsContract.GetSymbolRequest request) {
		if (request == null) {
			request = new SymbolsContract.GetSymbolRequest(
				0L);
		}
		return runtime.getSymbol(request);
	}

	public SymbolsContract.ListSymbolsResponse listSymbols(
			SymbolsContract.ListSymbolsRequest request) {
		if (request == null) {
			request = new SymbolsContract.ListSymbolsRequest(
				0L,
				0L,
				0,
				0);
		}
		return runtime.listSymbols(request);
	}

	public SymbolsContract.RenameSymbolResponse renameSymbol(
			SymbolsContract.RenameSymbolRequest request) {
		if (request == null) {
			request = new SymbolsContract.RenameSymbolRequest(
				0L,
				"");
		}
		return runtime.renameSymbol(request);
	}

	public SymbolsContract.DeleteSymbolResponse deleteSymbol(
			SymbolsContract.DeleteSymbolRequest request) {
		if (request == null) {
			request = new SymbolsContract.DeleteSymbolRequest(
				0L,
				"");
		}
		return runtime.deleteSymbol(request);
	}
}
