// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import libghidra.host.contract.SymbolsContract;

public interface SymbolsOperations {

	SymbolsContract.GetSymbolResponse getSymbol(SymbolsContract.GetSymbolRequest request);

	SymbolsContract.ListSymbolsResponse listSymbols(SymbolsContract.ListSymbolsRequest request);

	SymbolsContract.RenameSymbolResponse renameSymbol(SymbolsContract.RenameSymbolRequest request);

	SymbolsContract.DeleteSymbolResponse deleteSymbol(SymbolsContract.DeleteSymbolRequest request);
}
