package libghidra.host.runtime;

import libghidra.host.contract.SymbolsContract;

public interface SymbolsOperations {

	SymbolsContract.GetSymbolResponse getSymbol(SymbolsContract.GetSymbolRequest request);

	SymbolsContract.ListSymbolsResponse listSymbols(SymbolsContract.ListSymbolsRequest request);

	SymbolsContract.RenameSymbolResponse renameSymbol(SymbolsContract.RenameSymbolRequest request);

	SymbolsContract.DeleteSymbolResponse deleteSymbol(SymbolsContract.DeleteSymbolRequest request);
}
