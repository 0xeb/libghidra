package libghidra.host.runtime;

import libghidra.host.contract.DecompilerContract;

public interface DecompilerOperations {

	DecompilerContract.DecompileFunctionResponse decompileFunction(
		DecompilerContract.DecompileFunctionRequest request);

	DecompilerContract.ListDecompilationsResponse listDecompilations(
		DecompilerContract.ListDecompilationsRequest request);
}
