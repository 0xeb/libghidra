package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import libghidra.host.contract.DecompilerContract;

public final class DecompilerRuntime extends RuntimeSupport implements DecompilerOperations {

	public DecompilerRuntime(HostState state) {
		super(state);
	}

	@Override
	public DecompilerContract.DecompileFunctionResponse decompileFunction(
			DecompilerContract.DecompileFunctionRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new DecompilerContract.DecompileFunctionResponse(null);
			}
			try {
				Address address = toAddress(program, request.address());
				Function function = program.getFunctionManager().getFunctionContaining(address);
				if (function == null) {
					return new DecompilerContract.DecompileFunctionResponse(null);
				}

				int timeoutSeconds = DecompilerSupport.normalizeDecompileTimeoutSeconds(request.timeoutMs());
				DecompInterface decompiler = DecompilerSupport.createDecompiler(program);
				try {
					return new DecompilerContract.DecompileFunctionResponse(
						DecompilerSupport.toDecompileRecord(function, decompiler, timeoutSeconds));
				}
				finally {
					if (decompiler != null) {
						decompiler.dispose();
					}
				}
			}
			catch (IllegalArgumentException e) {
				return new DecompilerContract.DecompileFunctionResponse(null);
			}
		}
	}

	@Override
	public DecompilerContract.ListDecompilationsResponse listDecompilations(
			DecompilerContract.ListDecompilationsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null) {
				return new DecompilerContract.ListDecompilationsResponse(List.of());
			}
			try {
				long defaultStart = program.getMinAddress().getOffset();
				long defaultEnd = program.getMaxAddress().getOffset();
				long startOffset = request != null ? request.rangeStart() : defaultStart;
				long endOffset = request != null ? request.rangeEnd() : defaultEnd;
				if (startOffset <= 0) {
					startOffset = defaultStart;
				}
				if (endOffset <= 0) {
					endOffset = defaultEnd;
				}
				if (endOffset < startOffset) {
					return new DecompilerContract.ListDecompilationsResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 128;
				int timeoutSeconds = DecompilerSupport.normalizeDecompileTimeoutSeconds(
					request != null ? request.timeoutMs() : 0);

				FunctionManager functionManager = program.getFunctionManager();
				Address start = toAddress(program, startOffset);
				FunctionIterator it = functionManager.getFunctions(start, true);
				List<DecompilerContract.DecompileRecord> rows = new ArrayList<>();
				int seen = 0;

				DecompInterface decompiler = DecompilerSupport.createDecompiler(program);
				try {
					while (it.hasNext()) {
						Function function = it.next();
						if (function == null) {
							continue;
						}
						long address = function.getEntryPoint().getOffset();
						if (address < startOffset) {
							continue;
						}
						if (address > endOffset) {
							break;
						}
						if (seen++ < offset) {
							continue;
						}
						rows.add(DecompilerSupport.toDecompileRecord(function, decompiler, timeoutSeconds));
						if (rows.size() >= limit) {
							break;
						}
					}
				}
				finally {
					if (decompiler != null) {
						decompiler.dispose();
					}
				}
				return new DecompilerContract.ListDecompilationsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new DecompilerContract.ListDecompilationsResponse(List.of());
			}
		}
	}
}
