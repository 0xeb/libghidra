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
}
