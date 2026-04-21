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
		boolean isDynamic) {
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

	public record RenameSymbolRequest(
		long address,
		String newName) {
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
