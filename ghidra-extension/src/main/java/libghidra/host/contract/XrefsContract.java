package libghidra.host.contract;

import java.util.List;

public final class XrefsContract {

	private XrefsContract() {
	}

	public record XrefRecord(
		long fromAddress,
		long toAddress,
		int operandIndex,
		String refType,
		boolean isPrimary,
		String source,
		long symbolId,
		boolean isExternal,
		boolean isMemory,
		boolean isFlow) {
	}

	public record ListXrefsRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset) {
	}

	public record ListXrefsResponse(List<XrefRecord> xrefs) {
	}
}
