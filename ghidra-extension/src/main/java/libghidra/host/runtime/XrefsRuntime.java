package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import libghidra.host.contract.XrefsContract;

public final class XrefsRuntime extends RuntimeSupport implements XrefsOperations {

	public XrefsRuntime(HostState state) {
		super(state);
	}

	@Override
	public XrefsContract.ListXrefsResponse listXrefs(XrefsContract.ListXrefsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null) {
				return new XrefsContract.ListXrefsResponse(List.of());
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
					return new XrefsContract.ListXrefsResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 1024;

				ReferenceManager referenceManager = program.getReferenceManager();
				Address start = toAddress(program, startOffset);
				List<XrefsContract.XrefRecord> rows = new ArrayList<>();
				int seen = 0;
				var fromIterator = referenceManager.getReferenceSourceIterator(start, true);
				while (fromIterator.hasNext()) {
					Address fromAddress = fromIterator.next();
					long fromOffset = fromAddress.getOffset();
					if (fromOffset < startOffset) {
						continue;
					}
					if (fromOffset > endOffset) {
						break;
					}
					Reference[] refs = referenceManager.getReferencesFrom(fromAddress);
					if (refs == null || refs.length == 0) {
						continue;
					}
					for (Reference ref : refs) {
						if (ref == null) {
							continue;
						}
						if (seen++ < offset) {
							continue;
						}
						rows.add(RuntimeMappers.toXrefRecord(ref));
						if (rows.size() >= limit) {
							return new XrefsContract.ListXrefsResponse(rows);
						}
					}
				}
				return new XrefsContract.ListXrefsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new XrefsContract.ListXrefsResponse(List.of());
			}
		}
	}
}
