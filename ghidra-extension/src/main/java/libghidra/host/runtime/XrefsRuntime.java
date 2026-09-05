// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import libghidra.host.contract.XrefsContract;

public final class XrefsRuntime extends RuntimeSupport implements XrefsOperations {

	public XrefsRuntime(HostState state) {
		super(state);
	}

	private static XrefsContract.XrefRecord withFunctionContext(
			Program program, Function fromFunction, Reference reference) {
		XrefsContract.XrefRecord base = RuntimeMappers.toXrefRecord(reference);
		if (base == null || reference == null) {
			return base;
		}
		long fromFunctionAddress = 0L;
		String fromFunctionName = "";
		if (fromFunction != null) {
			fromFunctionAddress = fromFunction.getEntryPoint().getOffset();
			fromFunctionName = fromFunction.getName();
		}

		long toFunctionAddress = reference.getToAddress().getOffset();
		String toFunctionName = "";
		Function toFunction =
			program.getFunctionManager().getFunctionContaining(reference.getToAddress());
		if (toFunction != null) {
			toFunctionAddress = toFunction.getEntryPoint().getOffset();
			toFunctionName = toFunction.getName();
		}
		else {
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(reference.getToAddress());
			if (symbol != null) {
				toFunctionName = symbol.getName();
			}
		}

		return new XrefsContract.XrefRecord(
			base.fromAddress(),
			base.toAddress(),
			base.operandIndex(),
			base.refType(),
			base.isPrimary(),
			base.source(),
			base.symbolId(),
			base.isExternal(),
			base.isMemory(),
			base.isFlow(),
			fromFunctionAddress,
			fromFunctionName,
			toFunctionAddress,
			toFunctionName);
	}

	@Override
	public XrefsContract.ListXrefsResponse listXrefs(XrefsContract.ListXrefsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			try {
				boolean exactToAddress = request != null && request.exactToAddress();
				boolean exactFromFunction =
					request != null && request.exactFromFunction();
				boolean exactToFunction =
					request != null && request.exactToFunction();
				int exactModes = (exactToAddress ? 1 : 0) +
					(exactFromFunction ? 1 : 0) + (exactToFunction ? 1 : 0);
				if (exactModes > 1) {
					return new XrefsContract.ListXrefsResponse(List.of());
				}

				long defaultStart = programMinOffset(program);
				long startOffset = request != null ? request.rangeStart() : defaultStart;
				long endOffset = request != null ? request.rangeEnd() : -1L;
				if (startOffset == 0) {
					startOffset = defaultStart;
				}
				if (!exactToAddress && !exactFromFunction && !exactToFunction &&
						Long.compareUnsigned(endOffset, startOffset) < 0) {
					return new XrefsContract.ListXrefsResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 1024;

				ReferenceManager referenceManager = program.getReferenceManager();
				if (exactToAddress) {
					Address toAddress = toAddress(program, request.toAddress());
					ReferenceIterator iterator = referenceManager.getReferencesTo(toAddress);
					List<XrefsContract.XrefRecord> rows = new ArrayList<>();
					int seen = 0;
					while (iterator.hasNext()) {
						checkCancelled();
						Reference ref = iterator.next();
						if (ref == null) {
							continue;
						}
						// The bulk ListXrefs surface iterates program-memory source
						// addresses. getReferencesTo also yields synthetic external-space
						// references (commonly from address zero), so exclude those to keep
						// exact-predicate pushdown row-equivalent to a filtered full scan.
						if (!program.getMemory().contains(ref.getFromAddress())) {
							continue;
						}
						if (seen++ < offset) {
							continue;
						}
						rows.add(RuntimeMappers.toXrefRecord(ref));
						if (rows.size() >= limit) {
							break;
						}
					}
					return new XrefsContract.ListXrefsResponse(rows);
				}

				if (exactFromFunction) {
					Address functionAddress = toAddress(program, request.functionAddress());
					Function function = program.getFunctionManager().getFunctionAt(functionAddress);
					if (function == null) {
						// Distinguish "there is no function starting here" from "this
						// function makes no references". Returning an empty list for
						// both is indistinguishable to the caller, and the asymmetry
						// is easy to hit because getFunctionAt() requires an EXACT
						// entry point while GetFunction accepts any interior address
						// and resolves it to the containing function -- so the same
						// address can work for one call and silently yield nothing here.
						throw new SessionRpcException("not_found",
							"no function starts at address 0x" +
								Long.toHexString(request.functionAddress()));
					}
					List<XrefsContract.XrefRecord> rows = new ArrayList<>();
					int seen = 0;
					var ranges = function.getBody().getAddressRanges(true);
					while (ranges.hasNext()) {
						checkCancelled();
						AddressRange range = ranges.next();
						Address rangeStart = range.getMinAddress();
						Address rangeEnd = range.getMaxAddress();
						var fromIterator =
							referenceManager.getReferenceSourceIterator(rangeStart, true);
						while (fromIterator.hasNext()) {
							checkCancelled();
							Address fromAddress = fromIterator.next();
							if (fromAddress.compareTo(rangeEnd) > 0) {
								break;
							}
							Reference[] refs = referenceManager.getReferencesFrom(fromAddress);
							if (refs == null) {
								continue;
							}
							for (Reference ref : refs) {
								checkCancelled();
								if (ref == null || seen++ < offset) {
									continue;
								}
								rows.add(withFunctionContext(program, function, ref));
								if (rows.size() >= limit) {
									return new XrefsContract.ListXrefsResponse(rows);
								}
							}
						}
					}
					return new XrefsContract.ListXrefsResponse(rows);
				}

				if (exactToFunction) {
					Address functionAddress = toAddress(program, request.toFunctionAddress());
					Function function = program.getFunctionManager().getFunctionAt(functionAddress);
					if (function == null) {
						return new XrefsContract.ListXrefsResponse(List.of());
					}
					var destinationIterator = referenceManager.getReferenceDestinationIterator(
						function.getBody(), true);
					List<XrefsContract.XrefRecord> rows = new ArrayList<>();
					int seen = 0;
					while (destinationIterator.hasNext()) {
						checkCancelled();
						Address destination = destinationIterator.next();
						ReferenceIterator refs = referenceManager.getReferencesTo(destination);
						while (refs.hasNext()) {
							checkCancelled();
							Reference ref = refs.next();
							if (ref == null || !program.getMemory().contains(ref.getFromAddress())) {
								continue;
							}
							if (seen++ < offset) {
								continue;
							}
							Function fromFunction = program.getFunctionManager()
								.getFunctionContaining(ref.getFromAddress());
							rows.add(withFunctionContext(program, fromFunction, ref));
							if (rows.size() >= limit) {
								return new XrefsContract.ListXrefsResponse(rows);
							}
						}
					}
					return new XrefsContract.ListXrefsResponse(rows);
				}

				Address start = toAddress(program, startOffset);
				List<XrefsContract.XrefRecord> rows = new ArrayList<>();
				int seen = 0;
				var fromIterator = referenceManager.getReferenceSourceIterator(start, true);
				while (fromIterator.hasNext()) {
					checkCancelled();
					Address fromAddress = fromIterator.next();
					long fromOffset = fromAddress.getOffset();
					if (Long.compareUnsigned(fromOffset, startOffset) < 0) {
						continue;
					}
					if (Long.compareUnsigned(fromOffset, endOffset) > 0) {
						break;
					}
					Reference[] refs = referenceManager.getReferencesFrom(fromAddress);
					if (refs == null || refs.length == 0) {
						continue;
					}
					for (Reference ref : refs) {
						checkCancelled();
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
