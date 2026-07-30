// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import libghidra.host.contract.SymbolsContract;

public final class SymbolsRuntime extends RuntimeSupport implements SymbolsOperations {

	public SymbolsRuntime(HostState state) {
		super(state);
	}

	@Override
	public SymbolsContract.GetSymbolResponse getSymbol(SymbolsContract.GetSymbolRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new SymbolsContract.GetSymbolResponse(null);
			}
			try {
				Address address = toAddress(program, request.address());
				// A bogus address that merely happens to have a reference to it (e.g.
				// a stray operand pointing far outside any loaded block) makes
				// getPrimarySymbol() synthesize a *dynamic* default label
				// (DAT_/LAB_deadbeef) even though nothing is actually mapped there —
				// see SymbolManager.getPrimarySymbol: it falls back to a dynamic
				// symbol whenever refManager.hasReferencesTo(addr). Treat "no real
				// memory block backs this address" as not-found so a query at a bogus
				// address yields no symbol rather than a phantom dynamic one.
				Memory memory = program.getMemory();
				if (memory.getBlock(address) == null) {
					return new SymbolsContract.GetSymbolResponse(null);
				}
				Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
				return new SymbolsContract.GetSymbolResponse(RuntimeMappers.toSymbolRecord(symbol));
			}
			catch (IllegalArgumentException e) {
				return new SymbolsContract.GetSymbolResponse(null);
			}
		}
	}

	@Override
	public SymbolsContract.ListSymbolsResponse listSymbols(SymbolsContract.ListSymbolsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			try {
				long defaultStart = programMinOffset(program);
				long startOffset = request != null ? request.rangeStart() : defaultStart;
				long endOffset = request != null ? request.rangeEnd() : -1L;
				if (startOffset == 0) {
					startOffset = defaultStart;
				}
				if (Long.compareUnsigned(endOffset, startOffset) < 0) {
					return new SymbolsContract.ListSymbolsResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 512;

				SymbolTable symbolTable = program.getSymbolTable();
				Address start = toAddress(program, startOffset);
				SymbolIterator it = symbolTable.getSymbolIterator(start, true);
				List<SymbolsContract.SymbolRecord> rows = new ArrayList<>();
				int seen = 0;
				boolean limitReached = false;
				while (it.hasNext()) {
					Symbol symbol = it.next();
					if (symbol == null || symbol.isDeleted()) {
						continue;
					}
					long address = symbol.getAddress().getOffset();
					if (Long.compareUnsigned(address, startOffset) < 0) {
						continue;
					}
					// Inclusive [start, end]: the C++ client issues point queries as
					// [addr, addr] (read_symbols_at) and full scans as [0, MAX]. An
					// exclusive end (address >= endOffset) dropped the exact address on
					// a point query, so every filtered symbol read (names WHERE addr=X)
					// and every freshly-inserted label point-checked at its own address
					// came back empty. Same inclusive-range-end class as the ListingRuntime fixes.
					if (Long.compareUnsigned(address, endOffset) > 0) {
						break;
					}
					if (seen++ < offset) {
						continue;
					}
					rows.add(RuntimeMappers.toSymbolRecord(symbol));
					if (rows.size() >= limit) {
						limitReached = true;
						break;
					}
				}

				// External symbols (imports, external functions/data) live in Ghidra's
				// EXTERNAL address space, which getSymbolIterator(Address,boolean) — a
				// MEMORY-space iterator — cannot reach (it throws on a non-memory address).
				// They are only reachable via getExternalSymbols(). Without this the
				// `imports` surface (which filters is_external) was empty after any
				// save/reopen. Append them at the tail of the global ordered stream so
				// the C++ offset/limit pagination stays consistent across pages.
				// Only for full-range scans (endOffset == unsigned max): point/narrow
				// address queries (read_symbols_at) must not drag in every external.
				boolean fullRangeScan = (endOffset == -1L);
				if (!limitReached && fullRangeScan) {
					SymbolIterator externalIter = symbolTable.getExternalSymbols();
					while (externalIter.hasNext()) {
						Symbol symbol = externalIter.next();
						if (symbol == null || symbol.isDeleted()) {
							continue;
						}
						if (seen++ < offset) {
							continue;
						}
						rows.add(RuntimeMappers.toSymbolRecord(symbol));
						if (rows.size() >= limit) {
							break;
						}
					}
				}
				return new SymbolsContract.ListSymbolsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new SymbolsContract.ListSymbolsResponse(List.of());
			}
		}
	}

	@Override
	public SymbolsContract.RenameSymbolResponse renameSymbol(
			SymbolsContract.RenameSymbolRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new SymbolsContract.RenameSymbolResponse(false, "");
			}
			String newName = request.newName() != null ? request.newName().trim() : "";
			if (newName.isEmpty()) {
				return new SymbolsContract.RenameSymbolResponse(false, "");
			}
			int tx = program.startTransaction("libghidra rename symbol");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				SymbolTable symTable = program.getSymbolTable();
				Symbol symbol = symTable.getPrimarySymbol(address);
				if (symbol == null || symbol.isDeleted()) {
					symbol = symTable.createLabel(address, newName, SourceType.USER_DEFINED);
				}
				else {
					symbol.setName(newName, SourceType.USER_DEFINED);
				}
				commit = true;
				return new SymbolsContract.RenameSymbolResponse(true, nullableString(symbol.getName()));
			}
			catch (IllegalArgumentException | DuplicateNameException | InvalidInputException e) {
				Msg.error(this, "renameSymbol failed: " + e.getMessage(), e);
				return new SymbolsContract.RenameSymbolResponse(false, "");
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public SymbolsContract.DeleteSymbolResponse deleteSymbol(
			SymbolsContract.DeleteSymbolRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new SymbolsContract.DeleteSymbolResponse(false, 0);
			}
			int tx = program.startTransaction("libghidra delete symbol");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				SymbolTable symbolTable = program.getSymbolTable();
				String filterName = request.name() != null ? request.name().trim() : "";
				int deletedCount = 0;
				Symbol[] symbols = symbolTable.getSymbols(address);
				for (Symbol symbol : symbols) {
					if (symbol == null || symbol.isDeleted()) {
						continue;
					}
					if (!filterName.isEmpty() && !filterName.equals(symbol.getName())) {
						continue;
					}
					if (symbol.getSymbolType() == SymbolType.FUNCTION) {
						// Symbol.delete() on a function symbol destroys the ENTIRE
						// function (body/params/signature) and leaves a bare default
						// label. removeSymbolSpecial removes the NAME (demoting the
						// function to its default name) and leaves the function intact.
						if (symbolTable.removeSymbolSpecial(symbol)) {
							deletedCount++;
						}
					} else if (symbol.delete()) {
						deletedCount++;
					}
				}
				if (deletedCount <= 0) {
					return new SymbolsContract.DeleteSymbolResponse(false, 0);
				}
				commit = true;
				return new SymbolsContract.DeleteSymbolResponse(true, deletedCount);
			}
			catch (IllegalArgumentException e) {
				Msg.error(this, "deleteSymbol failed: " + e.getMessage(), e);
				return new SymbolsContract.DeleteSymbolResponse(false, 0);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}
}
