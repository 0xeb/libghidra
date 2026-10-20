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
import ghidra.program.model.symbol.SymbolUtilities;
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
			// No program open is an error (not_loaded), never "not found".
			Program program = requireProgram();
			if (request == null) {
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

	/**
	 * Renames a symbol at a mapped address. With {@code oldName} set it renames exactly
	 * the symbol of that name there, primary or not ({@code not_found} when the address
	 * has none), which is how a secondary label is renamed. Unset, it renames the primary
	 * symbol, or creates a label when the address has none (the upsert
	 * {@code INSERT INTO names} relies on). An unmapped address is
	 * {@code unmapped_address}: no label is ever created outside the program's memory.
	 */
	@Override
	public SymbolsContract.RenameSymbolResponse renameSymbol(
			SymbolsContract.RenameSymbolRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = requireProgram();
			requireRequest(request);
			String newName = requireText(request.newName(), "new symbol name");
			String oldName = request.oldName() != null
				? requireText(request.oldName(), "old symbol name")
				: null;
			Address address = requireMappedAddress(program, request.address());
			SymbolTable symTable = program.getSymbolTable();
			Symbol named = null;
			if (oldName != null) {
				named = symbolNamed(symTable, address, oldName);
				if (named == null) {
					throw SessionRpcException.notFound("no symbol named '" + oldName + "' at 0x" +
						Long.toHexString(request.address()));
				}
			}
			int tx = program.startTransaction("libghidra rename symbol");
			boolean commit = false;
			try {
				Symbol symbol = named != null ? named : symTable.getPrimarySymbol(address);
				if (named != null) {
					symbol.setName(newName, SourceType.USER_DEFINED);
				}
				else if (symbol == null || symbol.isDeleted()) {
					symbol = symTable.createLabel(address, newName, SourceType.USER_DEFINED);
				}
				else {
					symbol.setName(newName, SourceType.USER_DEFINED);
				}
				commit = true;
				return new SymbolsContract.RenameSymbolResponse(true, nullableString(symbol.getName()));
			}
			catch (IllegalArgumentException | DuplicateNameException | InvalidInputException e) {
				throw SessionRpcException.from("rename symbol", e);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	/**
	 * Adds the label {@code name} at a mapped address through Ghidra's
	 * {@link SymbolTable#createLabel}; it never renames another label. The address keeps
	 * the symbols it has, and the new label is primary only when it had none (Ghidra's
	 * rule). One case is Ghidra's own and kept: on a function that still has its default
	 * name ({@code FUN_...}), the label becomes the function's name.
	 *
	 * Errors: {@code invalid_argument} for a blank or invalid name; {@code unmapped_address}
	 * outside every memory block; {@code duplicate_name} when a symbol of that name is
	 * already at the address (Ghidra would silently return it).
	 */
	@Override
	public SymbolsContract.CreateLabelResponse createLabel(
			SymbolsContract.CreateLabelRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = requireProgram();
			requireRequest(request);
			String name = requireText(request.name(), "label name");
			try {
				SymbolUtilities.validateName(name);
			}
			catch (InvalidInputException e) {
				throw SessionRpcException.from("create label", e);
			}
			Address address = requireMappedAddress(program, request.address());
			SymbolTable symTable = program.getSymbolTable();
			Symbol same = symbolNamed(symTable, address, name);
			if (same != null && !same.isDynamic()) {
				throw SessionRpcException.duplicateName("a symbol named '" + name +
					"' is already at 0x" + Long.toHexString(request.address()));
			}
			int tx = program.startTransaction("libghidra create label");
			boolean commit = false;
			try {
				Symbol symbol = symTable.createLabel(address, name, SourceType.USER_DEFINED);
				commit = true;
				return new SymbolsContract.CreateLabelResponse(true,
					RuntimeMappers.toSymbolRecord(symbol));
			}
			catch (IllegalArgumentException | InvalidInputException e) {
				throw SessionRpcException.from("create label", e);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	/** The live symbol at {@code address} whose name (or namespaced name) is {@code name}. */
	private static Symbol symbolNamed(SymbolTable symTable, Address address, String name) {
		for (Symbol symbol : symTable.getSymbols(address)) {
			if (symbol == null || symbol.isDeleted()) {
				continue;
			}
			if (name.equals(symbol.getName()) || name.equals(symbol.getName(true))) {
				return symbol;
			}
		}
		return null;
	}

	/**
	 * Deletes the symbols at an address (only those named {@code name} when it is set).
	 * A function's own symbol loses its name and the function stays (removeSymbolSpecial).
	 * Nothing to delete is {@code not_found}.
	 */
	@Override
	public SymbolsContract.DeleteSymbolResponse deleteSymbol(
			SymbolsContract.DeleteSymbolRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = requireProgram();
			requireRequest(request);
			Address address = requireMappedAddress(program, request.address());
			int tx = program.startTransaction("libghidra delete symbol");
			boolean commit = false;
			try {
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
					throw SessionRpcException.notFound(filterName.isEmpty()
						? "no symbol to delete at 0x" + Long.toHexString(request.address())
						: "no symbol named '" + filterName + "' at 0x" +
							Long.toHexString(request.address()));
				}
				commit = true;
				return new SymbolsContract.DeleteSymbolResponse(true, deletedCount);
			}
			catch (IllegalArgumentException e) {
				throw SessionRpcException.from("delete symbol", e);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}
}
