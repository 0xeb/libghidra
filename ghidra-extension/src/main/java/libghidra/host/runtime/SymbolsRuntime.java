package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
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
			Program program = currentProgram();
			if (program == null) {
				return new SymbolsContract.ListSymbolsResponse(List.of());
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
					return new SymbolsContract.ListSymbolsResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 512;

				SymbolTable symbolTable = program.getSymbolTable();
				Address start = toAddress(program, startOffset);
				SymbolIterator it = symbolTable.getSymbolIterator(start, true);
				List<SymbolsContract.SymbolRecord> rows = new ArrayList<>();
				int seen = 0;
				while (it.hasNext()) {
					Symbol symbol = it.next();
					if (symbol == null || symbol.isDeleted()) {
						continue;
					}
					long address = symbol.getAddress().getOffset();
					if (address < startOffset) {
						continue;
					}
					if (address > endOffset) {
						break;
					}
					if (seen++ < offset) {
						continue;
					}
					rows.add(RuntimeMappers.toSymbolRecord(symbol));
					if (rows.size() >= limit) {
						break;
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
				bumpRevision();
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
					if (symbol.delete()) {
						deletedCount++;
					}
				}
				if (deletedCount <= 0) {
					return new SymbolsContract.DeleteSymbolResponse(false, 0);
				}
				bumpRevision();
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
