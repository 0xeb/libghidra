package libghidra.host.runtime;

import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeException;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

final class FunctionVariableMutationSupport {

	private FunctionVariableMutationSupport() {
	}

	private static HighSymbol splitMergedHighVariable(HighSymbol symbol) throws PcodeException {
		if (symbol == null) {
			return null;
		}
		HighVariable highVariable = symbol.getHighVariable();
		if (highVariable == null) {
			return symbol;
		}
		Varnode exactSpot = chooseExactVarnode(symbol, highVariable);
		if (exactSpot == null) {
			return symbol;
		}
		HighVariable exactHigh = exactSpot.getHigh();
		if (exactHigh == null) {
			exactHigh = highVariable;
		}
		HighVariable split = symbol.getHighFunction().splitOutMergeGroup(exactHigh, exactSpot);
		return split != null && split.getSymbol() != null ? split.getSymbol() : symbol;
	}

	private static Varnode chooseExactVarnode(HighSymbol symbol, HighVariable highVariable) {
		VariableStorage storage = symbol.getStorage();
		Varnode storageVarnode = null;
		if (storage != null &&
				!storage.isBadStorage() &&
				!storage.isUnassignedStorage() &&
				!storage.isVoidStorage()) {
			storageVarnode = storage.getFirstVarnode();
		}
		if (storageVarnode != null) {
			for (Varnode instance : highVariable.getInstances()) {
				if (instance != null &&
						instance.getSize() == storageVarnode.getSize() &&
						instance.getAddress().equals(storageVarnode.getAddress())) {
					return instance;
				}
			}
		}
		return highVariable.getRepresentative();
	}

	static boolean hasUsableMutationStorage(VariableStorage storage) {
		return storage != null &&
			!storage.isBadStorage() &&
			!storage.isUnassignedStorage() &&
			!storage.isVoidStorage();
	}

	private static void requireUsableMutationStorage(HighSymbol symbol, String localId)
			throws InvalidInputException {
		requireUsableMutationStorage(symbol != null ? symbol.getStorage() : null, localId);
	}

	static void requireUsableMutationStorage(VariableStorage storage, String localId)
			throws InvalidInputException {
		if (hasUsableMutationStorage(storage)) {
			return;
		}
		String id = localId == null || localId.isBlank() ? "<unknown>" : localId;
		throw new InvalidInputException(
			"local '" + id + "' has no concrete storage; decompiler local mutation was not applied");
	}

	static boolean decompileAndRenameHighVariable(
			Program program,
			long functionAddress,
			String localId,
			String newName)
			throws InvalidInputException, DuplicateNameException {
		Function function = FunctionSupport.resolveFunction(program, functionAddress);
		if (function == null) {
			return false;
		}
		DecompInterface decompiler = DecompilerSupport.createDecompiler(program);
		if (decompiler == null) {
			return false;
		}
		try {
			DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
			if (results == null || !results.decompileCompleted()) {
				return false;
			}
			HighFunction highFunc = results.getHighFunction();
			if (highFunc == null) {
				return false;
			}
			Iterator<HighSymbol> iter = highFunc.getLocalSymbolMap().getSymbols();
			while (iter.hasNext()) {
				HighSymbol sym = iter.next();
				if (FunctionSupport.matchesLocalId(function, sym, localId)) {
					if (!sym.isNameLocked()) {
						sym = splitMergedHighVariable(sym);
					}
					requireUsableMutationStorage(sym, localId);
					HighFunctionDBUtil.updateDBVariable(sym, newName, null, SourceType.USER_DEFINED);
					return true;
				}
			}
			return false;
		}
		catch (InvalidInputException | DuplicateNameException e) {
			throw e;
		}
		catch (Exception e) {
			Msg.error(
				FunctionVariableMutationSupport.class,
				"decompileAndRenameHighVariable failed: " + e.getMessage(),
				e);
			return false;
		}
		finally {
			decompiler.dispose();
		}
	}

	static String decompileAndRetypeHighVariable(
			Program program,
			long functionAddress,
			String localId,
			DataType dataType)
			throws InvalidInputException, DuplicateNameException {
		Function function = FunctionSupport.resolveFunction(program, functionAddress);
		if (function == null) {
			return null;
		}
		DecompInterface decompiler = DecompilerSupport.createDecompiler(program);
		if (decompiler == null) {
			return null;
		}
		try {
			DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
			if (results == null || !results.decompileCompleted()) {
				return null;
			}
			HighFunction highFunc = results.getHighFunction();
			if (highFunc == null) {
				return null;
			}
			Iterator<HighSymbol> iter = highFunc.getLocalSymbolMap().getSymbols();
			while (iter.hasNext()) {
				HighSymbol sym = iter.next();
				if (FunctionSupport.matchesLocalId(function, sym, localId)) {
					sym = splitMergedHighVariable(sym);
					requireUsableMutationStorage(sym, localId);
					HighFunctionDBUtil.updateDBVariable(sym, null, dataType, SourceType.USER_DEFINED);
					return dataType.getPathName();
				}
			}
			return null;
		}
		catch (InvalidInputException | DuplicateNameException e) {
			throw e;
		}
		catch (Exception e) {
			Msg.error(
				FunctionVariableMutationSupport.class,
				"decompileAndRetypeHighVariable failed: " + e.getMessage(),
				e);
			return null;
		}
		finally {
			decompiler.dispose();
		}
	}
}
