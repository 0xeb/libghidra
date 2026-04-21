package libghidra.host.runtime;

import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

final class FunctionVariableMutationSupport {

	private FunctionVariableMutationSupport() {
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
					if (sym.getStorage().isStackStorage()) {
						// For stack variables, use the StackFrame API directly.
						// updateDBVariable + addLocalVariable can silently fail for stack locals
						// in some cases; the stack frame API is the authoritative path for
						// stack variable creation/rename.
						int stackOffset = (int) sym.getStorage().getStackOffset();
						ghidra.program.model.listing.Variable existing =
							function.getStackFrame().getVariableContaining(stackOffset);
						if (existing != null) {
							existing.setName(newName, SourceType.USER_DEFINED);
						} else {
							function.getStackFrame().createVariable(newName, stackOffset,
								sym.getDataType(), SourceType.USER_DEFINED);
						}
					} else {
						HighFunctionDBUtil.updateDBVariable(sym, newName, null, SourceType.USER_DEFINED);
					}
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
					if (sym.getStorage().isStackStorage()) {
						int stackOffset = (int) sym.getStorage().getStackOffset();
						ghidra.program.model.listing.Variable existing =
							function.getStackFrame().getVariableContaining(stackOffset);
						if (existing != null) {
							existing.setDataType(dataType, SourceType.USER_DEFINED);
						} else {
							function.getStackFrame().createVariable(sym.getName(), stackOffset,
								dataType, SourceType.USER_DEFINED);
						}
					} else {
						HighFunctionDBUtil.updateDBVariable(sym, null, dataType, SourceType.USER_DEFINED);
					}
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
