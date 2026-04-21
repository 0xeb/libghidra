package libghidra.host.runtime;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighSymbol;

final class FunctionSupport {

	private FunctionSupport() {
	}

	static Function resolveFunction(Program program, long addressOffset) {
		if (program == null) {
			return null;
		}
		Address address = RuntimeSupport.toAddress(program, addressOffset);
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionAt(address);
		if (function == null) {
			function = functionManager.getFunctionContaining(address);
		}
		return function;
	}

	static Parameter resolveFunctionParameter(Program program, long functionAddress, int ordinal) {
		if (program == null || ordinal < 0) {
			return null;
		}
		Function function = resolveFunction(program, functionAddress);
		if (function == null) {
			return null;
		}
		Parameter[] parameters = function.getParameters();
		if (ordinal >= parameters.length) {
			return null;
		}
		return parameters[ordinal];
	}

	static Variable resolveFunctionVariable(Program program, long functionAddress, String localId) {
		if (program == null || localId == null || localId.isBlank()) {
			return null;
		}
		Function function = resolveFunction(program, functionAddress);
		if (function == null) {
			return null;
		}
		String normalizedId = localId.trim();

		Integer argIndex = parseIndexedLocalId(normalizedId, "arg");
		if (argIndex != null) {
			Parameter[] parameters = function.getParameters();
			return argIndex >= 0 && argIndex < parameters.length ? parameters[argIndex] : null;
		}

		Integer localIndex = parseIndexedLocalId(normalizedId, "var");
		if (localIndex == null) {
			localIndex = parseIndexedLocalId(normalizedId, "local");
		}
		if (localIndex != null) {
			Variable[] locals = function.getLocalVariables();
			return localIndex >= 0 && localIndex < locals.length ? locals[localIndex] : null;
		}

		for (Parameter parameter : function.getParameters()) {
			if (parameter != null && matchesLocalId(function, parameter, normalizedId)) {
				return parameter;
			}
		}
		for (Variable local : function.getLocalVariables()) {
			if (local != null && matchesLocalId(function, local, normalizedId)) {
				return local;
			}
		}
		// Also search stack frame variables which are stored separately from non-stack locals.
		// Stack variables may have different storage serialization than HighSymbol, so also
		// match by stack offset parsed from the canonical local_id format: "local:Stack[-0xNN]:size:firstUse"
		Integer stackOffset = parseStackOffsetFromLocalId(normalizedId);
		for (Variable stackVar : function.getStackFrame().getStackVariables()) {
			if (stackVar == null) {
				continue;
			}
			if (matchesLocalId(function, stackVar, normalizedId)) {
				return stackVar;
			}
			if (stackOffset != null && stackVar.hasStackStorage() &&
				stackVar.getStackOffset() == stackOffset.intValue()) {
				return stackVar;
			}
		}
		return null;
	}

	private static Integer parseStackOffsetFromLocalId(String localId) {
		// Parse "local:Stack[-0xNN]:size:firstUse" or "local:Stack[0xNN]:size:firstUse"
		if (localId == null || !localId.startsWith("local:Stack[")) {
			return null;
		}
		int bracketStart = localId.indexOf('[');
		int bracketEnd = localId.indexOf(']');
		if (bracketStart < 0 || bracketEnd < 0 || bracketEnd <= bracketStart + 1) {
			return null;
		}
		String offsetStr = localId.substring(bracketStart + 1, bracketEnd).trim();
		try {
			if (offsetStr.startsWith("-0x") || offsetStr.startsWith("-0X")) {
				return -Integer.parseInt(offsetStr.substring(3), 16);
			}
			if (offsetStr.startsWith("0x") || offsetStr.startsWith("0X")) {
				return Integer.parseInt(offsetStr.substring(2), 16);
			}
			return Integer.parseInt(offsetStr);
		} catch (NumberFormatException e) {
			return null;
		}
	}

	static boolean matchesLocalId(Function function, Variable variable, String localId) {
		if (variable == null || localId == null || localId.isBlank()) {
			return false;
		}
		String normalizedId = localId.trim();
		if (normalizedId.equals(variable.getName())) {
			return true;
		}
		return normalizedId.equals(canonicalLocalId(function, variable));
	}

	static boolean matchesLocalId(Function function, HighSymbol symbol, String localId) {
		if (symbol == null || localId == null || localId.isBlank()) {
			return false;
		}
		String normalizedId = localId.trim();
		if (normalizedId.equals(symbol.getName())) {
			return true;
		}
		return normalizedId.equals(canonicalLocalId(function, symbol));
	}

	static String canonicalLocalId(Function function, Variable variable) {
		if (variable == null) {
			return "";
		}
		if (variable instanceof Parameter parameter) {
			return "arg" + parameter.getOrdinal();
		}
		return canonicalLocalId(variable.getVariableStorage(), variable.getFirstUseOffset(), null);
	}

	static String canonicalLocalId(Function function, HighSymbol symbol) {
		if (symbol == null) {
			return "";
		}
		if (symbol.isParameter()) {
			return "arg" + symbol.getCategoryIndex();
		}
		Long symbolId = symbol.getId() != 0 ? Long.valueOf(symbol.getId()) : null;
		return canonicalLocalId(symbol.getStorage(), highSymbolFirstUseOffset(function, symbol), symbolId);
	}

	static String canonicalLocalId(VariableStorage storage, int firstUseOffset, Long symbolId) {
		if (storage != null &&
			!storage.isUnassignedStorage() &&
			!storage.isBadStorage() &&
			!storage.isVoidStorage()) {
			return "local:" + storage.getSerializationString() + ":" + firstUseOffset;
		}
		if (symbolId != null) {
			return "local:id:" + Long.toUnsignedString(symbolId.longValue());
		}
		return "local:anon:" + firstUseOffset;
	}

	static int highSymbolFirstUseOffset(Function function, HighSymbol symbol) {
		if (function == null || symbol == null) {
			return 0;
		}
		Address pcAddress = symbol.getPCAddress();
		if (pcAddress == null) {
			return 0;
		}
		try {
			return (int) pcAddress.subtract(function.getEntryPoint());
		}
		catch (Exception e) {
			return 0;
		}
	}

	private static Integer parseIndexedLocalId(String localId, String prefix) {
		if (localId == null || prefix == null || !localId.startsWith(prefix)) {
			return null;
		}
		String digits = localId.substring(prefix.length()).trim();
		if (digits.isEmpty()) {
			return null;
		}
		for (int i = 0; i < digits.length(); i++) {
			if (!Character.isDigit(digits.charAt(i))) {
				return null;
			}
		}
		try {
			return Integer.parseInt(digits);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}
}
