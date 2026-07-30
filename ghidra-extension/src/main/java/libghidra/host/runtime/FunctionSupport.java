// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
		// match by stack offset parsed from the canonical local_id format: "local:Stack[-0xNN]"
		// (parseStackOffsetFromLocalId also tolerates the retired "...:size:firstUse" suffix).
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
		// Parse the offset out of the canonical stack id "local:Stack[-0xNN]" / "local:Stack[0xNN]".
		// Only the bracket content is read, so the retired "...:size:firstUse" suffix still parses.
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
		// Compute the persistent program-DB symbol id for committed (DB-backed) symbols only; it is
		// used solely as the last-resort fallback in the core builder (case 3), NOT as the primary
		// key -- storage-based keying (case 1/2) wins so a local's id survives its first edit.
		// The decompiler assigns uncommitted locals a transient dynamic id of the form
		// ID_BASE + (counter & 0x7fffffff) (Ghidra's LocalSymbolMap.getNextId / GlobalSymbolMap):
		// the counter is masked to 31 bits, so a dynamic id's top byte is invariably 0x40 and can
		// never collide with a real DB key (record keys are small positive longs, nowhere near
		// 2^56). Excluding top-byte-0x40 ids therefore drops exactly the transient ones.
		// The (id >>> 56) test is exact, not a heuristic -- it is the same discriminator Ghidra uses
		// internally (HighSymbol encode ~L386, GlobalSymbolMap.populateSymbol).
		long rawSymbolId = symbol.getId();
		Long dbSymbolId = (rawSymbolId != 0 && (rawSymbolId >>> 56) != (HighSymbol.ID_BASE >>> 56))
			? Long.valueOf(rawSymbolId) : null;
		return canonicalLocalId(symbol.getStorage(), highSymbolFirstUseOffset(function, symbol), dbSymbolId);
	}

	static String canonicalLocalId(VariableStorage storage, int firstUseOffset, Long symbolId) {
		// (1) Stack locals: key on the frame offset ONLY (drop size + firstUseOffset) so the id is
		//     durable across rename AND retype -- set_local_type changes a local's size, not its
		//     stack slot. Stack-first (before the DB-id branch) so a committed stack local keeps its
		//     offset id instead of flipping to a symbol id on its first edit.
		if (storage != null && storage.isStackStorage()) {
			return "local:Stack[" + formatStackOffset(storage.getStackOffset()) + "]";
		}
		// (2) Concrete non-stack storage (register/unique/hash): key on the storage serialization
		//     + firstUse snapshot, PRIORITISED over the DB symbol id. Storage (space:offset:size)
		//     and the first-use PC are properties of the varnode, not of whether the local has yet
		//     been committed to the program DB -- so this id is stable across rename AND
		//     re-decompilation. Storage-first (before the DB-id branch, mirroring the stack case)
		//     is what makes identity survive the first edit: committing a rename via
		//     HighFunctionDBUtil.updateDBVariable assigns the symbol a persistent DB id, and keying
		//     on that id would flip the local_id on its very first rename (e.g.
		//     local:register:00000000:4:237 -> local:id:1106), breaking any follow-up UPDATE that
		//     still references the pre-edit id. Size stays in the key here (unlike the stack case)
		//     because distinct register locals share a register offset and are told apart only by
		//     size (e.g. register:00000000:4 vs register:00000000:8); a same-width retype (the
		//     common decompiler-cleanup case) keeps the id, and a width-changing retype is a rare
		//     structural change that legitimately re-identifies the varnode.
		if (storage != null &&
			!storage.isUnassignedStorage() &&
			!storage.isBadStorage() &&
			!storage.isVoidStorage()) {
			return "local:" + storage.getSerializationString() + ":" + firstUseOffset;
		}
		// (3) No usable storage to key on: fall back to the persistent program-DB symbol id when the
		//     caller determined the symbol is DB-backed. This is the only case where a DB id is used,
		//     and it applies to locals whose storage cannot distinguish them (unassigned/bad/void).
		if (symbolId != null) {
			return "local:id:" + Long.toUnsignedString(symbolId.longValue());
		}
		return "local:anon:" + firstUseOffset;
	}

	private static String formatStackOffset(int offset) {
		// Match Ghidra's VariableStorage stack serialization convention (e.g. -0x10, 0x8),
		// which parseStackOffsetFromLocalId round-trips.
		return offset < 0 ? "-0x" + Integer.toHexString(-offset) : "0x" + Integer.toHexString(offset);
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
