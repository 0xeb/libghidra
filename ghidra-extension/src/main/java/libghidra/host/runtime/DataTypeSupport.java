// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.SignedCharDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Program;

final class DataTypeSupport {

	private DataTypeSupport() {
	}

	static DataType resolveDataTypeById(DataTypeManager dtm, String typeId) {
		if (dtm == null || typeId == null) {
			return null;
		}
		String trimmed = typeId.trim();
		if (trimmed.isEmpty()) {
			return null;
		}
		try {
			long id = Long.parseLong(trimmed);
			DataType byId = dtm.getDataType(id);
			if (byId != null) {
				return byId;
			}
		}
		catch (NumberFormatException ignored) {
		}
		DataType byPath = dtm.getDataType(trimmed);
		if (byPath != null) {
			return byPath;
		}
		return findDataTypeByName(dtm, trimmed);
	}

	static DataType resolveTypeByIdPathOrName(DataTypeManager dtm, String typeIdOrPath) {
		return resolveDataTypeById(dtm, typeIdOrPath);
	}

	static DataType findDataTypeByName(DataTypeManager dtm, String name) {
		if (dtm == null || name == null || name.isBlank()) {
			return null;
		}
		String trimmed = name.trim();
		DataType byPath = dtm.getDataType("/" + trimmed);
		if (byPath != null) {
			return byPath;
		}
		List<DataType> matches = new ArrayList<>();
		dtm.findDataTypes(trimmed, matches);
		return matches.isEmpty() ? null : matches.get(0);
	}

	static String enumMemberNameByOrdinal(ghidra.program.model.data.Enum enumType, long ordinal) {
		if (enumType == null || ordinal < 0) {
			return null;
		}
		String[] names = enumType.getNames();
		int index = (int) ordinal;
		if (index < 0 || index >= names.length) {
			return null;
		}
		return names[index];
	}

	static DataType resolveWritableDataType(Program program, String typeText) {
		if (program == null || typeText == null) {
			return null;
		}
		String requested = typeText.trim();
		if (requested.isEmpty()) {
			return null;
		}

		DataTypeManager manager = program.getDataTypeManager();

		// Peel trailing array dimensions ("char[8]", "int[2][3]", "void *[4]").
		// Dimensions are collected left-to-right and applied right-to-left so
		// int[2][3] becomes array-of-2 of array-of-3 (C array semantics).
		// Without this the array element resolved to null and every array-typed
		// UPDATE (member/local/param/data-item/type-alias) failed -- pointers and
		// cv-qualifiers were handled but arrays were not.
		List<Integer> arrayDims = new ArrayList<>();
		String elementText = requested;
		while (elementText.endsWith("]")) {
			int open = elementText.lastIndexOf('[');
			if (open < 0) {
				return null;
			}
			String inner = elementText.substring(open + 1, elementText.length() - 1).trim();
			int count;
			try {
				count = Integer.parseInt(inner);
			} catch (NumberFormatException e) {
				return null; // non-numeric / flexible "[]" dimensions unsupported
			}
			if (count <= 0) {
				return null;
			}
			arrayDims.add(0, count);
			elementText = elementText.substring(0, open).trim();
		}

		int pointerDepth = 0;
		String baseText = elementText;
		while (baseText.endsWith("*")) {
			pointerDepth++;
			baseText = baseText.substring(0, baseText.length() - 1).trim();
		}
		baseText = stripCvQualifiers(baseText);
		if (baseText.isEmpty()) {
			return null;
		}

		// stdint typedef names (uint32_t, int8_t, ...) resolve typedef-first so the
		// round-trip echoes the requested name: an UPDATE ... SET type='uint32_t'
		// must read back 'uint32_t', not the anonymous builtin 'uint'. The keyword
		// switch below is only for genuine C spellings whose canonical Ghidra
		// primitive name IS the correct echo (int, unsigned int, char, ...).
		DataType base = resolveStdintAliasDataType(manager, baseText);
		if (base == null) {
			base = parseSimpleBaseDataType(baseText);
		}
		if (base == null) {
			base = resolveDataTypeByPathOrName(manager, baseText);
		}
		if (base == null) {
			return null;
		}

		DataType current = base;
		for (int i = 0; i < pointerDepth; i++) {
			current = new PointerDataType(current, manager);
		}

		for (int i = arrayDims.size() - 1; i >= 0; i--) {
			int count = arrayDims.get(i);
			current = new ArrayDataType(current, count, current.getLength(), manager);
		}
		return current;
	}

	static DataType resolveDataTypeByPathOrName(DataTypeManager manager, String typeText) {
		if (manager == null || typeText == null) {
			return null;
		}
		String trimmed = typeText.trim();
		if (trimmed.isEmpty()) {
			return null;
		}

		DataType byPath = manager.getDataType(trimmed);
		if (byPath == null && !trimmed.startsWith("/")) {
			byPath = manager.getDataType("/" + trimmed);
		}
		if (byPath != null) {
			return byPath;
		}

		List<DataType> matches = new ArrayList<>();
		manager.findDataTypes(trimmed, matches);
		if (!matches.isEmpty()) {
			return matches.get(0);
		}

		int slash = trimmed.lastIndexOf('/');
		if (slash >= 0 && slash + 1 < trimmed.length()) {
			String leaf = trimmed.substring(slash + 1);
			matches.clear();
			manager.findDataTypes(leaf, matches);
			if (!matches.isEmpty()) {
				return matches.get(0);
			}
		}
		return null;
	}

	static String stripCvQualifiers(String typeText) {
		if (typeText == null) {
			return "";
		}
		String out = typeText.trim();
		while (true) {
			String lower = out.toLowerCase(Locale.ROOT);
			if (lower.startsWith("const ")) {
				out = out.substring(6).trim();
				continue;
			}
			if (lower.startsWith("volatile ")) {
				out = out.substring(9).trim();
				continue;
			}
			break;
		}
		return out;
	}

	/**
	 * Fixed-width stdint alias names carry typedef identity: resolving them must
	 * echo the requested name on read-back (decomp_lvars.type, function_locals.
	 * local_type, type_members.member_type, data_items.data_type all render the
	 * applied type's display name). Mapping them straight to the anonymous Ghidra
	 * builtin (uint32_t -> uint) silently rewrote the user's type text — the
	 * offline/mock suite and idasql (whose lvar retype goes through a til-backed
	 * C parser that preserves typedef references) both promise textual echo.
	 *
	 * Resolution order:
	 *  1. an exact-named type already in the program DTM (PDB import, parse_decls,
	 *     archive) wins, whatever its definition;
	 *  2. otherwise mint the exact-named typedef onto the same builtin base the
	 *     old keyword mapping used, at the root category — the same place
	 *     parse_decls/CParser puts root-level typedefs. The instance is
	 *     constructed unresolved (like the Pointer/Array wrappers in
	 *     resolveWritableDataType) and is resolved into the program DTM when
	 *     applied; every caller runs inside a program transaction.
	 * Returns null for names that are not stdint aliases.
	 */
	static DataType resolveStdintAliasDataType(DataTypeManager manager, String baseText) {
		if (manager == null || baseText == null) {
			return null;
		}
		String normalized = baseText.trim().toLowerCase(Locale.ROOT);
		DataType builtinBase = stdintAliasBase(normalized);
		if (builtinBase == null) {
			return null;
		}
		DataType existing = resolveDataTypeByPathOrName(manager, normalized);
		if (existing != null) {
			return existing;
		}
		return new TypedefDataType(CategoryPath.ROOT, normalized, builtinBase, manager);
	}

	private static DataType stdintAliasBase(String normalized) {
		switch (normalized) {
			case "int8_t":
				return SignedByteDataType.dataType;
			case "uint8_t":
				return UnsignedCharDataType.dataType;
			case "int16_t":
				return ShortDataType.dataType;
			case "uint16_t":
				return UnsignedShortDataType.dataType;
			case "int32_t":
				return IntegerDataType.dataType;
			case "uint32_t":
				return UnsignedIntegerDataType.dataType;
			case "int64_t":
				return LongLongDataType.dataType;
			case "uint64_t":
				return UnsignedLongLongDataType.dataType;
			default:
				return null;
		}
	}

	static DataType parseSimpleBaseDataType(String typeText) {
		if (typeText == null) {
			return null;
		}
		String normalized = typeText.trim().toLowerCase(Locale.ROOT);
		if (normalized.isEmpty()) {
			return null;
		}

		// C keyword spellings only. The fixed-width stdint alias names (int8_t ...
		// uint64_t) are deliberately ABSENT: they carry typedef identity and are
		// handled typedef-first by resolveStdintAliasDataType (adding them back
		// here would silently rewrite e.g. uint32_t to the anonymous builtin uint).
		//
		// Every unsigned spelling maps to the Unsigned* data type ("unsigned long"
		// and "unsigned long long" used to decay to the SIGNED Long/LongLong
		// builtins — a silent signedness rewrite). "signed char" maps to the
		// char-class SignedCharDataType (schar), not the integer-class sbyte, to
		// mirror C's distinct signed-char character type. The signed-/int-suffixed
		// spellings ("signed int", "long long int", "unsigned long int", ...) are
		// covered so no standard C integer spelling silently falls through to a
		// DTM name lookup that cannot resolve a multi-word keyword form.
		switch (normalized) {
			case "void":
				return VoidDataType.dataType;
			case "bool":
			case "_bool":
				return BooleanDataType.dataType;
			case "char":
				return CharDataType.dataType;
			case "signed char":
				return SignedCharDataType.dataType;
			case "unsigned char":
				return UnsignedCharDataType.dataType;
			case "byte":
				return ByteDataType.dataType;
			case "short":
			case "short int":
			case "signed short":
			case "signed short int":
				return ShortDataType.dataType;
			case "unsigned short":
			case "unsigned short int":
				return UnsignedShortDataType.dataType;
			case "int":
			case "signed":
			case "signed int":
				return IntegerDataType.dataType;
			case "unsigned":
			case "unsigned int":
				return UnsignedIntegerDataType.dataType;
			case "long":
			case "long int":
			case "signed long":
			case "signed long int":
				return LongDataType.dataType;
			case "unsigned long":
			case "unsigned long int":
				return UnsignedLongDataType.dataType;
			case "long long":
			case "long long int":
			case "signed long long":
			case "signed long long int":
			case "int64":
			case "__int64":
				return LongLongDataType.dataType;
			case "unsigned long long":
			case "unsigned long long int":
			case "uint64":
			case "unsigned __int64":
				return UnsignedLongLongDataType.dataType;
			case "float":
				return FloatDataType.dataType;
			case "double":
				return DoubleDataType.dataType;
			default:
				return null;
		}
	}

	static boolean matchesTypeQuery(DataType dataType, String queryLower) {
		if (dataType == null || queryLower == null || queryLower.isEmpty()) {
			return true;
		}
		String name = RuntimeSupport.nullableString(dataType.getName()).toLowerCase(Locale.ROOT);
		String display = RuntimeSupport.nullableString(dataType.getDisplayName()).toLowerCase(Locale.ROOT);
		String path = RuntimeSupport.nullableString(dataType.getPathName()).toLowerCase(Locale.ROOT);
		return name.contains(queryLower) || display.contains(queryLower) || path.contains(queryLower);
	}
}
