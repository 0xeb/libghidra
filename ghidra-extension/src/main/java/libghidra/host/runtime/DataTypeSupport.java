package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
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
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
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

		int pointerDepth = 0;
		String baseText = requested;
		while (baseText.endsWith("*")) {
			pointerDepth++;
			baseText = baseText.substring(0, baseText.length() - 1).trim();
		}
		baseText = stripCvQualifiers(baseText);
		if (baseText.isEmpty()) {
			return null;
		}

		DataType base = parseSimpleBaseDataType(baseText);
		DataTypeManager manager = program.getDataTypeManager();
		if (base == null) {
			base = resolveDataTypeByPathOrName(manager, baseText);
		}
		if (base == null) {
			return null;
		}

		if (pointerDepth == 0) {
			return base;
		}

		DataType current = base;
		for (int i = 0; i < pointerDepth; i++) {
			current = new PointerDataType(current, manager);
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

	static DataType parseSimpleBaseDataType(String typeText) {
		if (typeText == null) {
			return null;
		}
		String normalized = typeText.trim().toLowerCase(Locale.ROOT);
		if (normalized.isEmpty()) {
			return null;
		}

		switch (normalized) {
			case "void":
				return VoidDataType.dataType;
			case "bool":
			case "_bool":
				return BooleanDataType.dataType;
			case "char":
				return CharDataType.dataType;
			case "signed char":
			case "int8_t":
				return SignedByteDataType.dataType;
			case "unsigned char":
			case "uint8_t":
				return UnsignedCharDataType.dataType;
			case "byte":
				return ByteDataType.dataType;
			case "short":
			case "short int":
			case "int16_t":
				return ShortDataType.dataType;
			case "unsigned short":
			case "uint16_t":
				return UnsignedShortDataType.dataType;
			case "int":
			case "int32_t":
				return IntegerDataType.dataType;
			case "unsigned":
			case "unsigned int":
			case "uint32_t":
				return UnsignedIntegerDataType.dataType;
			case "long":
			case "long int":
			case "unsigned long":
				return LongDataType.dataType;
			case "long long":
			case "unsigned long long":
			case "int64_t":
			case "int64":
			case "__int64":
				return LongLongDataType.dataType;
			case "uint64_t":
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
