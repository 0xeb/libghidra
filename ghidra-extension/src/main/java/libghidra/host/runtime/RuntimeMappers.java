package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableFilter;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import libghidra.host.contract.FunctionsContract;
import libghidra.host.contract.ListingContract;
import libghidra.host.contract.SymbolsContract;
import libghidra.host.contract.TypesContract;
import libghidra.host.contract.XrefsContract;

final class RuntimeMappers {

	private RuntimeMappers() {
	}

	static ListingContract.InstructionRecord toInstructionRecord(Instruction instruction) {
		String mnemonic = instruction.getMnemonicString();
		StringBuilder operands = new StringBuilder();
		int operandCount = instruction.getNumOperands();
		for (int i = 0; i < operandCount; i++) {
			if (i > 0) {
				operands.append(", ");
			}
			operands.append(instruction.getDefaultOperandRepresentation(i));
		}
		return new ListingContract.InstructionRecord(
			instruction.getAddress().getOffset(),
			mnemonic != null ? mnemonic : "",
			operands.toString(),
			instruction.toString(),
			instruction.getLength());
	}

	static FunctionsContract.FunctionRecord toFunctionRecord(Function function) {
		if (function == null) {
			return null;
		}

		long entryAddress = function.getEntryPoint().getOffset();
		long startAddress = entryAddress;
		long endAddress = entryAddress;
		long size = 0L;
		try {
			if (function.getBody() != null && !function.getBody().isEmpty()) {
				startAddress = function.getBody().getMinAddress().getOffset();
				endAddress = function.getBody().getMaxAddress().getOffset();
				size = function.getBody().getNumAddresses();
			}
		}
		catch (RuntimeException e) {
			ghidra.util.Msg.warn(
				RuntimeMappers.class,
				"failed to read function body for 0x" + Long.toHexString(entryAddress) + ": " +
					e.getMessage(),
				e);
		}

		String namespaceName = "";
		try {
			if (function.getParentNamespace() != null) {
				namespaceName = function.getParentNamespace().getName(true);
			}
		}
		catch (RuntimeException e) {
			ghidra.util.Msg.warn(
				RuntimeMappers.class,
				"failed to read namespace for function 0x" + Long.toHexString(entryAddress) + ": " +
					e.getMessage(),
				e);
		}

		String name = "";
		try {
			name = function.getName();
		}
		catch (RuntimeException e) {
			ghidra.util.Msg.warn(
				RuntimeMappers.class,
				"failed to read name for function 0x" + Long.toHexString(entryAddress) + ": " +
					e.getMessage(),
				e);
		}

		String prototype = "";
		try {
			prototype = function.getPrototypeString(false, false);
		}
		catch (RuntimeException e) {
			ghidra.util.Msg.warn(
				RuntimeMappers.class,
				"failed to read prototype for function 0x" + Long.toHexString(entryAddress) + ": " +
					e.getMessage(),
				e);
		}

		boolean isThunk = false;
		try {
			isThunk = function.isThunk();
		}
		catch (RuntimeException e) {
			ghidra.util.Msg.warn(
				RuntimeMappers.class,
				"failed to read thunk state for function 0x" + Long.toHexString(entryAddress) + ": " +
					e.getMessage(),
				e);
		}

		int parameterCount = 0;
		try {
			parameterCount = function.getParameterCount();
		}
		catch (RuntimeException e) {
			ghidra.util.Msg.warn(
				RuntimeMappers.class,
				"failed to read parameter count for function 0x" + Long.toHexString(entryAddress) + ": " +
					e.getMessage(),
				e);
		}

		return new FunctionsContract.FunctionRecord(
			entryAddress,
			name,
			startAddress,
			endAddress,
			size,
			namespaceName != null ? namespaceName : "",
			prototype != null ? prototype : "",
			isThunk,
			parameterCount);
	}

	static SymbolsContract.SymbolRecord toSymbolRecord(Symbol symbol) {
		if (symbol == null || symbol.isDeleted()) {
			return null;
		}
		String fullName = symbol.getName(true);
		String namespaceName = "";
		if (symbol.getParentNamespace() != null) {
			namespaceName = symbol.getParentNamespace().getName(true);
		}
		String typeName = symbol.getSymbolType() != null ? symbol.getSymbolType().toString() : "UNKNOWN";
		String sourceName = symbol.getSource() != null ? symbol.getSource().name() : "UNKNOWN";
		return new SymbolsContract.SymbolRecord(
			symbol.getID(),
			symbol.getAddress().getOffset(),
			symbol.getName(),
			fullName != null ? fullName : "",
			typeName,
			namespaceName != null ? namespaceName : "",
			sourceName,
			symbol.isPrimary(),
			symbol.isExternal(),
			symbol.isDynamic());
	}

	static XrefsContract.XrefRecord toXrefRecord(Reference reference) {
		if (reference == null) {
			return null;
		}
		String typeName = reference.getReferenceType() != null
				? reference.getReferenceType().toString()
				: "UNKNOWN";
		boolean isFlow = reference.getReferenceType() != null && reference.getReferenceType().isFlow();
		String sourceName = reference.getSource() != null ? reference.getSource().name() : "UNKNOWN";
		return new XrefsContract.XrefRecord(
			reference.getFromAddress().getOffset(),
			reference.getToAddress().getOffset(),
			reference.getOperandIndex(),
			typeName,
			reference.isPrimary(),
			sourceName,
			reference.getSymbolID(),
			reference.isExternalReference(),
			reference.isMemoryReference(),
			isFlow);
	}

	static TypesContract.TypeRecord toTypeRecord(DataTypeManager manager, DataType dataType) {
		if (manager == null || dataType == null || dataType.isDeleted()) {
			return null;
		}
		long typeId = manager.getID(dataType);
		String categoryPath = dataType.getCategoryPath() != null
				? dataType.getCategoryPath().getPath()
				: "";
		String sourceArchive = dataType.getSourceArchive() != null
				? dataType.getSourceArchive().getName()
				: "";
		String universalId = dataType.getUniversalID() != null
				? dataType.getUniversalID().toString()
				: "";
		return new TypesContract.TypeRecord(
			typeId,
			RuntimeSupport.nullableString(dataType.getName()),
			RuntimeSupport.nullableString(dataType.getPathName()),
			RuntimeSupport.nullableString(categoryPath),
			RuntimeSupport.nullableString(dataType.getDisplayName()),
			detectTypeKind(dataType),
			dataType.getLength(),
			dataType.isNotYetDefined(),
			RuntimeSupport.nullableString(sourceArchive),
			RuntimeSupport.nullableString(universalId));
	}

	static TypesContract.TypeAliasRecord toTypeAliasRecord(
			DataTypeManager manager,
			TypeDef dataType) {
		if (manager == null || dataType == null || dataType.isDeleted()) {
			return null;
		}
		long typeId = manager.getID(dataType);
		DataType base = dataType.getBaseDataType();
		String targetType = base != null ? RuntimeSupport.nullableString(base.getPathName()) : "";
		return new TypesContract.TypeAliasRecord(
			typeId,
			RuntimeSupport.nullableString(dataType.getPathName()),
			RuntimeSupport.nullableString(dataType.getName()),
			targetType,
			RuntimeSupport.nullableString(dataType.getDisplayName()));
	}

	static TypesContract.TypeUnionRecord toTypeUnionRecord(
			DataTypeManager manager,
			Union dataType) {
		if (manager == null || dataType == null || dataType.isDeleted()) {
			return null;
		}
		long typeId = manager.getID(dataType);
		long size = Math.max(0L, (long) dataType.getLength());
		return new TypesContract.TypeUnionRecord(
			typeId,
			RuntimeSupport.nullableString(dataType.getPathName()),
			RuntimeSupport.nullableString(dataType.getName()),
			size,
			RuntimeSupport.nullableString(dataType.getDisplayName()));
	}

	static TypesContract.TypeEnumRecord toTypeEnumRecord(
			DataTypeManager manager,
			ghidra.program.model.data.Enum dataType) {
		if (manager == null || dataType == null || dataType.isDeleted()) {
			return null;
		}
		long typeId = manager.getID(dataType);
		long width = Math.max(0L, (long) dataType.getLength());
		boolean signed;
		try {
			signed = dataType.isSigned();
		}
		catch (Exception ignored) {
			signed = false;
		}
		return new TypesContract.TypeEnumRecord(
			typeId,
			RuntimeSupport.nullableString(dataType.getPathName()),
			RuntimeSupport.nullableString(dataType.getName()),
			width,
			signed,
			RuntimeSupport.nullableString(dataType.getDisplayName()));
	}

	static int appendTypeEnumMembers(
			List<TypesContract.TypeEnumMemberRecord> out,
			DataTypeManager manager,
			ghidra.program.model.data.Enum enumType,
			int seen,
			int offset,
			int limit) {
		if (out == null || manager == null || enumType == null || enumType.isDeleted()) {
			return seen;
		}
		long typeId = manager.getID(enumType);
		String typePath = RuntimeSupport.nullableString(enumType.getPathName());
		String typeName = RuntimeSupport.nullableString(enumType.getName());
		String[] names = enumType.getNames();
		for (int i = 0; i < names.length; i++) {
			if (seen++ < offset) {
				continue;
			}
			String name = names[i];
			long value = 0L;
			try {
				value = enumType.getValue(name);
			}
			catch (Exception ignored) {
				value = 0L;
			}
			String comment = "";
			try {
				comment = RuntimeSupport.nullableString(enumType.getComment(name));
			}
			catch (Exception ignored) {
			}
			out.add(new TypesContract.TypeEnumMemberRecord(
				typeId,
				typePath,
				typeName,
				i,
				RuntimeSupport.nullableString(name),
				value,
				comment));
			if (out.size() >= limit) {
				break;
			}
		}
		return seen;
	}

	static int appendTypeMembers(
			List<TypesContract.TypeMemberRecord> out,
			DataTypeManager manager,
			Composite composite,
			int seen,
			int offset,
			int limit) {
		if (out == null || manager == null || composite == null || composite.isDeleted()) {
			return seen;
		}
		long parentTypeId = manager.getID(composite);
		String parentPath = RuntimeSupport.nullableString(composite.getPathName());
		String parentName = RuntimeSupport.nullableString(composite.getName());
		DataTypeComponent[] components = composite.getComponents();
		for (int i = 0; i < components.length; i++) {
			DataTypeComponent component = components[i];
			if (component == null) {
				continue;
			}
			if (seen++ < offset) {
				continue;
			}
			String name = RuntimeSupport.nullableString(component.getFieldName());
			if (name.isBlank()) {
				name = "field_" + i;
			}
			DataType memberType = component.getDataType();
			String memberTypePath = memberType != null
					? RuntimeSupport.nullableString(memberType.getPathName())
					: "";
			long size = Math.max(0L, (long) component.getLength());
			String comment = RuntimeSupport.nullableString(component.getComment());
			out.add(new TypesContract.TypeMemberRecord(
				parentTypeId,
				parentPath,
				parentName,
				i,
				name,
				memberTypePath,
				component.getOffset(),
				size,
				comment));
			if (out.size() >= limit) {
				break;
			}
		}
		return seen;
	}

	static TypesContract.FunctionSignatureRecord toFunctionSignatureRecord(Function function) {
		if (function == null) {
			return null;
		}
		String prototype = function.getPrototypeString(false, false);
		String returnType = "";
		DataType returnDataType = function.getReturnType();
		if (returnDataType != null) {
			returnType = RuntimeSupport.nullableString(returnDataType.getPathName());
		}

		List<TypesContract.ParameterRecord> parameters = new ArrayList<>();
		for (Parameter parameter : function.getParameters(VariableFilter.PARAMETER_FILTER)) {
			if (parameter == null) {
				continue;
			}
			DataType effectiveDataType = parameter.getDataType();
			DataType formalDataType = parameter.getFormalDataType();
			parameters.add(new TypesContract.ParameterRecord(
				parameter.getOrdinal(),
				RuntimeSupport.nullableString(parameter.getName()),
				effectiveDataType != null ? RuntimeSupport.nullableString(effectiveDataType.getPathName()) : "",
				formalDataType != null ? RuntimeSupport.nullableString(formalDataType.getPathName()) : "",
				parameter.isAutoParameter(),
				parameter.isForcedIndirect()));
		}

		return new TypesContract.FunctionSignatureRecord(
			function.getEntryPoint().getOffset(),
			RuntimeSupport.nullableString(function.getName()),
			RuntimeSupport.nullableString(prototype),
			returnType,
			function.hasVarArgs(),
			RuntimeSupport.nullableString(function.getCallingConventionName()),
			parameters);
	}

	static void appendCommentIfPresent(
			List<ListingContract.CommentRecord> rows,
			long address,
			ListingContract.CommentKind kind,
			String text) {
		if (rows == null || kind == null || text == null || text.isBlank()) {
			return;
		}
		rows.add(new ListingContract.CommentRecord(address, kind, text));
	}

	private static String detectTypeKind(DataType dataType) {
		if (dataType instanceof TypeDef) {
			return "TYPEDEF";
		}
		if (dataType instanceof Structure) {
			return "STRUCT";
		}
		if (dataType instanceof Union) {
			return "UNION";
		}
		if (dataType instanceof ghidra.program.model.data.Enum) {
			return "ENUM";
		}
		if (dataType instanceof Pointer) {
			return "POINTER";
		}
		if (dataType instanceof Array) {
			return "ARRAY";
		}
		if (dataType instanceof FunctionDefinition) {
			return "FUNCTION_DEF";
		}
		if (dataType instanceof BuiltInDataType) {
			return "BUILTIN";
		}
		return "OTHER";
	}
}
