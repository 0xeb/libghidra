package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

final class FunctionPrototypeSupport {

	private FunctionPrototypeSupport() {
	}

	static boolean applyFunctionPrototype(Program program, Function function, String prototype)
			throws ParseException, CancelledException, InvalidInputException, DuplicateNameException {
		return applyFunctionPrototype(program, function, prototype, null);
	}

	static boolean applyFunctionPrototype(Program program, Function function, String prototype,
			String callingConvention)
			throws ParseException, CancelledException, InvalidInputException, DuplicateNameException {
		if (program == null || function == null || prototype == null || prototype.isBlank()) {
			throw new InvalidInputException("prototype is empty");
		}

		FunctionSignatureParser parser = new FunctionSignatureParser(program.getDataTypeManager(), null);
		FunctionDefinitionDataType parsed = parser.parse(function.getSignature(true), prototype);
		if (parsed == null || parsed.getReturnType() == null) {
			throw new InvalidInputException("prototype parse failed");
		}

		DataTypeManager manager = program.getDataTypeManager();
		ReturnParameterImpl returnParameter =
			new ReturnParameterImpl(parsed.getReturnType().clone(manager), program);

		// Use explicit calling convention if provided, otherwise from parser.
		String convention = callingConvention;
		if (convention == null || convention.isBlank()) {
			convention = parsed.getCallingConventionName();
			if (convention != null && convention.isBlank()) {
				convention = null;
			}
		}

		boolean isThiscall = "__thiscall".equals(convention);
		ParameterDefinition[] args = parsed.getArguments();

		// For __thiscall: the first parameter in the prototype IS the this type.
		// Extract it so updateFunction doesn't create a duplicate void* this.
		DataType thisType = null;
		String thisName = null;
		int startIndex = 0;
		if (isThiscall && args.length > 0 && args[0] != null &&
			args[0].getDataType() instanceof Pointer) {
			thisType = args[0].getDataType().clone(manager);
			thisName = args[0].getName();
			startIndex = 1;
		}

		List<Parameter> parameters = new ArrayList<>();
		for (int i = startIndex; i < args.length; i++) {
			ParameterDefinition arg = args[i];
			if (arg == null || arg.getDataType() == null) {
				throw new InvalidInputException("parameter " + i + " has no data type");
			}
			String paramName = arg.getName();
			if (paramName == null || paramName.isBlank()) {
				paramName = "arg" + (i - startIndex);
			}
			ParameterImpl parameter = new ParameterImpl(
				paramName,
				arg.getDataType().clone(manager),
				program,
				SourceType.USER_DEFINED);
			parameter.setComment(arg.getComment());
			parameters.add(parameter);
		}

		function.updateFunction(
			convention,
			returnParameter,
			parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
			false,
			SourceType.USER_DEFINED);
		function.setVarArgs(parsed.hasVarArgs());

		// Apply the this type after updateFunction created the auto parameter.
		if (thisType != null) {
			Parameter autoThis = function.getParameter(0);
			if (autoThis != null && autoThis.isAutoParameter()) {
				function.setCustomVariableStorage(true);
				autoThis.setDataType(thisType, SourceType.USER_DEFINED);
				if (thisName != null && !thisName.isBlank()) {
					autoThis.setName(thisName, SourceType.USER_DEFINED);
				}
			}
		}

		String parsedName = parsed.getName();
		if (parsedName != null && !parsedName.isBlank() && !parsedName.equals(function.getName())) {
			function.setName(parsedName, SourceType.USER_DEFINED);
		}
		return true;
	}
}
