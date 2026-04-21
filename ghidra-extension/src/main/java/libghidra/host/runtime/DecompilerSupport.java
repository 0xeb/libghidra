package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangVariableToken;
import libghidra.host.contract.DecompilerContract;

final class DecompilerSupport {

	private DecompilerSupport() {
	}

	static String decompileLocalStorage(VariableStorage storage) {
		if (storage == null) {
			return "";
		}
		String rendered = RuntimeSupport.nullableString(storage.toString());
		if (!rendered.isBlank()) {
			return rendered;
		}
		if (!storage.isUnassignedStorage() && !storage.isBadStorage() && !storage.isVoidStorage()) {
			return storage.getSerializationString();
		}
		return "";
	}

	static DecompilerContract.DecompileTokenKind toDecompileTokenKind(int syntaxType) {
		return switch (syntaxType) {
			case 0 -> DecompilerContract.DecompileTokenKind.KEYWORD;
			case 1 -> DecompilerContract.DecompileTokenKind.COMMENT;
			case 2 -> DecompilerContract.DecompileTokenKind.TYPE;
			case 3 -> DecompilerContract.DecompileTokenKind.FUNCTION;
			case 4 -> DecompilerContract.DecompileTokenKind.VARIABLE;
			case 5 -> DecompilerContract.DecompileTokenKind.CONST;
			case 6 -> DecompilerContract.DecompileTokenKind.PARAMETER;
			case 7 -> DecompilerContract.DecompileTokenKind.GLOBAL;
			case 8 -> DecompilerContract.DecompileTokenKind.DEFAULT;
			case 9 -> DecompilerContract.DecompileTokenKind.ERROR;
			case 10 -> DecompilerContract.DecompileTokenKind.SPECIAL;
			default -> DecompilerContract.DecompileTokenKind.UNSPECIFIED;
		};
	}

	static DecompilerContract.DecompileLocalKind toDecompileLocalKind(HighSymbol symbol) {
		if (symbol == null) {
			return DecompilerContract.DecompileLocalKind.UNSPECIFIED;
		}
		if (symbol.isParameter()) {
			return DecompilerContract.DecompileLocalKind.PARAM;
		}
		VariableStorage storage = symbol.getStorage();
		if (storage != null &&
			(storage.isHashStorage() || storage.isUniqueStorage() || storage.isConstantStorage())) {
			return DecompilerContract.DecompileLocalKind.TEMP;
		}
		String name = RuntimeSupport.nullableString(symbol.getName());
		if (name.startsWith("auStack") || name.contains("Var")) {
			return DecompilerContract.DecompileLocalKind.TEMP;
		}
		return DecompilerContract.DecompileLocalKind.LOCAL;
	}

	static List<DecompilerContract.DecompileLocalRecord> buildDecompileLocalRecords(
			Function function,
			HighFunction highFunction) {
		if (function == null || highFunction == null || highFunction.getLocalSymbolMap() == null) {
			return List.of();
		}
		List<DecompilerContract.DecompileLocalRecord> locals = new ArrayList<>();
		Set<String> seen = new HashSet<>();
		Iterator<HighSymbol> iter = highFunction.getLocalSymbolMap().getSymbols();
		while (iter.hasNext()) {
			HighSymbol symbol = iter.next();
			if (symbol == null || symbol.isHiddenReturn()) {
				continue;
			}
			String localId = FunctionSupport.canonicalLocalId(function, symbol);
			if (localId.isBlank() || !seen.add(localId)) {
				continue;
			}
			String name = RuntimeSupport.nullableString(symbol.getName());
			if (name.isBlank()) {
				name = localId;
			}
			DataType dataType = symbol.getDataType();
			String dataTypeName = dataType != null ? RuntimeSupport.nullableString(dataType.getDisplayName()) : "";
			int ordinal = symbol.isParameter() ? symbol.getCategoryIndex() : -1;
			locals.add(new DecompilerContract.DecompileLocalRecord(
				localId,
				toDecompileLocalKind(symbol),
				name,
				dataTypeName,
				decompileLocalStorage(symbol.getStorage()),
				ordinal));
		}
		return locals;
	}

	static List<DecompilerContract.DecompileTokenRecord> buildDecompileTokenRecords(
			DecompileResults results) {
		if (results == null) {
			return List.of();
		}
		ClangTokenGroup codeMarkup = results.getCCodeMarkup();
		if (codeMarkup == null) {
			return List.of();
		}
		List<ClangNode> flatList = new ArrayList<>();
		codeMarkup.flatten(flatList);

		List<DecompilerContract.DecompileTokenRecord> tokens = new ArrayList<>();
		for (ClangNode node : flatList) {
			if (!(node instanceof ClangToken token)) {
				continue;
			}
			String text = RuntimeSupport.nullableString(token.getText());
			if (text.isEmpty()) {
				continue;
			}
			DecompilerContract.DecompileTokenKind kind = toDecompileTokenKind(token.getSyntaxType());
			ClangLine lineParent = token.getLineParent();
			int lineNum = lineParent != null ? lineParent.getLineNumber() : -1;
			int colOffset = -1;
			if (lineParent != null) {
				List<ClangToken> lineTokens = lineParent.getAllTokens();
				colOffset = lineTokens != null ? lineTokens.indexOf(token) : -1;
			}

			String varName = "";
			String varType = "";
			String varStorage = "";
			if (token instanceof ClangVariableToken varToken) {
				try {
					HighVariable highVar = varToken.getHighVariable();
					if (highVar != null) {
						varName = RuntimeSupport.nullableString(highVar.getName());
						DataType dt = highVar.getDataType();
						if (dt != null) {
							varType = RuntimeSupport.nullableString(dt.getDisplayName());
						}
						Varnode rep = highVar.getRepresentative();
						if (rep != null) {
							varStorage = RuntimeSupport.nullableString(rep.getAddress().toString());
						}
					}
				} catch (Exception e) {
					// Variable info unavailable — leave fields empty
				}
			}

			tokens.add(new DecompilerContract.DecompileTokenRecord(
				text, kind, lineNum, colOffset, varName, varType, varStorage));
		}
		return tokens;
	}

	static DecompilerContract.DecompileRecord toDecompileRecord(
			Function function,
			DecompInterface decompiler,
			int timeoutSeconds) {
		if (function == null) {
			return null;
		}

		String functionName = RuntimeSupport.nullableString(function.getName(true));
		String prototype = RuntimeSupport.nullableString(function.getPrototypeString(false, false));
		String pseudocode = "";
		String error = "";
		boolean completed = false;
		boolean isFallback = false;
		List<DecompilerContract.DecompileLocalRecord> locals = List.of();
		List<DecompilerContract.DecompileTokenRecord> tokens = List.of();

		if (function.isExternal()) {
			error = "external function";
		}
		else if (decompiler == null) {
			error = "decompiler unavailable";
		}
		else {
			try {
				DecompileResults results =
					decompiler.decompileFunction(function, timeoutSeconds, TaskMonitor.DUMMY);
				if (results == null) {
					error = "decompiler returned no result";
				}
				else {
					completed = results.decompileCompleted();
					String errorMessage = results.getErrorMessage();
					if (errorMessage != null && !errorMessage.isBlank()) {
						error = errorMessage;
					}
					HighFunction highFunction = results.getHighFunction();
					if (highFunction != null) {
						locals = buildDecompileLocalRecords(function, highFunction);
					}
					tokens = buildDecompileTokenRecords(results);
					if (completed) {
						DecompiledFunction decompiled = results.getDecompiledFunction();
						if (decompiled != null && decompiled.getC() != null && !decompiled.getC().isBlank()) {
							pseudocode = decompiled.getC();
						}
					}
				}
			}
			catch (Exception e) {
				error = e.getMessage() != null ? e.getMessage() : "decompile failed";
			}
		}

		if (pseudocode == null || pseudocode.isBlank()) {
			if (error == null || error.isBlank()) {
				error = "decompile not completed";
			}
			pseudocode = buildDecompileFallback(functionName, error);
			isFallback = true;
		}

		return new DecompilerContract.DecompileRecord(
			function.getEntryPoint().getOffset(),
			functionName,
			prototype,
			pseudocode,
			completed,
			isFallback,
			RuntimeSupport.nullableString(error),
			locals,
			tokens);
	}

	static String buildDecompileFallback(String functionName, String reason) {
		String name = functionName != null && !functionName.isBlank()
				? functionName
				: "sub_unknown";
		StringBuilder text = new StringBuilder(128);
		text.append("void ").append(name).append("(void) {\n");
		text.append("    // ");
		text.append(reason != null && !reason.isBlank()
			? reason.replace('\n', ' ').replace('\r', ' ')
			: "decompile unavailable");
		text.append('\n');
		text.append("}\n");
		return text.toString();
	}

	static int normalizeDecompileTimeoutSeconds(int timeoutMs) {
		if (timeoutMs <= 0) {
			return 30;
		}
		int seconds = timeoutMs / 1000;
		if ((timeoutMs % 1000) != 0) {
			seconds++;
		}
		if (seconds < 1) {
			return 1;
		}
		return Math.min(seconds, 300);
	}

	static DecompInterface createDecompiler(Program program) {
		if (program == null) {
			return null;
		}
		try {
			DecompInterface decompiler = new DecompInterface();
			decompiler.setOptions(new DecompileOptions());
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			if (!decompiler.openProgram(program)) {
				decompiler.dispose();
				return null;
			}
			return decompiler;
		}
		catch (Exception e) {
			return null;
		}
	}
}
