package libghidra.host.runtime;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import libghidra.host.contract.TypesContract;

public final class TypesRuntime extends RuntimeSupport implements TypesOperations {

	public TypesRuntime(HostState state) {
		super(state);
	}

	@Override
	public TypesContract.GetTypeResponse getType(TypesContract.GetTypeRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new TypesContract.GetTypeResponse(null);
			}
			DataTypeManager manager = program.getDataTypeManager();
			String path = request.path() != null ? request.path().trim() : "";
			if (path.isEmpty()) {
				return new TypesContract.GetTypeResponse(null);
			}

			DataType dataType = manager.getDataType(path);
			if (dataType == null) {
				List<DataType> matches = new ArrayList<>();
				manager.findDataTypes(path, matches);
				if (!matches.isEmpty()) {
					dataType = matches.get(0);
				}
			}
			return new TypesContract.GetTypeResponse(RuntimeMappers.toTypeRecord(manager, dataType));
		}
	}

	@Override
	public TypesContract.ListTypesResponse listTypes(TypesContract.ListTypesRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null) {
				return new TypesContract.ListTypesResponse(List.of());
			}
			DataTypeManager manager = program.getDataTypeManager();
			String query = request != null && request.query() != null ? request.query().trim() : "";
			String queryLower = query.toLowerCase(Locale.ROOT);
			int offset = request != null ? Math.max(0, request.offset()) : 0;
			int limit = request != null && request.limit() > 0 ? request.limit() : 512;

			List<TypesContract.TypeRecord> rows = new ArrayList<>();
			int seen = 0;
			var it = manager.getAllDataTypes();
			while (it.hasNext()) {
				DataType dataType = it.next();
				if (dataType == null || dataType.isDeleted()) {
					continue;
				}
				if (!queryLower.isEmpty() && !DataTypeSupport.matchesTypeQuery(dataType, queryLower)) {
					continue;
				}
				if (seen++ < offset) {
					continue;
				}
				rows.add(RuntimeMappers.toTypeRecord(manager, dataType));
				if (rows.size() >= limit) {
					break;
				}
			}
			return new TypesContract.ListTypesResponse(rows);
		}
	}

	@Override
	public TypesContract.ListTypeAliasesResponse listTypeAliases(
			TypesContract.ListTypeAliasesRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null) {
				return new TypesContract.ListTypeAliasesResponse(List.of());
			}
			DataTypeManager manager = program.getDataTypeManager();
			String query = request != null && request.query() != null ? request.query().trim() : "";
			String queryLower = query.toLowerCase(Locale.ROOT);
			int offset = request != null ? Math.max(0, request.offset()) : 0;
			int limit = request != null && request.limit() > 0 ? request.limit() : 512;

			List<TypesContract.TypeAliasRecord> rows = new ArrayList<>();
			int seen = 0;
			var it = manager.getAllDataTypes();
			while (it.hasNext()) {
				DataType dataType = it.next();
				if (dataType == null || dataType.isDeleted() || !(dataType instanceof TypeDef)) {
					continue;
				}
				if (!queryLower.isEmpty() && !DataTypeSupport.matchesTypeQuery(dataType, queryLower)) {
					continue;
				}
				if (seen++ < offset) {
					continue;
				}
				rows.add(RuntimeMappers.toTypeAliasRecord(manager, (TypeDef) dataType));
				if (rows.size() >= limit) {
					break;
				}
			}
			return new TypesContract.ListTypeAliasesResponse(rows);
		}
	}

	@Override
	public TypesContract.ListTypeUnionsResponse listTypeUnions(
			TypesContract.ListTypeUnionsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null) {
				return new TypesContract.ListTypeUnionsResponse(List.of());
			}
			DataTypeManager manager = program.getDataTypeManager();
			String query = request != null && request.query() != null ? request.query().trim() : "";
			String queryLower = query.toLowerCase(Locale.ROOT);
			int offset = request != null ? Math.max(0, request.offset()) : 0;
			int limit = request != null && request.limit() > 0 ? request.limit() : 512;

			List<TypesContract.TypeUnionRecord> rows = new ArrayList<>();
			int seen = 0;
			var it = manager.getAllDataTypes();
			while (it.hasNext()) {
				DataType dataType = it.next();
				if (dataType == null || dataType.isDeleted() || !(dataType instanceof Union)) {
					continue;
				}
				if (!queryLower.isEmpty() && !DataTypeSupport.matchesTypeQuery(dataType, queryLower)) {
					continue;
				}
				if (seen++ < offset) {
					continue;
				}
				rows.add(RuntimeMappers.toTypeUnionRecord(manager, (Union) dataType));
				if (rows.size() >= limit) {
					break;
				}
			}
			return new TypesContract.ListTypeUnionsResponse(rows);
		}
	}

	@Override
	public TypesContract.ListTypeEnumsResponse listTypeEnums(
			TypesContract.ListTypeEnumsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null) {
				return new TypesContract.ListTypeEnumsResponse(List.of());
			}
			DataTypeManager manager = program.getDataTypeManager();
			String query = request != null && request.query() != null ? request.query().trim() : "";
			String queryLower = query.toLowerCase(Locale.ROOT);
			int offset = request != null ? Math.max(0, request.offset()) : 0;
			int limit = request != null && request.limit() > 0 ? request.limit() : 512;

			List<TypesContract.TypeEnumRecord> rows = new ArrayList<>();
			int seen = 0;
			var it = manager.getAllDataTypes();
			while (it.hasNext()) {
				DataType dataType = it.next();
				if (dataType == null || dataType.isDeleted() ||
					!(dataType instanceof ghidra.program.model.data.Enum)) {
					continue;
				}
				if (!queryLower.isEmpty() && !DataTypeSupport.matchesTypeQuery(dataType, queryLower)) {
					continue;
				}
				if (seen++ < offset) {
					continue;
				}
				rows.add(RuntimeMappers.toTypeEnumRecord(
					manager,
					(ghidra.program.model.data.Enum) dataType));
				if (rows.size() >= limit) {
					break;
				}
			}
			return new TypesContract.ListTypeEnumsResponse(rows);
		}
	}

	@Override
	public TypesContract.ListTypeEnumMembersResponse listTypeEnumMembers(
			TypesContract.ListTypeEnumMembersRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null) {
				return new TypesContract.ListTypeEnumMembersResponse(List.of());
			}
			DataTypeManager manager = program.getDataTypeManager();
			String typeFilter = request != null && request.type() != null ? request.type().trim() : "";
			int offset = request != null ? Math.max(0, request.offset()) : 0;
			int limit = request != null && request.limit() > 0 ? request.limit() : 512;

			List<TypesContract.TypeEnumMemberRecord> rows = new ArrayList<>();
			int seen = 0;

			DataType specificType = typeFilter.isEmpty()
					? null
					: DataTypeSupport.resolveTypeByIdPathOrName(manager, typeFilter);
			if (specificType != null) {
				if (specificType instanceof ghidra.program.model.data.Enum) {
					RuntimeMappers.appendTypeEnumMembers(
						rows,
						manager,
						(ghidra.program.model.data.Enum) specificType,
						seen,
						offset,
						limit);
				}
				return new TypesContract.ListTypeEnumMembersResponse(rows);
			}

			var it = manager.getAllDataTypes();
			while (it.hasNext()) {
				DataType dataType = it.next();
				if (dataType == null || dataType.isDeleted() ||
					!(dataType instanceof ghidra.program.model.data.Enum)) {
					continue;
				}
				seen = RuntimeMappers.appendTypeEnumMembers(
					rows,
					manager,
					(ghidra.program.model.data.Enum) dataType,
					seen,
					offset,
					limit);
				if (rows.size() >= limit) {
					break;
				}
			}
			return new TypesContract.ListTypeEnumMembersResponse(rows);
		}
	}

	@Override
	public TypesContract.ListTypeMembersResponse listTypeMembers(
			TypesContract.ListTypeMembersRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null) {
				return new TypesContract.ListTypeMembersResponse(List.of());
			}
			DataTypeManager manager = program.getDataTypeManager();
			String typeFilter = request != null && request.type() != null ? request.type().trim() : "";
			int offset = request != null ? Math.max(0, request.offset()) : 0;
			int limit = request != null && request.limit() > 0 ? request.limit() : 512;

			List<TypesContract.TypeMemberRecord> rows = new ArrayList<>();
			int seen = 0;

			DataType specificType = typeFilter.isEmpty()
					? null
					: DataTypeSupport.resolveTypeByIdPathOrName(manager, typeFilter);
			if (specificType != null) {
				if (specificType instanceof Composite) {
					RuntimeMappers.appendTypeMembers(
						rows,
						manager,
						(Composite) specificType,
						seen,
						offset,
						limit);
				}
				return new TypesContract.ListTypeMembersResponse(rows);
			}

			var it = manager.getAllDataTypes();
			while (it.hasNext()) {
				DataType dataType = it.next();
				if (dataType == null || dataType.isDeleted() || !(dataType instanceof Composite)) {
					continue;
				}
				seen = RuntimeMappers.appendTypeMembers(
					rows,
					manager,
					(Composite) dataType,
					seen,
					offset,
					limit);
				if (rows.size() >= limit) {
					break;
				}
			}
			return new TypesContract.ListTypeMembersResponse(rows);
		}
	}

	@Override
	public TypesContract.GetFunctionSignatureResponse getFunctionSignature(
			TypesContract.GetFunctionSignatureRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new TypesContract.GetFunctionSignatureResponse(null);
			}
			try {
				Address address = toAddress(program, request.address());
				Function function = program.getFunctionManager().getFunctionContaining(address);
				return new TypesContract.GetFunctionSignatureResponse(
					RuntimeMappers.toFunctionSignatureRecord(function));
			}
			catch (IllegalArgumentException e) {
				return new TypesContract.GetFunctionSignatureResponse(null);
			}
		}
	}

	@Override
	public TypesContract.ListFunctionSignaturesResponse listFunctionSignatures(
			TypesContract.ListFunctionSignaturesRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null) {
				return new TypesContract.ListFunctionSignaturesResponse(List.of());
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
					return new TypesContract.ListFunctionSignaturesResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 512;

				FunctionManager functionManager = program.getFunctionManager();
				Address start = toAddress(program, startOffset);
				FunctionIterator it = functionManager.getFunctions(start, true);
				List<TypesContract.FunctionSignatureRecord> rows = new ArrayList<>();
				int seen = 0;
				while (it.hasNext()) {
					Function function = it.next();
					if (function == null) {
						continue;
					}
					long address = function.getEntryPoint().getOffset();
					if (address < startOffset) {
						continue;
					}
					if (address > endOffset) {
						break;
					}
					if (seen++ < offset) {
						continue;
					}
					rows.add(RuntimeMappers.toFunctionSignatureRecord(function));
					if (rows.size() >= limit) {
						break;
					}
				}
				return new TypesContract.ListFunctionSignaturesResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new TypesContract.ListFunctionSignaturesResponse(List.of());
			}
		}
	}

	@Override
	public TypesContract.SetFunctionSignatureResponse setFunctionSignature(
			TypesContract.SetFunctionSignatureRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new TypesContract.SetFunctionSignatureResponse(
					false, "", "", "not_loaded", "no current program");
			}
			String prototype = request.prototype() != null ? request.prototype().trim() : "";
			if (prototype.isEmpty()) {
				return new TypesContract.SetFunctionSignatureResponse(
					false, "", "", "invalid_argument", "prototype is empty");
			}
			int tx = program.startTransaction("libghidra set function signature");
			boolean commit = false;
			try {
				Function function = FunctionSupport.resolveFunction(program, request.address());
				if (function == null) {
					return new TypesContract.SetFunctionSignatureResponse(
						false,
						"",
						"",
						"not_found",
						"function not found at 0x" + Long.toHexString(request.address()));
				}
				String convention = request.callingConvention();
				if (convention != null && !convention.isBlank()) {
					convention = convention.trim();
				} else {
					convention = null;
				}
				if (!FunctionPrototypeSupport.applyFunctionPrototype(
						program, function, prototype, convention)) {
					return new TypesContract.SetFunctionSignatureResponse(
						false,
						"",
						"",
						"apply_error",
						"function prototype was not applied");
				}
				bumpRevision();
				commit = true;
				return new TypesContract.SetFunctionSignatureResponse(
					true,
					nullableString(function.getName()),
					nullableString(function.getPrototypeString(false, false)),
					"",
					"");
			}
			catch (ParseException | CancelledException | InvalidInputException |
				DuplicateNameException | IllegalArgumentException e) {
				Msg.error(this, "setFunctionSignature failed: " + e.getMessage(), e);
				String code = e instanceof ParseException ? "parse_error" :
					e instanceof DuplicateNameException ? "duplicate_name" :
					e instanceof CancelledException ? "cancelled" :
					"invalid_argument";
				return new TypesContract.SetFunctionSignatureResponse(
					false,
					"",
					"",
					code,
					nullableString(e.getMessage()));
			}
			finally {
				program.endTransaction(tx, commit);
				if (commit) {
					flushProgramEvents(program);
				}
			}
		}
	}

	@Override
	public TypesContract.RenameFunctionParameterResponse renameFunctionParameter(
			TypesContract.RenameFunctionParameterRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null || request.ordinal() < 0) {
				return new TypesContract.RenameFunctionParameterResponse(
					false, "", "invalid_argument", "invalid function parameter request");
			}
			String newName = request.newName() != null ? request.newName().trim() : "";
			if (newName.isEmpty()) {
				return new TypesContract.RenameFunctionParameterResponse(
					false, "", "invalid_argument", "parameter name is empty");
			}
			int tx = program.startTransaction("libghidra rename function parameter");
			boolean commit = false;
			try {
				Parameter parameter = FunctionSupport.resolveFunctionParameter(
					program,
					request.address(),
					request.ordinal());
				if (parameter == null) {
					return new TypesContract.RenameFunctionParameterResponse(
						false,
						"",
						"not_found",
						"parameter " + request.ordinal() + " not found for function 0x" +
							Long.toHexString(request.address()));
				}
				parameter.setName(newName, SourceType.USER_DEFINED);
				bumpRevision();
				commit = true;
				return new TypesContract.RenameFunctionParameterResponse(
					true,
					nullableString(parameter.getName()),
					"",
					"");
			}
			catch (InvalidInputException | DuplicateNameException | IllegalArgumentException e) {
				Msg.error(this, "renameFunctionParameter failed: " + e.getMessage(), e);
				String code = e instanceof DuplicateNameException ? "duplicate_name" : "invalid_argument";
				return new TypesContract.RenameFunctionParameterResponse(
					false,
					"",
					code,
					nullableString(e.getMessage()));
			}
			finally {
				program.endTransaction(tx, commit);
				if (commit) {
					flushProgramEvents(program);
				}
			}
		}
	}

	@Override
	public TypesContract.SetFunctionParameterTypeResponse setFunctionParameterType(
			TypesContract.SetFunctionParameterTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null || request.ordinal() < 0) {
				return new TypesContract.SetFunctionParameterTypeResponse(
					false, "", "invalid_argument", "invalid function parameter type request");
			}
			String requestedType = request.dataType() != null ? request.dataType().trim() : "";
			if (requestedType.isEmpty()) {
				return new TypesContract.SetFunctionParameterTypeResponse(
					false, "", "invalid_argument", "parameter type is empty");
			}
			int tx = program.startTransaction("libghidra set function parameter type");
			boolean commit = false;
			try {
				Parameter parameter = FunctionSupport.resolveFunctionParameter(
					program,
					request.address(),
					request.ordinal());
				if (parameter == null) {
					return new TypesContract.SetFunctionParameterTypeResponse(
						false,
						"",
						"not_found",
						"parameter " + request.ordinal() + " not found for function 0x" +
							Long.toHexString(request.address()));
				}
				DataType parsed = DataTypeSupport.resolveWritableDataType(program, requestedType);
				if (parsed == null) {
					return new TypesContract.SetFunctionParameterTypeResponse(
						false,
						"",
						"unknown_type",
						"unable to resolve writable data type '" + requestedType + "'");
				}
				parameter.setDataType(parsed, SourceType.USER_DEFINED);
				bumpRevision();
				commit = true;
				return new TypesContract.SetFunctionParameterTypeResponse(
					true,
					nullableString(parameter.getDataType().getPathName()),
					"",
					"");
			}
			catch (InvalidInputException | IllegalArgumentException e) {
				Msg.error(this, "setFunctionParameterType failed: " + e.getMessage(), e);
				return new TypesContract.SetFunctionParameterTypeResponse(
					false,
					"",
					"invalid_argument",
					nullableString(e.getMessage()));
			}
			finally {
				program.endTransaction(tx, commit);
				if (commit) {
					flushProgramEvents(program);
				}
			}
		}
	}

	@Override
	public TypesContract.RenameFunctionLocalResponse renameFunctionLocal(
			TypesContract.RenameFunctionLocalRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new TypesContract.RenameFunctionLocalResponse(
					false, "", "", "not_loaded", "no current program");
			}
			String localId = request.localId() != null ? request.localId().trim() : "";
			String newName = request.newName() != null ? request.newName().trim() : "";
			if (localId.isEmpty() || newName.isEmpty()) {
				return new TypesContract.RenameFunctionLocalResponse(
					false, "", "", "invalid_argument", "local id or new name is empty");
			}
			int tx = program.startTransaction("libghidra rename function local");
			boolean commit = false;
			try {
				Variable variable = FunctionSupport.resolveFunctionVariable(program, request.address(), localId);
				if (variable != null) {
					variable.setName(newName, SourceType.USER_DEFINED);
					bumpRevision();
					commit = true;
					return new TypesContract.RenameFunctionLocalResponse(
						true,
						localId,
						nullableString(variable.getName()),
						"",
						"");
				}
				boolean renamed = FunctionVariableMutationSupport.decompileAndRenameHighVariable(
					program,
					request.address(),
					localId,
					newName);
				if (!renamed) {
					return new TypesContract.RenameFunctionLocalResponse(
						false,
						localId,
						"",
						"not_found",
						"local '" + localId + "' not found for function 0x" +
							Long.toHexString(request.address()));
				}
				bumpRevision();
				commit = true;
				return new TypesContract.RenameFunctionLocalResponse(
					true, localId, newName, "", "");
			}
			catch (InvalidInputException | DuplicateNameException | IllegalArgumentException e) {
				Msg.error(this, "renameFunctionLocal failed: " + e.getMessage(), e);
				String code = e instanceof DuplicateNameException ? "duplicate_name" : "invalid_argument";
				return new TypesContract.RenameFunctionLocalResponse(
					false,
					localId,
					"",
					code,
					nullableString(e.getMessage()));
			}
			finally {
				program.endTransaction(tx, commit);
				if (commit) {
					flushProgramEvents(program);
				}
			}
		}
	}

	@Override
	public TypesContract.SetFunctionLocalTypeResponse setFunctionLocalType(
			TypesContract.SetFunctionLocalTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new TypesContract.SetFunctionLocalTypeResponse(
					false, "", "", "not_loaded", "no current program");
			}
			String localId = request.localId() != null ? request.localId().trim() : "";
			String requestedType = request.dataType() != null ? request.dataType().trim() : "";
			if (localId.isEmpty() || requestedType.isEmpty()) {
				return new TypesContract.SetFunctionLocalTypeResponse(
					false, "", "", "invalid_argument", "local id or data type is empty");
			}
			int tx = program.startTransaction("libghidra set function local type");
			boolean commit = false;
			try {
				DataType parsed = DataTypeSupport.resolveWritableDataType(program, requestedType);
				if (parsed == null) {
					return new TypesContract.SetFunctionLocalTypeResponse(
						false,
						localId,
						"",
						"unknown_type",
						"unable to resolve writable data type '" + requestedType + "'");
				}
				Variable variable = FunctionSupport.resolveFunctionVariable(program, request.address(), localId);
				if (variable != null) {
					variable.setDataType(parsed, SourceType.USER_DEFINED);
					bumpRevision();
					commit = true;
					return new TypesContract.SetFunctionLocalTypeResponse(
						true,
						localId,
						nullableString(variable.getDataType().getPathName()),
						"",
						"");
				}
				String appliedType = FunctionVariableMutationSupport.decompileAndRetypeHighVariable(
					program,
					request.address(),
					localId,
					parsed);
				if (appliedType == null) {
					return new TypesContract.SetFunctionLocalTypeResponse(
						false,
						localId,
						"",
						"not_found",
						"local '" + localId + "' not found for function 0x" +
							Long.toHexString(request.address()));
				}
				bumpRevision();
				commit = true;
				return new TypesContract.SetFunctionLocalTypeResponse(
					true, localId, appliedType, "", "");
			}
			catch (InvalidInputException | DuplicateNameException | IllegalArgumentException e) {
				Msg.error(this, "setFunctionLocalType failed: " + e.getMessage(), e);
				String code = e instanceof DuplicateNameException ? "duplicate_name" : "invalid_argument";
				return new TypesContract.SetFunctionLocalTypeResponse(
					false,
					localId,
					"",
					code,
					nullableString(e.getMessage()));
			}
			finally {
				program.endTransaction(tx, commit);
				if (commit) {
					flushProgramEvents(program);
				}
			}
		}
	}

	@Override
	public TypesContract.ApplyDataTypeResponse applyDataType(TypesContract.ApplyDataTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new TypesContract.ApplyDataTypeResponse(false, "");
			}
			String requestedType = request.dataType() != null ? request.dataType().trim() : "";
			if (requestedType.isEmpty()) {
				return new TypesContract.ApplyDataTypeResponse(false, "");
			}
			int tx = program.startTransaction("libghidra apply data type");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				Listing listing = program.getListing();
				Data data = listing.getDataAt(address);
				if (data == null) {
					return new TypesContract.ApplyDataTypeResponse(false, "");
				}
				DataType parsed = DataTypeSupport.resolveWritableDataType(program, requestedType);
				if (parsed == null) {
					return new TypesContract.ApplyDataTypeResponse(false, "");
				}
				Address clearEnd = data.getMaxAddress();
				int parsedLength = parsed.getLength();
				if (parsedLength > 0) {
					Address parsedEnd = address.addNoWrap(parsedLength - 1L);
					if (parsedEnd.compareTo(clearEnd) > 0) {
						clearEnd = parsedEnd;
					}
				}
				listing.clearCodeUnits(address, clearEnd, false);
				listing.createData(address, parsed);
				bumpRevision();
				commit = true;
				Data reapplied = listing.getDataAt(address);
				String appliedPath = reapplied != null && reapplied.getDataType() != null
						? nullableString(reapplied.getDataType().getPathName())
						: "";
				return new TypesContract.ApplyDataTypeResponse(true, appliedPath);
			}
			catch (AddressOverflowException | IllegalArgumentException |
				ghidra.program.model.util.CodeUnitInsertionException e) {
				Msg.error(this, "applyDataType failed: " + e.getMessage(), e);
				return new TypesContract.ApplyDataTypeResponse(false, "");
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.CreateTypeResponse createType(TypesContract.CreateTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new TypesContract.CreateTypeResponse(false);
			}
			String name = nullableString(request.name()).trim();
			String kind = nullableString(request.kind()).trim().toLowerCase(Locale.ROOT);
			if (name.isEmpty() || kind.isEmpty()) {
				return new TypesContract.CreateTypeResponse(false);
			}
			int tx = program.startTransaction("libghidra create type");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				if (DataTypeSupport.findDataTypeByName(dtm, name) != null) {
					return new TypesContract.CreateTypeResponse(false);
				}
				DataType dataType;
				switch (kind) {
					case "struct":
						dataType = new ghidra.program.model.data.StructureDataType(
							name,
							Math.max(0, (int) request.size()));
						break;
					case "enum":
						int width = (int) Math.max(1L, Math.min(8L, request.size() <= 0 ? 4 : request.size()));
						dataType = new ghidra.program.model.data.EnumDataType(name, width);
						break;
					case "union":
						dataType = new ghidra.program.model.data.UnionDataType(name);
						break;
					default:
						return new TypesContract.CreateTypeResponse(false);
				}
				dtm.addDataType(
					dataType,
					ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
				bumpRevision();
				commit = true;
				return new TypesContract.CreateTypeResponse(true);
			}
			catch (IllegalArgumentException e) {
				Msg.error(this, "createType failed: " + e.getMessage(), e);
				return new TypesContract.CreateTypeResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.DeleteTypeResponse deleteType(TypesContract.DeleteTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null || nullableString(request.type()).isBlank()) {
				return new TypesContract.DeleteTypeResponse(false);
			}
			int tx = program.startTransaction("libghidra delete type");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (dataType == null) {
					return new TypesContract.DeleteTypeResponse(false);
				}
				dtm.remove(dataType);
				bumpRevision();
				commit = true;
				return new TypesContract.DeleteTypeResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "deleteType failed: " + e.getMessage(), e);
				return new TypesContract.DeleteTypeResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.RenameTypeResponse renameType(TypesContract.RenameTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				nullableString(request.newName()).isBlank()) {
				return new TypesContract.RenameTypeResponse(false, "");
			}
			int tx = program.startTransaction("libghidra rename type");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (dataType == null) {
					return new TypesContract.RenameTypeResponse(false, "");
				}
				String newName = request.newName().trim();
				dataType.setName(newName);
				bumpRevision();
				commit = true;
				return new TypesContract.RenameTypeResponse(true, newName);
			}
			catch (Exception e) {
				Msg.error(this, "renameType failed: " + e.getMessage(), e);
				return new TypesContract.RenameTypeResponse(false, "");
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.CreateTypeAliasResponse createTypeAlias(
			TypesContract.CreateTypeAliasRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.name()).isBlank() ||
				nullableString(request.targetType()).isBlank()) {
				return new TypesContract.CreateTypeAliasResponse(false);
			}
			String name = request.name().trim();
			int tx = program.startTransaction("libghidra create type alias");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				if (DataTypeSupport.findDataTypeByName(dtm, name) != null) {
					return new TypesContract.CreateTypeAliasResponse(false);
				}
				DataType target = DataTypeSupport.resolveWritableDataType(program, request.targetType());
				if (target == null) {
					return new TypesContract.CreateTypeAliasResponse(false);
				}
				DataType alias = new ghidra.program.model.data.TypedefDataType(name, target);
				dtm.addDataType(
					alias,
					ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
				bumpRevision();
				commit = true;
				return new TypesContract.CreateTypeAliasResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "createTypeAlias failed: " + e.getMessage(), e);
				return new TypesContract.CreateTypeAliasResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.DeleteTypeAliasResponse deleteTypeAlias(
			TypesContract.DeleteTypeAliasRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null || nullableString(request.type()).isBlank()) {
				return new TypesContract.DeleteTypeAliasResponse(false);
			}
			int tx = program.startTransaction("libghidra delete type alias");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof TypeDef)) {
					return new TypesContract.DeleteTypeAliasResponse(false);
				}
				dtm.remove(dataType);
				bumpRevision();
				commit = true;
				return new TypesContract.DeleteTypeAliasResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "deleteTypeAlias failed: " + e.getMessage(), e);
				return new TypesContract.DeleteTypeAliasResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.SetTypeAliasTargetResponse setTypeAliasTarget(
			TypesContract.SetTypeAliasTargetRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				nullableString(request.targetType()).isBlank()) {
				return new TypesContract.SetTypeAliasTargetResponse(false);
			}
			int tx = program.startTransaction("libghidra set type alias target");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof TypeDef)) {
					return new TypesContract.SetTypeAliasTargetResponse(false);
				}
				DataType target = DataTypeSupport.resolveWritableDataType(program, request.targetType());
				if (target == null) {
					return new TypesContract.SetTypeAliasTargetResponse(false);
				}
				DataType currentBase = ((TypeDef) dataType).getBaseDataType();
				if (currentBase != null && currentBase.isEquivalent(target)) {
					return new TypesContract.SetTypeAliasTargetResponse(true);
				}
				ghidra.program.model.data.TypedefDataType replacement =
					new ghidra.program.model.data.TypedefDataType(
						dataType.getCategoryPath(),
						dataType.getName(),
						target,
						dtm);
				dtm.replaceDataType(dataType, replacement, true);
				bumpRevision();
				commit = true;
				return new TypesContract.SetTypeAliasTargetResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "setTypeAliasTarget failed: " + e.getMessage(), e);
				return new TypesContract.SetTypeAliasTargetResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.CreateTypeEnumResponse createTypeEnum(
			TypesContract.CreateTypeEnumRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null || nullableString(request.name()).isBlank()) {
				return new TypesContract.CreateTypeEnumResponse(false);
			}
			String name = request.name().trim();
			int width = (int) Math.max(1L, Math.min(8L, request.width() <= 0 ? 4 : request.width()));
			int tx = program.startTransaction("libghidra create enum");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				if (DataTypeSupport.findDataTypeByName(dtm, name) != null) {
					return new TypesContract.CreateTypeEnumResponse(false);
				}
				ghidra.program.model.data.EnumDataType enumType =
					new ghidra.program.model.data.EnumDataType(name, width);
				if (request.signed()) {
					enumType.setDescription("signed");
				}
				dtm.addDataType(
					enumType,
					ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
				bumpRevision();
				commit = true;
				return new TypesContract.CreateTypeEnumResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "createTypeEnum failed: " + e.getMessage(), e);
				return new TypesContract.CreateTypeEnumResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.DeleteTypeEnumResponse deleteTypeEnum(
			TypesContract.DeleteTypeEnumRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null || nullableString(request.type()).isBlank()) {
				return new TypesContract.DeleteTypeEnumResponse(false);
			}
			int tx = program.startTransaction("libghidra delete enum");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof ghidra.program.model.data.Enum)) {
					return new TypesContract.DeleteTypeEnumResponse(false);
				}
				dtm.remove(dataType);
				bumpRevision();
				commit = true;
				return new TypesContract.DeleteTypeEnumResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "deleteTypeEnum failed: " + e.getMessage(), e);
				return new TypesContract.DeleteTypeEnumResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.AddTypeEnumMemberResponse addTypeEnumMember(
			TypesContract.AddTypeEnumMemberRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				nullableString(request.name()).isBlank()) {
				return new TypesContract.AddTypeEnumMemberResponse(false);
			}
			int tx = program.startTransaction("libghidra add enum member");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof ghidra.program.model.data.Enum)) {
					return new TypesContract.AddTypeEnumMemberResponse(false);
				}
				ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
				String nextName = request.name().trim();
				for (String existing : enumType.getNames()) {
					if (nextName.equals(existing)) {
						return new TypesContract.AddTypeEnumMemberResponse(false);
					}
				}
				enumType.add(nextName, request.value());
				bumpRevision();
				commit = true;
				return new TypesContract.AddTypeEnumMemberResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "addTypeEnumMember failed: " + e.getMessage(), e);
				return new TypesContract.AddTypeEnumMemberResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.DeleteTypeEnumMemberResponse deleteTypeEnumMember(
			TypesContract.DeleteTypeEnumMemberRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				request.ordinal() < 0) {
				return new TypesContract.DeleteTypeEnumMemberResponse(false);
			}
			int tx = program.startTransaction("libghidra delete enum member");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof ghidra.program.model.data.Enum)) {
					return new TypesContract.DeleteTypeEnumMemberResponse(false);
				}
				ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
				String memberName = DataTypeSupport.enumMemberNameByOrdinal(enumType, request.ordinal());
				if (memberName == null) {
					return new TypesContract.DeleteTypeEnumMemberResponse(false);
				}
				enumType.remove(memberName);
				bumpRevision();
				commit = true;
				return new TypesContract.DeleteTypeEnumMemberResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "deleteTypeEnumMember failed: " + e.getMessage(), e);
				return new TypesContract.DeleteTypeEnumMemberResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.RenameTypeEnumMemberResponse renameTypeEnumMember(
			TypesContract.RenameTypeEnumMemberRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				nullableString(request.newName()).isBlank() ||
				request.ordinal() < 0) {
				return new TypesContract.RenameTypeEnumMemberResponse(false);
			}
			int tx = program.startTransaction("libghidra rename enum member");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof ghidra.program.model.data.Enum)) {
					return new TypesContract.RenameTypeEnumMemberResponse(false);
				}
				ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
				String oldName = DataTypeSupport.enumMemberNameByOrdinal(enumType, request.ordinal());
				String nextName = request.newName().trim();
				if (oldName == null || nextName.isEmpty() || oldName.equals(nextName)) {
					return new TypesContract.RenameTypeEnumMemberResponse(false);
				}
				for (String existing : enumType.getNames()) {
					if (nextName.equals(existing)) {
						return new TypesContract.RenameTypeEnumMemberResponse(false);
					}
				}
				long value = enumType.getValue(oldName);
				enumType.remove(oldName);
				enumType.add(nextName, value);
				bumpRevision();
				commit = true;
				return new TypesContract.RenameTypeEnumMemberResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "renameTypeEnumMember failed: " + e.getMessage(), e);
				return new TypesContract.RenameTypeEnumMemberResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.SetTypeEnumMemberValueResponse setTypeEnumMemberValue(
			TypesContract.SetTypeEnumMemberValueRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				request.ordinal() < 0) {
				return new TypesContract.SetTypeEnumMemberValueResponse(false);
			}
			int tx = program.startTransaction("libghidra set enum member value");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof ghidra.program.model.data.Enum)) {
					return new TypesContract.SetTypeEnumMemberValueResponse(false);
				}
				ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
				String memberName = DataTypeSupport.enumMemberNameByOrdinal(enumType, request.ordinal());
				if (memberName == null) {
					return new TypesContract.SetTypeEnumMemberValueResponse(false);
				}
				long oldValue = enumType.getValue(memberName);
				if (oldValue == request.value()) {
					return new TypesContract.SetTypeEnumMemberValueResponse(true);
				}
				enumType.remove(memberName);
				enumType.add(memberName, request.value());
				bumpRevision();
				commit = true;
				return new TypesContract.SetTypeEnumMemberValueResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "setTypeEnumMemberValue failed: " + e.getMessage(), e);
				return new TypesContract.SetTypeEnumMemberValueResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.AddTypeMemberResponse addTypeMember(
			TypesContract.AddTypeMemberRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				nullableString(request.name()).isBlank() ||
				nullableString(request.memberType()).isBlank()) {
				return new TypesContract.AddTypeMemberResponse(false);
			}
			int tx = program.startTransaction("libghidra add type member");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof Composite)) {
					return new TypesContract.AddTypeMemberResponse(false);
				}
				DataType parsed = DataTypeSupport.resolveWritableDataType(program, request.memberType());
				if (parsed == null) {
					return new TypesContract.AddTypeMemberResponse(false);
				}
				Composite composite = (Composite) dataType;
				int memberLen = parsed.getLength();
				if (memberLen <= 0) {
					memberLen = (int) Math.max(1L, request.size());
				}
				composite.insert(
					composite.getNumComponents(),
					parsed,
					memberLen,
					request.name().trim(),
					null);
				bumpRevision();
				commit = true;
				return new TypesContract.AddTypeMemberResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "addTypeMember failed: " + e.getMessage(), e);
				return new TypesContract.AddTypeMemberResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.DeleteTypeMemberResponse deleteTypeMember(
			TypesContract.DeleteTypeMemberRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				request.ordinal() < 0) {
				return new TypesContract.DeleteTypeMemberResponse(false);
			}
			int tx = program.startTransaction("libghidra delete type member");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof Composite)) {
					return new TypesContract.DeleteTypeMemberResponse(false);
				}
				Composite composite = (Composite) dataType;
				int index = (int) request.ordinal();
				if (index < 0 || index >= composite.getNumComponents()) {
					return new TypesContract.DeleteTypeMemberResponse(false);
				}
				composite.delete(index);
				bumpRevision();
				commit = true;
				return new TypesContract.DeleteTypeMemberResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "deleteTypeMember failed: " + e.getMessage(), e);
				return new TypesContract.DeleteTypeMemberResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.RenameTypeMemberResponse renameTypeMember(
			TypesContract.RenameTypeMemberRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				nullableString(request.newName()).isBlank() ||
				request.ordinal() < 0) {
				return new TypesContract.RenameTypeMemberResponse(false);
			}
			int tx = program.startTransaction("libghidra rename type member");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof Composite)) {
					return new TypesContract.RenameTypeMemberResponse(false);
				}
				Composite composite = (Composite) dataType;
				int index = (int) request.ordinal();
				if (index < 0 || index >= composite.getNumComponents()) {
					return new TypesContract.RenameTypeMemberResponse(false);
				}
				composite.getComponent(index).setFieldName(request.newName().trim());
				bumpRevision();
				commit = true;
				return new TypesContract.RenameTypeMemberResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "renameTypeMember failed: " + e.getMessage(), e);
				return new TypesContract.RenameTypeMemberResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.SetTypeMemberTypeResponse setTypeMemberType(
			TypesContract.SetTypeMemberTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				nullableString(request.memberType()).isBlank() ||
				request.ordinal() < 0) {
				return new TypesContract.SetTypeMemberTypeResponse(false);
			}
			int tx = program.startTransaction("libghidra set type member type");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof Composite)) {
					return new TypesContract.SetTypeMemberTypeResponse(false);
				}
				Composite composite = (Composite) dataType;
				int index = (int) request.ordinal();
				if (index < 0 || index >= composite.getNumComponents()) {
					return new TypesContract.SetTypeMemberTypeResponse(false);
				}
				DataType parsed = DataTypeSupport.resolveWritableDataType(program, request.memberType());
				if (parsed == null) {
					return new TypesContract.SetTypeMemberTypeResponse(false);
				}
				DataType current = composite.getComponent(index).getDataType();
				if (current != null && current.equals(parsed)) {
					return new TypesContract.SetTypeMemberTypeResponse(true);
				}
				int nextLen = parsed.getLength();
				if (nextLen <= 0) {
					nextLen = composite.getComponent(index).getLength();
				}
				if (nextLen <= 0) {
					nextLen = 1;
				}
				String fieldName = composite.getComponent(index).getFieldName();
				String comment = composite.getComponent(index).getComment();
				if (dataType instanceof Structure) {
					Structure structure = (Structure) dataType;
					structure.replace(index, parsed, nextLen, fieldName, comment);
				}
				else {
					composite.delete(index);
					composite.insert(index, parsed, nextLen, fieldName, comment);
				}
				bumpRevision();
				commit = true;
				return new TypesContract.SetTypeMemberTypeResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "setTypeMemberType failed: " + e.getMessage(), e);
				return new TypesContract.SetTypeMemberTypeResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.SetTypeMemberCommentResponse setTypeMemberComment(
			TypesContract.SetTypeMemberCommentRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				request.ordinal() < 0) {
				return new TypesContract.SetTypeMemberCommentResponse(false);
			}
			int tx = program.startTransaction("libghidra set type member comment");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof Composite)) {
					return new TypesContract.SetTypeMemberCommentResponse(false);
				}
				Composite composite = (Composite) dataType;
				int index = (int) request.ordinal();
				if (index < 0 || index >= composite.getNumComponents()) {
					return new TypesContract.SetTypeMemberCommentResponse(false);
				}
				String nextComment = request.comment() != null ? request.comment() : "";
				var component = composite.getComponent(index);
				String fieldName = component.getFieldName();
				DataType memberDt = component.getDataType();
				int nextLen = component.getLength();
				if (dataType instanceof Structure) {
					Structure structure = (Structure) dataType;
					structure.replace(index, memberDt, nextLen, fieldName, nextComment);
				}
				else {
					composite.delete(index);
					composite.insert(index, memberDt, nextLen, fieldName, nextComment);
				}
				bumpRevision();
				commit = true;
				return new TypesContract.SetTypeMemberCommentResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "setTypeMemberComment failed: " + e.getMessage(), e);
				return new TypesContract.SetTypeMemberCommentResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.SetTypeEnumMemberCommentResponse setTypeEnumMemberComment(
			TypesContract.SetTypeEnumMemberCommentRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null ||
				nullableString(request.type()).isBlank() ||
				request.ordinal() < 0) {
				return new TypesContract.SetTypeEnumMemberCommentResponse(false);
			}
			int tx = program.startTransaction("libghidra set enum member comment");
			boolean commit = false;
			try {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, request.type());
				if (!(dataType instanceof ghidra.program.model.data.Enum)) {
					return new TypesContract.SetTypeEnumMemberCommentResponse(false);
				}
				ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
				String memberName = DataTypeSupport.enumMemberNameByOrdinal(enumType, request.ordinal());
				if (memberName == null) {
					return new TypesContract.SetTypeEnumMemberCommentResponse(false);
				}
				String nextComment = request.comment() != null ? request.comment() : "";
				long value = enumType.getValue(memberName);
				enumType.remove(memberName);
				enumType.add(memberName, value, nextComment);
				bumpRevision();
				commit = true;
				return new TypesContract.SetTypeEnumMemberCommentResponse(true);
			}
			catch (Exception e) {
				Msg.error(this, "setTypeEnumMemberComment failed: " + e.getMessage(), e);
				return new TypesContract.SetTypeEnumMemberCommentResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.ParseDeclarationsResponse parseDeclarations(
			TypesContract.ParseDeclarationsRequest request) {
		Program program;
		try (LockScope ignored = readLock()) {
			program = currentProgram();
		}
		if (program == null || request == null) {
			return new TypesContract.ParseDeclarationsResponse(0, List.of(), List.of("no program"));
		}
		String sourceText = request.sourceText();
		if (sourceText == null || sourceText.isBlank()) {
			return new TypesContract.ParseDeclarationsResponse(0, List.of(), List.of("empty source text"));
		}
		try {
			DataTypeManager dtm = program.getDataTypeManager();
			List<DataType> beforeTypes = new ArrayList<>();
			dtm.getAllDataTypes(beforeTypes);
			int beforeCount = beforeTypes.size();

			CParser parser = new CParser(dtm, true, null);
			parser.parse(new ByteArrayInputStream(sourceText.getBytes(StandardCharsets.UTF_8)));

			List<DataType> afterTypes = new ArrayList<>();
			dtm.getAllDataTypes(afterTypes);

			List<String> newTypeNames = new ArrayList<>();
			for (DataType dt : afterTypes) {
				boolean found = false;
				for (DataType bt : beforeTypes) {
					if (bt.getUniversalID() != null && bt.getUniversalID().equals(dt.getUniversalID())) {
						found = true;
						break;
					}
				}
				if (!found) {
					newTypeNames.add(dt.getPathName());
				}
			}

			int created = afterTypes.size() - beforeCount;
			try (LockScope ignored = writeLock()) {
				bumpRevision();
			}
			return new TypesContract.ParseDeclarationsResponse(
				Math.max(0, created),
				newTypeNames,
				List.of());
		}
		catch (ParseException e) {
			Msg.error(this, "parseDeclarations parse failed: " + e.getMessage(), e);
			return new TypesContract.ParseDeclarationsResponse(
				0,
				List.of(),
				List.of("parse error: " + e.getMessage()));
		}
		catch (Exception e) {
			Msg.error(this, "parseDeclarations failed: " + e.getMessage(), e);
			return new TypesContract.ParseDeclarationsResponse(
				0,
				List.of(),
				List.of("error: " + e.getMessage()));
		}
	}
}
