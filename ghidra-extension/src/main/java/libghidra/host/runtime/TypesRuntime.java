// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
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
			// No program open is an error (not_loaded), never "not found".
			Program program = requireProgram();
			if (request == null) {
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
			Program program = requireProgram();
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
			Program program = requireProgram();
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
			Program program = requireProgram();
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
			Program program = requireProgram();
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
			Program program = requireProgram();
			DataTypeManager manager = program.getDataTypeManager();
			String typeFilter = request != null && request.type() != null ? request.type().trim() : "";
			int offset = request != null ? Math.max(0, request.offset()) : 0;
			int limit = request != null && request.limit() > 0 ? request.limit() : 512;

			List<TypesContract.TypeEnumMemberRecord> rows = new ArrayList<>();
			int seen = 0;

			// A named type that does not exist (or is no enum) has no members --
			// never every enum's members, which is what the unfiltered walk is.
			if (!typeFilter.isEmpty()) {
				DataType specificType = DataTypeSupport.resolveTypeByIdPathOrName(manager, typeFilter);
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
			Program program = requireProgram();
			DataTypeManager manager = program.getDataTypeManager();
			String typeFilter = request != null && request.type() != null ? request.type().trim() : "";
			int offset = request != null ? Math.max(0, request.offset()) : 0;
			int limit = request != null && request.limit() > 0 ? request.limit() : 512;

			List<TypesContract.TypeMemberRecord> rows = new ArrayList<>();
			int seen = 0;

			// A named type that does not exist (or is no composite) has no members
			// -- never every composite's members, which is what the unfiltered walk is.
			if (!typeFilter.isEmpty()) {
				DataType specificType = DataTypeSupport.resolveTypeByIdPathOrName(manager, typeFilter);
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
			// No program open is an error (not_loaded), never "not found".
			Program program = requireProgram();
			if (request == null) {
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
			Program program = requireProgram();
			try {
				long defaultStart = programMinOffset(program);
				long startOffset = request != null ? request.rangeStart() : defaultStart;
				long endOffset = request != null ? request.rangeEnd() : -1L;
				if (startOffset == 0) {
					startOffset = defaultStart;
				}
				if (Long.compareUnsigned(endOffset, startOffset) < 0) {
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
					if (Long.compareUnsigned(address, startOffset) < 0) {
						continue;
					}
					if (Long.compareUnsigned(address, endOffset) >= 0) {
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
			Program program = requireProgram();
			requireRequest(request);
			String prototype = requireText(request.prototype(), "prototype");
			Function function = requireFunction(program, request.address());
			int tx = program.startTransaction("libghidra set function signature");
			boolean commit = false;
			try {
				String convention = request.callingConvention();
				if (convention != null && !convention.isBlank()) {
					convention = convention.trim();
				} else {
					convention = null;
				}
				if (!FunctionPrototypeSupport.applyFunctionPrototype(
						program, function, prototype, convention)) {
					throw SessionRpcException.internalError("function prototype was not applied");
				}
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
				throw SessionRpcException.from("set function signature", e);
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
			Program program = requireProgram();
			requireRequest(request);
			String newName = requireText(request.newName(), "parameter name");
			Parameter parameter = requireParameter(program, request.address(), request.ordinal());
			int tx = program.startTransaction("libghidra rename function parameter");
			boolean commit = false;
			try {
				parameter = editableParameter(parameter, request.ordinal());
				parameter.setName(newName, SourceType.USER_DEFINED);
				commit = true;
				return new TypesContract.RenameFunctionParameterResponse(
					true,
					nullableString(parameter.getName()),
					"",
					"");
			}
			catch (InvalidInputException | DuplicateNameException | IllegalArgumentException e) {
				throw SessionRpcException.from("rename function parameter", e);
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
			Program program = requireProgram();
			requireRequest(request);
			String requestedType = requireText(request.dataType(), "parameter type");
			Parameter parameter = requireParameter(program, request.address(), request.ordinal());
			int tx = program.startTransaction("libghidra set function parameter type");
			boolean commit = false;
			try {
				DataType parsed = requireArgumentType(program, requestedType);
				parameter = editableParameter(parameter, request.ordinal());
				parameter.setDataType(parsed, SourceType.USER_DEFINED);
				commit = true;
				return new TypesContract.SetFunctionParameterTypeResponse(
					true,
					nullableString(parameter.getDataType().getPathName()),
					"",
					"");
			}
			catch (InvalidInputException | IllegalArgumentException e) {
				throw SessionRpcException.from("set function parameter type", e);
			}
			finally {
				program.endTransaction(tx, commit);
				if (commit) {
					flushProgramEvents(program);
				}
			}
		}
	}

	/**
	 * Parameter {@code ordinal} of the function at, or containing, {@code address}:
	 * {@code unmapped_address} / {@code not_found} for the function, {@code not_found}
	 * for an ordinal it does not have.
	 */
	private static Parameter requireParameter(Program program, long address, int ordinal) {
		if (ordinal < 0) {
			throw SessionRpcException.invalidArgument("parameter ordinal must be >= 0");
		}
		Function function = requireFunction(program, address);
		Parameter[] parameters = function.getParameters();
		if (ordinal >= parameters.length) {
			throw SessionRpcException.notFound("function " + function.getName() + " has no parameter " +
				ordinal + " (it has " + parameters.length + ")");
		}
		return parameters[ordinal];
	}

	/** Materialize an auto parameter inside the caller's mutation transaction. */
	private static Parameter editableParameter(Parameter parameter, int ordinal) {
		if (!parameter.isAutoParameter()) {
			return parameter;
		}
		Function function = parameter.getFunction();
		// Preserve the signature's current storage, then refetch: the old
		// AutoParameterImpl remains immutable after the storage conversion.
		function.setCustomVariableStorage(true);
		Parameter editable = function.getParameter(ordinal);
		if (editable == null || editable.isAutoParameter()) {
			throw SessionRpcException.internalError("could not materialize parameter " + ordinal);
		}
		return editable;
	}

	@Override
	public TypesContract.RenameFunctionLocalResponse renameFunctionLocal(
			TypesContract.RenameFunctionLocalRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = requireProgram();
			requireRequest(request);
			String localId = requireText(request.localId(), "local id");
			String newName = requireText(request.newName(), "new local name");
			requireFunction(program, request.address());
			int tx = program.startTransaction("libghidra rename function local");
			boolean commit = false;
			try {
				if (localId.startsWith("local:")) {
					boolean renamed = FunctionVariableMutationSupport.decompileAndRenameHighVariable(
						state,
						program,
						request.address(),
						localId,
						newName);
					if (renamed) {
						commit = true;
						return new TypesContract.RenameFunctionLocalResponse(
							true, localId, newName, "", "");
					}
				}
				Variable variable = FunctionSupport.resolveFunctionVariable(program, request.address(), localId);
				if (variable != null) {
					variable.setName(newName, SourceType.USER_DEFINED);
					commit = true;
					return new TypesContract.RenameFunctionLocalResponse(
						true,
						localId,
						nullableString(variable.getName()),
						"",
						"");
				}
				if (!localId.startsWith("local:")) {
					boolean renamed = FunctionVariableMutationSupport.decompileAndRenameHighVariable(
						state,
						program,
						request.address(),
						localId,
						newName);
					if (renamed) {
						commit = true;
						return new TypesContract.RenameFunctionLocalResponse(
							true, localId, newName, "", "");
					}
				}
				throw SessionRpcException.notFound("local '" + localId + "' not found for function 0x" +
					Long.toHexString(request.address()));
			}
			catch (InvalidInputException | DuplicateNameException | IllegalArgumentException e) {
				throw SessionRpcException.from("rename function local", e);
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
			Program program = requireProgram();
			requireRequest(request);
			String localId = requireText(request.localId(), "local id");
			String requestedType = requireText(request.dataType(), "local type");
			requireFunction(program, request.address());
			DataType parsed = requireArgumentType(program, requestedType);
			int tx = program.startTransaction("libghidra set function local type");
			boolean commit = false;
			try {
				if (localId.startsWith("local:")) {
					String appliedType = FunctionVariableMutationSupport.decompileAndRetypeHighVariable(
						state,
						program,
						request.address(),
						localId,
						parsed);
					if (appliedType != null) {
						commit = true;
						return new TypesContract.SetFunctionLocalTypeResponse(
							true, localId, appliedType, "", "");
					}
				}
				Variable variable = FunctionSupport.resolveFunctionVariable(program, request.address(), localId);
				if (variable != null) {
					String existingName = variable.getName();
					variable.setDataType(parsed, SourceType.USER_DEFINED);
					if (existingName != null &&
							!existingName.isBlank() &&
							!existingName.equals(variable.getName())) {
						variable.setName(existingName, SourceType.USER_DEFINED);
					}
					commit = true;
					return new TypesContract.SetFunctionLocalTypeResponse(
						true,
						localId,
						nullableString(variable.getDataType().getPathName()),
						"",
						"");
				}
				if (!localId.startsWith("local:")) {
					String appliedType = FunctionVariableMutationSupport.decompileAndRetypeHighVariable(
						state,
						program,
						request.address(),
						localId,
						parsed);
					if (appliedType != null) {
						commit = true;
						return new TypesContract.SetFunctionLocalTypeResponse(
							true, localId, appliedType, "", "");
					}
				}
				throw SessionRpcException.notFound("local '" + localId + "' not found for function 0x" +
					Long.toHexString(request.address()));
			}
			catch (InvalidInputException | DuplicateNameException | IllegalArgumentException e) {
				throw SessionRpcException.from("set function local type", e);
			}
			finally {
				program.endTransaction(tx, commit);
				if (commit) {
					flushProgramEvents(program);
				}
			}
		}
	}

	/**
	 * Applies a data type at a mapped address: it retypes the item that starts there,
	 * or creates one on undefined bytes (the upsert {@code INSERT INTO data_items}
	 * relies on, including an address inside a larger item). It refuses to lay data
	 * over instructions ({@code invalid_argument}): clear the code first.
	 */
	@Override
	public TypesContract.ApplyDataTypeResponse applyDataType(TypesContract.ApplyDataTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = requireProgram();
			requireRequest(request);
			String requestedType = requireText(request.dataType(), "data type");
			Address address = requireMappedAddress(program, request.address());
			DataType parsed = requireArgumentType(program, requestedType);
			Listing listing = program.getListing();
			Data data = listing.getDataAt(address);
			// Clear span: for a retype start from the existing item's end; for a
			// create there is no existing item, so start from the address itself and
			// let the requested type's length extend it.
			Address clearEnd = data != null ? data.getMaxAddress() : address;
			int parsedLength = parsed.getLength();
			if (parsedLength > 0) {
				try {
					Address parsedEnd = address.addNoWrap(parsedLength - 1L);
					if (parsedEnd.compareTo(clearEnd) > 0) {
						clearEnd = parsedEnd;
					}
				}
				catch (AddressOverflowException e) {
					throw SessionRpcException.from("apply data type", e);
				}
			}
			if (listing.getInstructions(new AddressSet(address, clearEnd), true).hasNext()) {
				throw SessionRpcException.invalidArgument("instructions occupy 0x" +
					Long.toHexString(request.address()) + ".." + clearEnd +
					"; clear the code before applying a data type");
			}
			int tx = program.startTransaction("libghidra apply data type");
			boolean commit = false;
			try {
				listing.clearCodeUnits(address, clearEnd, false);
				listing.createData(address, parsed);
				commit = true;
				Data reapplied = listing.getDataAt(address);
				String appliedPath = reapplied != null && reapplied.getDataType() != null
						? nullableString(reapplied.getDataType().getPathName())
						: "";
				return new TypesContract.ApplyDataTypeResponse(true, appliedPath);
			}
			catch (IllegalArgumentException | ghidra.program.model.util.CodeUnitInsertionException e) {
				throw SessionRpcException.from("apply data type", e);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.CreateTypeResponse createType(
			TypesContract.CreateTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			String name = requireText(request.name(), "type name");
			String kind = requireText(request.kind(), "type kind").toLowerCase(Locale.ROOT);
			if (!kind.equals("struct") && !kind.equals("enum") && !kind.equals("union")) {
				throw SessionRpcException.invalidArgument(
					"unknown type kind '" + request.kind() + "'; expected struct, enum or union");
			}
			requireNewTypeName(dtm, name);
			int tx = program.startTransaction("libghidra create type");
			boolean commit = false;
			try {
				DataType dataType = switch (kind) {
					case "struct" -> new ghidra.program.model.data.StructureDataType(
						name, Math.max(0, (int) request.size()));
					case "enum" -> new ghidra.program.model.data.EnumDataType(
						name, (int) Math.max(1L, Math.min(8L, request.size() <= 0 ? 4 : request.size())));
					default -> new ghidra.program.model.data.UnionDataType(name);
				};
				dtm.addDataType(
					dataType,
					ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
				commit = true;
				return new TypesContract.CreateTypeResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("create type", e);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.DeleteTypeResponse deleteType(
			TypesContract.DeleteTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dataType = requireType(dtm, request.type());
			int tx = program.startTransaction("libghidra delete type");
			boolean commit = false;
			try {
				if (!dtm.remove(dataType)) {
					throw SessionRpcException.internalError("type '" + request.type() + "' was not removed");
				}
				commit = true;
				return new TypesContract.DeleteTypeResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("delete type", e);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public TypesContract.RenameTypeResponse renameType(
			TypesContract.RenameTypeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dataType = requireType(dtm, request.type());
			String newName = requireText(request.newName(), "new type name");
			int tx = program.startTransaction("libghidra rename type");
			boolean commit = false;
			try {
				dataType.setName(newName);
				commit = true;
				return new TypesContract.RenameTypeResponse(true, newName);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("rename type", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			String name = requireText(request.name(), "alias name");
			requireText(request.targetType(), "alias target type");
			requireNewTypeName(dtm, name);
			DataType target = requireArgumentType(program, request.targetType());
			int tx = program.startTransaction("libghidra create type alias");
			boolean commit = false;
			try {
				dtm.addDataType(
					new ghidra.program.model.data.TypedefDataType(name, target),
					ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
				commit = true;
				return new TypesContract.CreateTypeAliasResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("create type alias", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dataType = requireTypeOfKind(dtm, request.type(), TypeDef.class, "a typedef");
			int tx = program.startTransaction("libghidra delete type alias");
			boolean commit = false;
			try {
				if (!dtm.remove(dataType)) {
					throw SessionRpcException.internalError("typedef '" + request.type() + "' was not removed");
				}
				commit = true;
				return new TypesContract.DeleteTypeAliasResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("delete type alias", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			TypeDef alias = requireTypeOfKind(dtm, request.type(), TypeDef.class, "a typedef");
			requireText(request.targetType(), "alias target type");
			DataType target = requireArgumentType(program, request.targetType());
			DataType currentBase = alias.getBaseDataType();
			if (currentBase != null && currentBase.isEquivalent(target)) {
				return new TypesContract.SetTypeAliasTargetResponse(true);
			}
			int tx = program.startTransaction("libghidra set type alias target");
			boolean commit = false;
			try {
				ghidra.program.model.data.TypedefDataType replacement =
					new ghidra.program.model.data.TypedefDataType(
						alias.getCategoryPath(),
						alias.getName(),
						target,
						dtm);
				dtm.replaceDataType(alias, replacement, true);
				commit = true;
				return new TypesContract.SetTypeAliasTargetResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("set type alias target", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			String name = requireText(request.name(), "enum name");
			int width = (int) Math.max(1L, Math.min(8L, request.width() <= 0 ? 4 : request.width()));
			requireNewTypeName(dtm, name);
			int tx = program.startTransaction("libghidra create enum");
			boolean commit = false;
			try {
				ghidra.program.model.data.EnumDataType enumType =
					new ghidra.program.model.data.EnumDataType(name, width);
				if (request.signed()) {
					enumType.setDescription("signed");
				}
				dtm.addDataType(
					enumType,
					ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
				commit = true;
				return new TypesContract.CreateTypeEnumResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("create enum", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dataType = requireTypeOfKind(dtm, request.type(), ghidra.program.model.data.Enum.class, "an enum");
			int tx = program.startTransaction("libghidra delete enum");
			boolean commit = false;
			try {
				if (!dtm.remove(dataType)) {
					throw SessionRpcException.internalError("enum '" + request.type() + "' was not removed");
				}
				commit = true;
				return new TypesContract.DeleteTypeEnumResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("delete enum", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			ghidra.program.model.data.Enum enumType =
				requireTypeOfKind(dtm, request.type(), ghidra.program.model.data.Enum.class, "an enum");
			String nextName = requireText(request.name(), "enum member name");
			requireNewEnumMemberName(enumType, request.type(), nextName);
			int tx = program.startTransaction("libghidra add enum member");
			boolean commit = false;
			try {
				enumType.add(nextName, request.value());
				commit = true;
				return new TypesContract.AddTypeEnumMemberResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("add enum member", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			ghidra.program.model.data.Enum enumType =
				requireTypeOfKind(dtm, request.type(), ghidra.program.model.data.Enum.class, "an enum");
			String memberName = requireEnumMember(enumType, request.type(), request.ordinal());
			int tx = program.startTransaction("libghidra delete enum member");
			boolean commit = false;
			try {
				enumType.remove(memberName);
				commit = true;
				return new TypesContract.DeleteTypeEnumMemberResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("delete enum member", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			ghidra.program.model.data.Enum enumType =
				requireTypeOfKind(dtm, request.type(), ghidra.program.model.data.Enum.class, "an enum");
			String memberName = requireEnumMember(enumType, request.type(), request.ordinal());
			String nextName = requireText(request.newName(), "new enum member name");
			if (memberName.equals(nextName)) {
				return new TypesContract.RenameTypeEnumMemberResponse(true);
			}
			requireNewEnumMemberName(enumType, request.type(), nextName);
			int tx = program.startTransaction("libghidra rename enum member");
			boolean commit = false;
			try {
				long value = enumType.getValue(memberName);
				String comment = enumType.getComment(memberName);
				enumType.remove(memberName);
				enumType.add(nextName, value, comment);
				commit = true;
				return new TypesContract.RenameTypeEnumMemberResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("rename enum member", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			ghidra.program.model.data.Enum enumType =
				requireTypeOfKind(dtm, request.type(), ghidra.program.model.data.Enum.class, "an enum");
			String memberName = requireEnumMember(enumType, request.type(), request.ordinal());
			if (enumType.getValue(memberName) == request.value()) {
				return new TypesContract.SetTypeEnumMemberValueResponse(true);
			}
			int tx = program.startTransaction("libghidra set enum member value");
			boolean commit = false;
			try {
				String comment = enumType.getComment(memberName);
				enumType.remove(memberName);
				enumType.add(memberName, request.value(), comment);
				commit = true;
				return new TypesContract.SetTypeEnumMemberValueResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("set enum member value", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			Composite composite = requireTypeOfKind(dtm, request.type(), Composite.class, "a struct or union");
			String memberName = requireText(request.name(), "member name");
			requireText(request.memberType(), "member type");
			DataType parsed = requireArgumentType(program, request.memberType());
			int tx = program.startTransaction("libghidra add type member");
			boolean commit = false;
			try {
				int memberLen = parsed.getLength();
				if (memberLen <= 0) {
					memberLen = (int) Math.max(1L, request.size());
				}
				composite.insert(
					composite.getNumComponents(),
					parsed,
					memberLen,
					memberName,
					null);
				commit = true;
				return new TypesContract.AddTypeMemberResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("add type member", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			Composite composite = requireTypeOfKind(dtm, request.type(), Composite.class, "a struct or union");
			int index = requireComponent(composite, request.type(), request.ordinal());
			int tx = program.startTransaction("libghidra delete type member");
			boolean commit = false;
			try {
				composite.delete(index);
				commit = true;
				return new TypesContract.DeleteTypeMemberResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("delete type member", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			Composite composite = requireTypeOfKind(dtm, request.type(), Composite.class, "a struct or union");
			int index = requireComponent(composite, request.type(), request.ordinal());
			String newName = requireText(request.newName(), "new member name");
			int tx = program.startTransaction("libghidra rename type member");
			boolean commit = false;
			try {
				composite.getComponent(index).setFieldName(newName);
				commit = true;
				return new TypesContract.RenameTypeMemberResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("rename type member", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			Composite composite = requireTypeOfKind(dtm, request.type(), Composite.class, "a struct or union");
			int index = requireComponent(composite, request.type(), request.ordinal());
			requireText(request.memberType(), "member type");
			DataType parsed = requireArgumentType(program, request.memberType());
			DataType current = composite.getComponent(index).getDataType();
			if (current != null && current.equals(parsed)) {
				return new TypesContract.SetTypeMemberTypeResponse(true);
			}
			int tx = program.startTransaction("libghidra set type member type");
			boolean commit = false;
			try {
				int nextLen = parsed.getLength();
				if (nextLen <= 0) {
					nextLen = composite.getComponent(index).getLength();
				}
				if (nextLen <= 0) {
					nextLen = 1;
				}
				String fieldName = composite.getComponent(index).getFieldName();
				String comment = composite.getComponent(index).getComment();
				if (composite instanceof Structure structure) {
					structure.replace(index, parsed, nextLen, fieldName, comment);
				}
				else {
					composite.delete(index);
					composite.insert(index, parsed, nextLen, fieldName, comment);
				}
				commit = true;
				return new TypesContract.SetTypeMemberTypeResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("set type member type", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			Composite composite = requireTypeOfKind(dtm, request.type(), Composite.class, "a struct or union");
			int index = requireComponent(composite, request.type(), request.ordinal());
			int tx = program.startTransaction("libghidra set type member comment");
			boolean commit = false;
			try {
				String nextComment = request.comment() != null ? request.comment() : "";
				var component = composite.getComponent(index);
				String fieldName = component.getFieldName();
				DataType memberDt = component.getDataType();
				int nextLen = component.getLength();
				if (composite instanceof Structure structure) {
					structure.replace(index, memberDt, nextLen, fieldName, nextComment);
				}
				else {
					composite.delete(index);
					composite.insert(index, memberDt, nextLen, fieldName, nextComment);
				}
				commit = true;
				return new TypesContract.SetTypeMemberCommentResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("set type member comment", e);
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
			Program program = requireProgram();
			requireRequest(request);
			DataTypeManager dtm = program.getDataTypeManager();
			ghidra.program.model.data.Enum enumType =
				requireTypeOfKind(dtm, request.type(), ghidra.program.model.data.Enum.class, "an enum");
			String memberName = requireEnumMember(enumType, request.type(), request.ordinal());
			int tx = program.startTransaction("libghidra set enum member comment");
			boolean commit = false;
			try {
				String nextComment = request.comment() != null ? request.comment() : "";
				long value = enumType.getValue(memberName);
				enumType.remove(memberName);
				enumType.add(memberName, value, nextComment);
				commit = true;
				return new TypesContract.SetTypeEnumMemberCommentResponse(true);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				throw SessionRpcException.from("set enum member comment", e);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	/**
	 * Parses C declarations into the program's types, all or nothing: a parse error is
	 * {@code parse_error} and leaves no type behind (the whole parse runs in one
	 * transaction that is rolled back).
	 */
	@Override
	public TypesContract.ParseDeclarationsResponse parseDeclarations(
			TypesContract.ParseDeclarationsRequest request) {
		// Mutating the program's DataTypeManager (parser.parse below) must hold
		// the host write lock so a concurrent reader (e.g. getAllDataTypes under
		// readLock) cannot race the newly parsed types.
		try (LockScope ignored = writeLock()) {
			Program program = requireProgram();
			requireRequest(request);
			String sourceText = requireText(request.sourceText(), "source text");
			DataTypeManager dtm = program.getDataTypeManager();
			List<DataType> beforeTypes = new ArrayList<>();
			dtm.getAllDataTypes(beforeTypes);

			int tx = program.startTransaction("libghidra parse declarations");
			boolean commit = false;
			try {
				// The parser does not store as it goes (storeDataType = false), so a name
				// the text uses (`struct S`, `enum E`) resolves to the program's type. A
				// storing parser never looks in the program for a composite or enum: a
				// forward reference to an existing S made a new empty S that replaced the
				// real one. The parsed types are added afterwards, a definition of an
				// existing type replacing it in place.
				CParser parser = new CParser(dtm, false, null);
				parser.parse(new ByteArrayInputStream(sourceText.getBytes(StandardCharsets.UTF_8)));
				addParsedTypes(dtm, parser.getComposites());
				addParsedTypes(dtm, parser.getEnums());
				addParsedTypes(dtm, parser.getTypes());
				addParsedTypes(dtm, parser.getFunctions());

				List<DataType> afterTypes = new ArrayList<>();
				dtm.getAllDataTypes(afterTypes);

				// A type is new when its path was not there before. (Built-in types have
				// no universal id, so an id comparison counted every one of them.) Only
				// named types count: a pointer or array the text needed is derived,
				// unnamed in the decompiler's type system, and counted by neither backend.
				Set<String> beforePaths = new HashSet<>();
				for (DataType bt : beforeTypes) {
					beforePaths.add(bt.getPathName());
				}
				List<String> newTypeNames = new ArrayList<>();
				for (DataType dt : afterTypes) {
					if (!beforePaths.contains(dt.getPathName()) && !(dt instanceof Pointer) &&
						!(dt instanceof Array)) {
						newTypeNames.add(dt.getPathName());
					}
				}
				commit = true;
				return new TypesContract.ParseDeclarationsResponse(
					newTypeNames.size(),
					newTypeNames,
					List.of());
			}
			catch (ParseException | ghidra.app.util.cparser.C.TokenMgrError e) {
				throw new SessionRpcException(SessionRpcException.PARSE_ERROR,
					"parse error: " + e.getMessage());
			}
			catch (RuntimeException e) {
				throw SessionRpcException.from("parse declarations", e);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	/** Adds one of the parser's tables to the program, replacing a type of the same path. */
	private static void addParsedTypes(DataTypeManager dtm, Map<String, DataType> parsed) {
		for (DataType dt : parsed.values()) {
			dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
		}
	}

	// ---- write-target resolution: one rule per failure, shared by every type write ----

	/** The type {@code typeId} names (id, path or name); {@code not_found} when none. */
	private static DataType requireType(DataTypeManager dtm, String typeId) {
		String id = requireText(typeId, "type");
		DataType dataType = DataTypeSupport.resolveDataTypeById(dtm, id);
		if (dataType == null) {
			throw SessionRpcException.notFound("no type '" + id + "'");
		}
		return dataType;
	}

	/** The type, which must be a {@code kind}; another kind is {@code invalid_argument}. */
	private static <T> T requireTypeOfKind(
			DataTypeManager dtm, String typeId, Class<T> kind, String kindName) {
		DataType dataType = requireType(dtm, typeId);
		if (!kind.isInstance(dataType)) {
			throw SessionRpcException.invalidArgument("type '" + typeId.trim() + "' is " +
				describeKind(dataType) + ", not " + kindName);
		}
		return kind.cast(dataType);
	}

	private static String describeKind(DataType dataType) {
		if (dataType instanceof Structure) {
			return "a struct";
		}
		if (dataType instanceof Union) {
			return "a union";
		}
		if (dataType instanceof ghidra.program.model.data.Enum) {
			return "an enum";
		}
		if (dataType instanceof TypeDef) {
			return "a typedef";
		}
		return "a " + dataType.getClass().getSimpleName();
	}

	/** A name a new type may take; an existing type of that name is {@code duplicate_name}. */
	private static void requireNewTypeName(DataTypeManager dtm, String name) {
		DataType existing = DataTypeSupport.findDataTypeByName(dtm, name);
		if (existing != null) {
			throw SessionRpcException.duplicateName(
				"a type named '" + name + "' already exists: " + existing.getPathName());
		}
	}

	/**
	 * A type named as an argument (a member, parameter, local, alias target or
	 * ApplyDataType type) -- not the write's target. {@code unknown_type} when it does
	 * not resolve, which tells a missing argument apart from a missing target.
	 */
	private static DataType requireArgumentType(Program program, String typeText) {
		DataType parsed = DataTypeSupport.resolveWritableDataType(program, typeText);
		if (parsed == null) {
			throw SessionRpcException.unknownType(typeText.trim());
		}
		return parsed;
	}

	private static String requireEnumMember(
			ghidra.program.model.data.Enum enumType, String typeId, long ordinal) {
		if (ordinal < 0) {
			throw SessionRpcException.invalidArgument("member ordinal must be >= 0");
		}
		String memberName = DataTypeSupport.enumMemberNameByOrdinal(enumType, ordinal);
		if (memberName == null) {
			throw SessionRpcException.notFound("enum '" + typeId.trim() + "' has no member " + ordinal +
				" (it has " + enumType.getCount() + ")");
		}
		return memberName;
	}

	private static void requireNewEnumMemberName(
			ghidra.program.model.data.Enum enumType, String typeId, String name) {
		for (String existing : enumType.getNames()) {
			if (name.equals(existing)) {
				throw SessionRpcException.duplicateName(
					"enum '" + typeId.trim() + "' already has a member named '" + name + "'");
			}
		}
	}

	private static int requireComponent(Composite composite, String typeId, long ordinal) {
		if (ordinal < 0) {
			throw SessionRpcException.invalidArgument("member ordinal must be >= 0");
		}
		if (ordinal >= composite.getNumComponents()) {
			throw SessionRpcException.notFound("type '" + typeId.trim() + "' has no member " + ordinal +
				" (it has " + composite.getNumComponents() + ")");
		}
		return (int) ordinal;
	}
}
