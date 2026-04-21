package libghidra.host.rpc;

import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;

import libghidra.host.contract.DecompilerContract;
import libghidra.host.contract.FunctionsContract;
import libghidra.host.contract.HealthContract;
import libghidra.host.contract.ListingContract;
import libghidra.host.contract.MemoryContract;
import libghidra.host.contract.SessionContract;
import libghidra.host.contract.SymbolsContract;
import libghidra.host.contract.TypesContract;
import libghidra.host.contract.XrefsContract;
import libghidra.host.http.LibGhidraHttpServer;
import libghidra.host.runtime.SessionRpcException;

public final class RpcDispatcher {

	private final LibGhidraHttpServer.Callbacks callbacks;

	public RpcDispatcher(LibGhidraHttpServer.Callbacks callbacks) {
		this.callbacks = callbacks;
	}

	public libghidra.RpcResponse dispatch(libghidra.RpcRequest request) {
		if (callbacks == null) {
			return error("config_error", "callbacks not configured");
		}
		if (request == null || request.getMethod().isBlank()) {
			return error("invalid_argument", "method is required");
		}
		try {
			switch (request.getMethod()) {
				case "libghidra.HealthService/GetStatus":
					return healthGetStatus(request);
				case "libghidra.HealthService/GetCapabilities":
					return healthGetCapabilities(request);
				case "libghidra.SessionService/OpenProgram":
					return sessionOpenProgram(request);
				case "libghidra.SessionService/CloseProgram":
					return sessionCloseProgram(request);
				case "libghidra.SessionService/SaveProgram":
					return sessionSaveProgram(request);
				case "libghidra.SessionService/DiscardProgram":
					return sessionDiscardProgram(request);
				case "libghidra.SessionService/GetRevision":
					return sessionGetRevision(request);
				case "libghidra.SessionService/Shutdown":
					return sessionShutdown(request);
				case "libghidra.MemoryService/ReadBytes":
					return memoryReadBytes(request);
				case "libghidra.MemoryService/WriteBytes":
					return memoryWriteBytes(request);
				case "libghidra.MemoryService/PatchBytesBatch":
					return memoryPatchBytesBatch(request);
				case "libghidra.MemoryService/ListMemoryBlocks":
					return memoryListMemoryBlocks(request);
				case "libghidra.FunctionsService/GetFunction":
					return functionsGetFunction(request);
				case "libghidra.FunctionsService/ListFunctions":
					return functionsListFunctions(request);
				case "libghidra.FunctionsService/RenameFunction":
					return functionsRenameFunction(request);
				case "libghidra.FunctionsService/ListBasicBlocks":
					return functionsListBasicBlocks(request);
				case "libghidra.FunctionsService/ListCFGEdges":
					return functionsListCFGEdges(request);
				case "libghidra.FunctionsService/ListFunctionTags":
					return functionsListFunctionTags(request);
				case "libghidra.FunctionsService/CreateFunctionTag":
					return functionsCreateFunctionTag(request);
				case "libghidra.FunctionsService/DeleteFunctionTag":
					return functionsDeleteFunctionTag(request);
				case "libghidra.FunctionsService/ListFunctionTagMappings":
					return functionsListFunctionTagMappings(request);
				case "libghidra.FunctionsService/TagFunction":
					return functionsTagFunction(request);
				case "libghidra.FunctionsService/UntagFunction":
					return functionsUntagFunction(request);
				case "libghidra.FunctionsService/ListSwitchTables":
					return functionsListSwitchTables(request);
				case "libghidra.FunctionsService/ListDominators":
					return functionsListDominators(request);
				case "libghidra.FunctionsService/ListPostDominators":
					return functionsListPostDominators(request);
				case "libghidra.FunctionsService/ListLoops":
					return functionsListLoops(request);
				case "libghidra.SymbolsService/GetSymbol":
					return symbolsGetSymbol(request);
				case "libghidra.SymbolsService/ListSymbols":
					return symbolsListSymbols(request);
				case "libghidra.SymbolsService/RenameSymbol":
					return symbolsRenameSymbol(request);
				case "libghidra.SymbolsService/DeleteSymbol":
					return symbolsDeleteSymbol(request);
				case "libghidra.XrefsService/ListXrefs":
					return xrefsListXrefs(request);
				case "libghidra.DecompilerService/DecompileFunction":
					return decompilerDecompileFunction(request);
				case "libghidra.DecompilerService/ListDecompilations":
					return decompilerListDecompilations(request);
				case "libghidra.ListingService/GetInstruction":
					return listingGetInstruction(request);
				case "libghidra.ListingService/ListInstructions":
					return listingListInstructions(request);
				case "libghidra.ListingService/GetComments":
					return listingGetComments(request);
				case "libghidra.ListingService/SetComment":
					return listingSetComment(request);
				case "libghidra.ListingService/DeleteComment":
					return listingDeleteComment(request);
				case "libghidra.ListingService/RenameDataItem":
					return listingRenameDataItem(request);
				case "libghidra.ListingService/DeleteDataItem":
					return listingDeleteDataItem(request);
				case "libghidra.ListingService/ListDataItems":
					return listingListDataItems(request);
				case "libghidra.ListingService/ListBookmarks":
					return listingListBookmarks(request);
				case "libghidra.ListingService/AddBookmark":
					return listingAddBookmark(request);
				case "libghidra.ListingService/DeleteBookmark":
					return listingDeleteBookmark(request);
				case "libghidra.ListingService/ListBreakpoints":
					return listingListBreakpoints(request);
				case "libghidra.ListingService/AddBreakpoint":
					return listingAddBreakpoint(request);
				case "libghidra.ListingService/SetBreakpointEnabled":
					return listingSetBreakpointEnabled(request);
				case "libghidra.ListingService/SetBreakpointKind":
					return listingSetBreakpointKind(request);
				case "libghidra.ListingService/SetBreakpointSize":
					return listingSetBreakpointSize(request);
				case "libghidra.ListingService/SetBreakpointCondition":
					return listingSetBreakpointCondition(request);
				case "libghidra.ListingService/SetBreakpointGroup":
					return listingSetBreakpointGroup(request);
				case "libghidra.ListingService/DeleteBreakpoint":
					return listingDeleteBreakpoint(request);
				case "libghidra.ListingService/ListDefinedStrings":
					return listingListDefinedStrings(request);
				case "libghidra.TypesService/GetType":
					return typesGetType(request);
				case "libghidra.TypesService/ListTypes":
					return typesListTypes(request);
				case "libghidra.TypesService/ListTypeAliases":
					return typesListTypeAliases(request);
				case "libghidra.TypesService/ListTypeUnions":
					return typesListTypeUnions(request);
				case "libghidra.TypesService/ListTypeEnums":
					return typesListTypeEnums(request);
				case "libghidra.TypesService/ListTypeEnumMembers":
					return typesListTypeEnumMembers(request);
				case "libghidra.TypesService/ListTypeMembers":
					return typesListTypeMembers(request);
				case "libghidra.TypesService/GetFunctionSignature":
					return typesGetFunctionSignature(request);
				case "libghidra.TypesService/ListFunctionSignatures":
					return typesListFunctionSignatures(request);
				case "libghidra.TypesService/SetFunctionSignature":
					return typesSetFunctionSignature(request);
				case "libghidra.TypesService/RenameFunctionParameter":
					return typesRenameFunctionParameter(request);
				case "libghidra.TypesService/SetFunctionParameterType":
					return typesSetFunctionParameterType(request);
				case "libghidra.TypesService/RenameFunctionLocal":
					return typesRenameFunctionLocal(request);
				case "libghidra.TypesService/SetFunctionLocalType":
					return typesSetFunctionLocalType(request);
				case "libghidra.TypesService/ApplyDataType":
					return typesApplyDataType(request);
				case "libghidra.TypesService/CreateType":
					return typesCreateType(request);
				case "libghidra.TypesService/DeleteType":
					return typesDeleteType(request);
				case "libghidra.TypesService/RenameType":
					return typesRenameType(request);
				case "libghidra.TypesService/CreateTypeAlias":
					return typesCreateTypeAlias(request);
				case "libghidra.TypesService/DeleteTypeAlias":
					return typesDeleteTypeAlias(request);
				case "libghidra.TypesService/SetTypeAliasTarget":
					return typesSetTypeAliasTarget(request);
				case "libghidra.TypesService/CreateTypeEnum":
					return typesCreateTypeEnum(request);
				case "libghidra.TypesService/DeleteTypeEnum":
					return typesDeleteTypeEnum(request);
				case "libghidra.TypesService/AddTypeEnumMember":
					return typesAddTypeEnumMember(request);
				case "libghidra.TypesService/DeleteTypeEnumMember":
					return typesDeleteTypeEnumMember(request);
				case "libghidra.TypesService/RenameTypeEnumMember":
					return typesRenameTypeEnumMember(request);
				case "libghidra.TypesService/SetTypeEnumMemberValue":
					return typesSetTypeEnumMemberValue(request);
				case "libghidra.TypesService/AddTypeMember":
					return typesAddTypeMember(request);
				case "libghidra.TypesService/DeleteTypeMember":
					return typesDeleteTypeMember(request);
				case "libghidra.TypesService/RenameTypeMember":
					return typesRenameTypeMember(request);
				case "libghidra.TypesService/SetTypeMemberType":
					return typesSetTypeMemberType(request);
				case "libghidra.TypesService/SetTypeMemberComment":
					return typesSetTypeMemberComment(request);
				case "libghidra.TypesService/SetTypeEnumMemberComment":
					return typesSetTypeEnumMemberComment(request);
				case "libghidra.TypesService/ParseDeclarations":
					return typesParseDeclarations(request);
				default:
					return error("unknown_method", "unsupported method: " + request.getMethod());
			}
		}
		catch (InvalidProtocolBufferException e) {
			return error("invalid_payload", e.getMessage());
		}
		catch (SessionRpcException e) {
			return error(e.code(), e.getMessage());
		}
		catch (Exception e) {
			String message = e.getMessage();
			if (message == null || message.isBlank()) {
				message = e.toString();
			}
			return error("internal_error", message);
		}
	}

	private libghidra.RpcResponse healthGetStatus(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		unpackPayload(request, libghidra.HealthStatusRequest.class,
			libghidra.HealthStatusRequest.getDefaultInstance());
		HealthContract.HealthStatusResponse response =
			callbacks.healthStatus(new HealthContract.HealthStatusRequest());
		libghidra.HealthStatusResponse proto = libghidra.HealthStatusResponse.newBuilder()
			.setOk(response != null && response.ok())
			.setServiceName(nullable(response != null ? response.serviceName() : null))
			.setServiceVersion(nullable(response != null ? response.serviceVersion() : null))
			.setHostMode(nullable(response != null ? response.hostMode() : null))
			.setProgramRevision(response != null ? response.programRevision() : 0L)
			.addAllWarnings(copyStrings(response != null ? response.warnings() : null))
			.build();
		return ok(proto, proto.getProgramRevision());
	}

	private libghidra.RpcResponse healthGetCapabilities(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		unpackPayload(request, libghidra.CapabilityRequest.class,
			libghidra.CapabilityRequest.getDefaultInstance());
		HealthContract.CapabilityResponse response =
			callbacks.capabilities(new HealthContract.CapabilityRequest());
		libghidra.CapabilityResponse.Builder out = libghidra.CapabilityResponse.newBuilder();
		if (response != null && response.capabilities() != null) {
			for (HealthContract.Capability cap : response.capabilities()) {
				if (cap == null) {
					continue;
				}
				out.addCapabilities(libghidra.Capability.newBuilder()
					.setId(nullable(cap.id()))
					.setStatus(nullable(cap.status()))
					.setNote(nullable(cap.note()))
					.build());
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse sessionOpenProgram(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.OpenProgramRequest protoRequest = unpackPayload(request,
			libghidra.OpenProgramRequest.class,
			libghidra.OpenProgramRequest.getDefaultInstance());
		SessionContract.OpenProgramResponse response = callbacks.openProgram(
			new SessionContract.OpenProgramRequest(
				protoRequest.getProjectPath(),
				protoRequest.getProjectName(),
				protoRequest.getProgramPath(),
				protoRequest.getAnalyze(),
				protoRequest.getReadOnly()));
		libghidra.OpenProgramResponse proto = libghidra.OpenProgramResponse.newBuilder()
			.setProgramName(nullable(response != null ? response.programName() : null))
			.setLanguageId(nullable(response != null ? response.languageId() : null))
			.setCompilerSpec(nullable(response != null ? response.compilerSpec() : null))
			.setImageBase(response != null ? response.imageBase() : 0L)
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse sessionCloseProgram(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.CloseProgramRequest protoRequest = unpackPayload(request,
			libghidra.CloseProgramRequest.class,
			libghidra.CloseProgramRequest.getDefaultInstance());
		SessionContract.CloseProgramResponse response = callbacks.closeProgram(
			new SessionContract.CloseProgramRequest(
				toPolicy(protoRequest.getShutdownPolicy())));
		libghidra.CloseProgramResponse proto = libghidra.CloseProgramResponse.newBuilder()
			.setClosed(response != null && response.closed())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse sessionSaveProgram(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SaveProgramRequest protoRequest = unpackPayload(request,
			libghidra.SaveProgramRequest.class,
			libghidra.SaveProgramRequest.getDefaultInstance());
		SessionContract.SaveProgramResponse response = callbacks.saveProgram(
			new SessionContract.SaveProgramRequest());
		libghidra.SaveProgramResponse proto = libghidra.SaveProgramResponse.newBuilder()
			.setSaved(response != null && response.saved())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse sessionDiscardProgram(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DiscardProgramRequest protoRequest = unpackPayload(request,
			libghidra.DiscardProgramRequest.class,
			libghidra.DiscardProgramRequest.getDefaultInstance());
		SessionContract.DiscardProgramResponse response = callbacks.discardProgram(
			new SessionContract.DiscardProgramRequest());
		libghidra.DiscardProgramResponse proto = libghidra.DiscardProgramResponse.newBuilder()
			.setDiscarded(response != null && response.discarded())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse sessionGetRevision(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.GetRevisionRequest protoRequest = unpackPayload(request,
			libghidra.GetRevisionRequest.class,
			libghidra.GetRevisionRequest.getDefaultInstance());
		SessionContract.GetRevisionResponse response = callbacks.getRevision(
			new SessionContract.GetRevisionRequest());
		long revision = response != null ? response.revision() : 0L;
		libghidra.GetRevisionResponse proto = libghidra.GetRevisionResponse.newBuilder()
			.setRevision(revision)
			.build();
		return ok(proto, revision);
	}

	private libghidra.RpcResponse sessionShutdown(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ShutdownRequest protoRequest = unpackPayload(request,
			libghidra.ShutdownRequest.class,
			libghidra.ShutdownRequest.getDefaultInstance());
		SessionContract.ShutdownResponse response = callbacks.shutdown(
			new SessionContract.ShutdownRequest(toPolicy(protoRequest.getShutdownPolicy())));
		libghidra.ShutdownResponse proto = libghidra.ShutdownResponse.newBuilder()
			.setAccepted(response != null && response.accepted())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse memoryReadBytes(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ReadBytesRequest protoRequest = unpackPayload(request,
			libghidra.ReadBytesRequest.class,
			libghidra.ReadBytesRequest.getDefaultInstance());
		MemoryContract.ReadBytesResponse response = callbacks.readBytes(
			new MemoryContract.ReadBytesRequest(
				protoRequest.getAddress(),
				(int) protoRequest.getLength()));
		byte[] data = response != null ? response.data() : null;
		libghidra.ReadBytesResponse proto = libghidra.ReadBytesResponse.newBuilder()
			.setData(toByteString(data))
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse memoryWriteBytes(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.WriteBytesRequest protoRequest = unpackPayload(request,
			libghidra.WriteBytesRequest.class,
			libghidra.WriteBytesRequest.getDefaultInstance());
		MemoryContract.WriteBytesResponse response = callbacks.writeBytes(
			new MemoryContract.WriteBytesRequest(
				protoRequest.getAddress(),
				protoRequest.getData().toByteArray()));
		libghidra.WriteBytesResponse proto = libghidra.WriteBytesResponse.newBuilder()
			.setBytesWritten(response != null ? response.bytesWritten() : 0)
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse memoryPatchBytesBatch(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.PatchBytesBatchRequest protoRequest = unpackPayload(request,
			libghidra.PatchBytesBatchRequest.class,
			libghidra.PatchBytesBatchRequest.getDefaultInstance());
		List<MemoryContract.BytePatch> patches = new ArrayList<>(protoRequest.getPatchesCount());
		for (libghidra.BytePatch patch : protoRequest.getPatchesList()) {
			patches.add(new MemoryContract.BytePatch(
				patch.getAddress(),
				patch.getData().toByteArray()));
		}
		MemoryContract.PatchBytesBatchResponse response = callbacks.patchBytes(
			new MemoryContract.PatchBytesBatchRequest(
				patches));
		libghidra.PatchBytesBatchResponse proto =
			libghidra.PatchBytesBatchResponse.newBuilder()
				.setPatchCount(response != null ? response.patchCount() : 0)
				.setBytesWritten(response != null ? response.bytesWritten() : 0)
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse memoryListMemoryBlocks(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListMemoryBlocksRequest protoRequest = unpackPayload(request,
			libghidra.ListMemoryBlocksRequest.class,
			libghidra.ListMemoryBlocksRequest.getDefaultInstance());
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		MemoryContract.ListMemoryBlocksResponse response = callbacks.listMemoryBlocks(
			new MemoryContract.ListMemoryBlocksRequest(
				limit,
				offset));
		libghidra.ListMemoryBlocksResponse.Builder out =
			libghidra.ListMemoryBlocksResponse.newBuilder();
		if (response != null && response.blocks() != null) {
			for (MemoryContract.MemoryBlockRecord row : response.blocks()) {
				out.addBlocks(libghidra.MemoryBlockRecord.newBuilder()
					.setName(row.name() != null ? row.name() : "")
					.setStartAddress(row.startAddress())
					.setEndAddress(row.endAddress())
					.setSize(row.size())
					.setIsRead(row.isRead())
					.setIsWrite(row.isWrite())
					.setIsExecute(row.isExecute())
					.setIsVolatile(row.isVolatile())
					.setIsInitialized(row.isInitialized())
					.setSourceName(row.sourceName() != null ? row.sourceName() : "")
					.setComment(row.comment() != null ? row.comment() : "")
					.build());
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse functionsGetFunction(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.GetFunctionRequest protoRequest = unpackPayload(request,
			libghidra.GetFunctionRequest.class,
			libghidra.GetFunctionRequest.getDefaultInstance());
		FunctionsContract.GetFunctionResponse response = callbacks.getFunction(
			new FunctionsContract.GetFunctionRequest(
				protoRequest.getAddress()));
		libghidra.GetFunctionResponse.Builder proto = libghidra.GetFunctionResponse.newBuilder();
		if (response != null && response.function() != null) {
			proto.setFunction(toFunctionRecord(response.function()));
		}
		return ok(proto.build(), 0L);
	}

	private libghidra.RpcResponse functionsListFunctions(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListFunctionsRequest protoRequest = unpackPayload(request,
			libghidra.ListFunctionsRequest.class,
			libghidra.ListFunctionsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		FunctionsContract.ListFunctionsResponse response = callbacks.listFunctions(
			new FunctionsContract.ListFunctionsRequest(
				start,
				end,
				limit,
				offset));
		libghidra.ListFunctionsResponse.Builder out =
			libghidra.ListFunctionsResponse.newBuilder();
		if (response != null && response.functions() != null) {
			for (FunctionsContract.FunctionRecord row : response.functions()) {
				out.addFunctions(toFunctionRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse functionsRenameFunction(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.RenameFunctionRequest protoRequest = unpackPayload(request,
			libghidra.RenameFunctionRequest.class,
			libghidra.RenameFunctionRequest.getDefaultInstance());
		FunctionsContract.RenameFunctionResponse response = callbacks.renameFunction(
			new FunctionsContract.RenameFunctionRequest(
				protoRequest.getAddress(),
				protoRequest.getNewName()));
		if (response != null && !response.renamed() && response.errorMessage() != null &&
			!response.errorMessage().isBlank()) {
			return error(
				response.errorCode() != null && !response.errorCode().isBlank()
					? response.errorCode()
					: "rename_function_failed",
				response.errorMessage());
		}
		libghidra.RenameFunctionResponse proto =
			libghidra.RenameFunctionResponse.newBuilder()
				.setRenamed(response != null && response.renamed())
				.setName(nullable(response != null ? response.name() : null))
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse functionsListBasicBlocks(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListBasicBlocksRequest protoRequest = unpackPayload(request,
			libghidra.ListBasicBlocksRequest.class,
			libghidra.ListBasicBlocksRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		FunctionsContract.ListBasicBlocksResponse response = callbacks.listBasicBlocks(
			new FunctionsContract.ListBasicBlocksRequest(
				start, end, limit, offset));
		libghidra.ListBasicBlocksResponse.Builder out =
			libghidra.ListBasicBlocksResponse.newBuilder();
		if (response != null && response.blocks() != null) {
			for (FunctionsContract.BasicBlockRecord row : response.blocks()) {
				out.addBlocks(libghidra.BasicBlockRecord.newBuilder()
					.setFunctionEntry(row.functionEntry())
					.setStartAddress(row.startAddress())
					.setEndAddress(row.endAddress())
					.setInDegree(row.inDegree())
					.setOutDegree(row.outDegree())
					.build());
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse functionsListCFGEdges(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListCFGEdgesRequest protoRequest = unpackPayload(request,
			libghidra.ListCFGEdgesRequest.class,
			libghidra.ListCFGEdgesRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		FunctionsContract.ListCFGEdgesResponse response = callbacks.listCFGEdges(
			new FunctionsContract.ListCFGEdgesRequest(
				start, end, limit, offset));
		libghidra.ListCFGEdgesResponse.Builder out =
			libghidra.ListCFGEdgesResponse.newBuilder();
		if (response != null && response.edges() != null) {
			for (FunctionsContract.CFGEdgeRecord row : response.edges()) {
				out.addEdges(libghidra.CFGEdgeRecord.newBuilder()
					.setFunctionEntry(row.functionEntry())
					.setSrcBlockStart(row.srcBlockStart())
					.setDstBlockStart(row.dstBlockStart())
					.setEdgeKind(row.edgeKind() != null ? row.edgeKind() : "")
					.build());
			}
		}
		return ok(out.build(), 0L);
	}

	// ── Function tags ─────────────────────────────────────────────────────

	private libghidra.RpcResponse functionsListFunctionTags(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListFunctionTagsRequest protoRequest = unpackPayload(request,
			libghidra.ListFunctionTagsRequest.class,
			libghidra.ListFunctionTagsRequest.getDefaultInstance());
		FunctionsContract.ListFunctionTagsResponse response = callbacks.listFunctionTags(
			new FunctionsContract.ListFunctionTagsRequest(
				));
		libghidra.ListFunctionTagsResponse.Builder out =
			libghidra.ListFunctionTagsResponse.newBuilder();
		if (response != null && response.tags() != null) {
			for (FunctionsContract.FunctionTagRecord row : response.tags()) {
				out.addTags(libghidra.FunctionTagRecord.newBuilder()
					.setName(row.name() != null ? row.name() : "")
					.setComment(row.comment() != null ? row.comment() : "")
					.build());
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse functionsCreateFunctionTag(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.CreateFunctionTagRequest protoRequest = unpackPayload(request,
			libghidra.CreateFunctionTagRequest.class,
			libghidra.CreateFunctionTagRequest.getDefaultInstance());
		FunctionsContract.CreateFunctionTagResponse response = callbacks.createFunctionTag(
			new FunctionsContract.CreateFunctionTagRequest(
				protoRequest.getName(),
				protoRequest.getComment()));
		return ok(libghidra.CreateFunctionTagResponse.newBuilder()
			.setCreated(response != null && response.created())
			.build(), 0L);
	}

	private libghidra.RpcResponse functionsDeleteFunctionTag(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteFunctionTagRequest protoRequest = unpackPayload(request,
			libghidra.DeleteFunctionTagRequest.class,
			libghidra.DeleteFunctionTagRequest.getDefaultInstance());
		FunctionsContract.DeleteFunctionTagResponse response = callbacks.deleteFunctionTag(
			new FunctionsContract.DeleteFunctionTagRequest(
				protoRequest.getName()));
		return ok(libghidra.DeleteFunctionTagResponse.newBuilder()
			.setDeleted(response != null && response.deleted())
			.build(), 0L);
	}

	private libghidra.RpcResponse functionsListFunctionTagMappings(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListFunctionTagMappingsRequest protoRequest = unpackPayload(request,
			libghidra.ListFunctionTagMappingsRequest.class,
			libghidra.ListFunctionTagMappingsRequest.getDefaultInstance());
		FunctionsContract.ListFunctionTagMappingsResponse response = callbacks.listFunctionTagMappings(
			new FunctionsContract.ListFunctionTagMappingsRequest(
				protoRequest.getFunctionEntry()));
		libghidra.ListFunctionTagMappingsResponse.Builder out =
			libghidra.ListFunctionTagMappingsResponse.newBuilder();
		if (response != null && response.mappings() != null) {
			for (FunctionsContract.FunctionTagMappingRecord row : response.mappings()) {
				out.addMappings(libghidra.FunctionTagMappingRecord.newBuilder()
					.setFunctionEntry(row.functionEntry())
					.setTagName(row.tagName() != null ? row.tagName() : "")
					.build());
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse functionsTagFunction(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.TagFunctionRequest protoRequest = unpackPayload(request,
			libghidra.TagFunctionRequest.class,
			libghidra.TagFunctionRequest.getDefaultInstance());
		FunctionsContract.TagFunctionResponse response = callbacks.tagFunction(
			new FunctionsContract.TagFunctionRequest(
				protoRequest.getFunctionEntry(),
				protoRequest.getTagName()));
		return ok(libghidra.TagFunctionResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.build(), 0L);
	}

	private libghidra.RpcResponse functionsUntagFunction(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.UntagFunctionRequest protoRequest = unpackPayload(request,
			libghidra.UntagFunctionRequest.class,
			libghidra.UntagFunctionRequest.getDefaultInstance());
		FunctionsContract.UntagFunctionResponse response = callbacks.untagFunction(
			new FunctionsContract.UntagFunctionRequest(
				protoRequest.getFunctionEntry(),
				protoRequest.getTagName()));
		return ok(libghidra.UntagFunctionResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.build(), 0L);
	}

	private libghidra.RpcResponse functionsListSwitchTables(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListSwitchTablesRequest protoRequest = unpackPayload(request,
			libghidra.ListSwitchTablesRequest.class,
			libghidra.ListSwitchTablesRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		FunctionsContract.ListSwitchTablesResponse response = callbacks.listSwitchTables(
			new FunctionsContract.ListSwitchTablesRequest(start, end, limit, offset));
		libghidra.ListSwitchTablesResponse.Builder out =
			libghidra.ListSwitchTablesResponse.newBuilder();
		if (response != null && response.switchTables() != null) {
			for (FunctionsContract.SwitchTableRecord row : response.switchTables()) {
				libghidra.SwitchTableRecord.Builder rec = libghidra.SwitchTableRecord.newBuilder()
					.setFunctionEntry(row.functionEntry())
					.setSwitchAddress(row.switchAddress())
					.setCaseCount(row.caseCount())
					.setDefaultAddress(row.defaultAddress());
				if (row.cases() != null) {
					for (FunctionsContract.SwitchCaseRecord c : row.cases()) {
						rec.addCases(libghidra.SwitchCaseRecord.newBuilder()
							.setValue(c.value())
							.setTargetAddress(c.targetAddress())
							.build());
					}
				}
				out.addSwitchTables(rec.build());
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse functionsListDominators(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListDominatorsRequest protoRequest = unpackPayload(request,
			libghidra.ListDominatorsRequest.class,
			libghidra.ListDominatorsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		FunctionsContract.ListDominatorsResponse response = callbacks.listDominators(
			new FunctionsContract.ListDominatorsRequest(start, end, limit, offset));
		libghidra.ListDominatorsResponse.Builder out =
			libghidra.ListDominatorsResponse.newBuilder();
		if (response != null && response.dominators() != null) {
			for (FunctionsContract.DominatorRecord row : response.dominators()) {
				out.addDominators(libghidra.DominatorRecord.newBuilder()
					.setFunctionEntry(row.functionEntry())
					.setBlockAddress(row.blockAddress())
					.setIdomAddress(row.idomAddress())
					.setDepth(row.depth())
					.setIsEntry(row.isEntry())
					.build());
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse functionsListPostDominators(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListPostDominatorsRequest protoRequest = unpackPayload(request,
			libghidra.ListPostDominatorsRequest.class,
			libghidra.ListPostDominatorsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		FunctionsContract.ListPostDominatorsResponse response = callbacks.listPostDominators(
			new FunctionsContract.ListPostDominatorsRequest(start, end, limit, offset));
		libghidra.ListPostDominatorsResponse.Builder out =
			libghidra.ListPostDominatorsResponse.newBuilder();
		if (response != null && response.postDominators() != null) {
			for (FunctionsContract.PostDominatorRecord row : response.postDominators()) {
				out.addPostDominators(libghidra.PostDominatorRecord.newBuilder()
					.setFunctionEntry(row.functionEntry())
					.setBlockAddress(row.blockAddress())
					.setIpdomAddress(row.ipdomAddress())
					.setDepth(row.depth())
					.setIsExit(row.isExit())
					.build());
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse functionsListLoops(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListLoopsRequest protoRequest = unpackPayload(request,
			libghidra.ListLoopsRequest.class,
			libghidra.ListLoopsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		FunctionsContract.ListLoopsResponse response = callbacks.listLoops(
			new FunctionsContract.ListLoopsRequest(start, end, limit, offset));
		libghidra.ListLoopsResponse.Builder out =
			libghidra.ListLoopsResponse.newBuilder();
		if (response != null && response.loops() != null) {
			for (FunctionsContract.LoopRecord row : response.loops()) {
				out.addLoops(libghidra.LoopRecord.newBuilder()
					.setFunctionEntry(row.functionEntry())
					.setHeaderAddress(row.headerAddress())
					.setBackEdgeSource(row.backEdgeSource())
					.setLoopKind(row.loopKind() != null ? row.loopKind() : "")
					.setBlockCount(row.blockCount())
					.setDepth(row.depth())
					.build());
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse symbolsGetSymbol(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.GetSymbolRequest protoRequest = unpackPayload(request,
			libghidra.GetSymbolRequest.class,
			libghidra.GetSymbolRequest.getDefaultInstance());
		SymbolsContract.GetSymbolResponse response = callbacks.getSymbol(
			new SymbolsContract.GetSymbolRequest(
				protoRequest.getAddress()));
		libghidra.GetSymbolResponse proto = libghidra.GetSymbolResponse.newBuilder()
			.setSymbol(toSymbolRecord(response != null ? response.symbol() : null))
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse symbolsListSymbols(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListSymbolsRequest protoRequest = unpackPayload(request,
			libghidra.ListSymbolsRequest.class,
			libghidra.ListSymbolsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		SymbolsContract.ListSymbolsResponse response = callbacks.listSymbols(
			new SymbolsContract.ListSymbolsRequest(
				start,
				end,
				limit,
				offset));
		libghidra.ListSymbolsResponse.Builder out = libghidra.ListSymbolsResponse.newBuilder();
		if (response != null && response.symbols() != null) {
			for (SymbolsContract.SymbolRecord row : response.symbols()) {
				out.addSymbols(toSymbolRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse symbolsRenameSymbol(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.RenameSymbolRequest protoRequest = unpackPayload(request,
			libghidra.RenameSymbolRequest.class,
			libghidra.RenameSymbolRequest.getDefaultInstance());
		SymbolsContract.RenameSymbolResponse response = callbacks.renameSymbol(
			new SymbolsContract.RenameSymbolRequest(
				protoRequest.getAddress(),
				protoRequest.getNewName()));
		libghidra.RenameSymbolResponse proto = libghidra.RenameSymbolResponse.newBuilder()
			.setRenamed(response != null && response.renamed())
			.setName(nullable(response != null ? response.name() : null))
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse symbolsDeleteSymbol(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteSymbolRequest protoRequest = unpackPayload(request,
			libghidra.DeleteSymbolRequest.class,
			libghidra.DeleteSymbolRequest.getDefaultInstance());
		SymbolsContract.DeleteSymbolResponse response = callbacks.deleteSymbol(
			new SymbolsContract.DeleteSymbolRequest(
				protoRequest.getAddress(),
				protoRequest.getName()));
		libghidra.DeleteSymbolResponse proto = libghidra.DeleteSymbolResponse.newBuilder()
			.setDeleted(response != null && response.deleted())
			.setDeletedCount(response != null ? response.deletedCount() : 0)
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse xrefsListXrefs(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListXrefsRequest protoRequest = unpackPayload(request,
			libghidra.ListXrefsRequest.class,
			libghidra.ListXrefsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		XrefsContract.ListXrefsResponse response = callbacks.listXrefs(
			new XrefsContract.ListXrefsRequest(
				start,
				end,
				limit,
				offset));
		libghidra.ListXrefsResponse.Builder out = libghidra.ListXrefsResponse.newBuilder();
		if (response != null && response.xrefs() != null) {
			for (XrefsContract.XrefRecord row : response.xrefs()) {
				out.addXrefs(toXrefRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse decompilerDecompileFunction(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DecompileFunctionRequest protoRequest = unpackPayload(request,
			libghidra.DecompileFunctionRequest.class,
			libghidra.DecompileFunctionRequest.getDefaultInstance());
		DecompilerContract.DecompileFunctionResponse response = callbacks.decompileFunction(
			new DecompilerContract.DecompileFunctionRequest(
				protoRequest.getAddress(),
				(int) protoRequest.getTimeoutMs()));
		libghidra.DecompileFunctionResponse proto =
			libghidra.DecompileFunctionResponse.newBuilder()
				.setDecompilation(toDecompileRecord(response != null ? response.decompilation() : null))
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse decompilerListDecompilations(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListDecompilationsRequest protoRequest = unpackPayload(request,
			libghidra.ListDecompilationsRequest.class,
			libghidra.ListDecompilationsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		DecompilerContract.ListDecompilationsResponse response = callbacks.listDecompilations(
			new DecompilerContract.ListDecompilationsRequest(
				start,
				end,
				limit,
				offset,
				(int) protoRequest.getTimeoutMs()));
		libghidra.ListDecompilationsResponse.Builder out =
			libghidra.ListDecompilationsResponse.newBuilder();
		if (response != null && response.decompilations() != null) {
			for (DecompilerContract.DecompileRecord row : response.decompilations()) {
				out.addDecompilations(toDecompileRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse listingGetInstruction(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.GetInstructionRequest protoRequest = unpackPayload(request,
			libghidra.GetInstructionRequest.class,
			libghidra.GetInstructionRequest.getDefaultInstance());
		ListingContract.GetInstructionResponse response = callbacks.getInstruction(
			new ListingContract.GetInstructionRequest(
				protoRequest.getAddress()));
		libghidra.GetInstructionResponse proto =
			libghidra.GetInstructionResponse.newBuilder()
				.setInstruction(toInstructionRecord(response != null ? response.instruction() : null))
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingListInstructions(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListInstructionsRequest protoRequest = unpackPayload(request,
			libghidra.ListInstructionsRequest.class,
			libghidra.ListInstructionsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		ListingContract.ListInstructionsResponse response = callbacks.listInstructions(
			new ListingContract.ListInstructionsRequest(
				start,
				end,
				limit,
				offset));
		libghidra.ListInstructionsResponse.Builder out =
			libghidra.ListInstructionsResponse.newBuilder();
		if (response != null && response.instructions() != null) {
			for (ListingContract.InstructionRecord row : response.instructions()) {
				out.addInstructions(toInstructionRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse listingGetComments(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.GetCommentsRequest protoRequest = unpackPayload(request,
			libghidra.GetCommentsRequest.class,
			libghidra.GetCommentsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		ListingContract.GetCommentsResponse response = callbacks.getComments(
			new ListingContract.GetCommentsRequest(
				start,
				end,
				limit,
				offset));
		libghidra.GetCommentsResponse.Builder out = libghidra.GetCommentsResponse.newBuilder();
		if (response != null && response.comments() != null) {
			for (ListingContract.CommentRecord row : response.comments()) {
				out.addComments(toCommentRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse listingSetComment(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetCommentRequest protoRequest = unpackPayload(request,
			libghidra.SetCommentRequest.class,
			libghidra.SetCommentRequest.getDefaultInstance());
		ListingContract.SetCommentResponse response = callbacks.setComment(
			new ListingContract.SetCommentRequest(
				protoRequest.getAddress(),
				toCommentKind(protoRequest.getKind()),
				protoRequest.getText()));
		if (response != null && !response.updated() && response.errorMessage() != null &&
			!response.errorMessage().isBlank()) {
			return error(
				response.errorCode() != null && !response.errorCode().isBlank()
					? response.errorCode()
					: "set_comment_failed",
				response.errorMessage());
		}
		libghidra.SetCommentResponse proto = libghidra.SetCommentResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingDeleteComment(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteCommentRequest protoRequest = unpackPayload(request,
			libghidra.DeleteCommentRequest.class,
			libghidra.DeleteCommentRequest.getDefaultInstance());
		ListingContract.DeleteCommentResponse response = callbacks.deleteComment(
			new ListingContract.DeleteCommentRequest(
				protoRequest.getAddress(),
				toCommentKind(protoRequest.getKind())));
		if (response != null && !response.deleted() && response.errorMessage() != null &&
			!response.errorMessage().isBlank()) {
			return error(
				response.errorCode() != null && !response.errorCode().isBlank()
					? response.errorCode()
					: "delete_comment_failed",
				response.errorMessage());
		}
		libghidra.DeleteCommentResponse proto =
			libghidra.DeleteCommentResponse.newBuilder()
				.setDeleted(response != null && response.deleted())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingRenameDataItem(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.RenameDataItemRequest protoRequest = unpackPayload(request,
			libghidra.RenameDataItemRequest.class,
			libghidra.RenameDataItemRequest.getDefaultInstance());
		ListingContract.RenameDataItemResponse response = callbacks.renameDataItem(
			new ListingContract.RenameDataItemRequest(
				protoRequest.getAddress(),
				protoRequest.getNewName()));
		libghidra.RenameDataItemResponse proto =
			libghidra.RenameDataItemResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.setName(nullable(response != null ? response.name() : null))
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingDeleteDataItem(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteDataItemRequest protoRequest = unpackPayload(request,
			libghidra.DeleteDataItemRequest.class,
			libghidra.DeleteDataItemRequest.getDefaultInstance());
		ListingContract.DeleteDataItemResponse response = callbacks.deleteDataItem(
			new ListingContract.DeleteDataItemRequest(
				protoRequest.getAddress()));
		libghidra.DeleteDataItemResponse proto =
			libghidra.DeleteDataItemResponse.newBuilder()
				.setDeleted(response != null && response.deleted())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingListDataItems(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListDataItemsRequest protoRequest = unpackPayload(request,
			libghidra.ListDataItemsRequest.class,
			libghidra.ListDataItemsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		ListingContract.ListDataItemsResponse response = callbacks.listDataItems(
			new ListingContract.ListDataItemsRequest(
				start,
				end,
				limit,
				offset));
		libghidra.ListDataItemsResponse.Builder out =
			libghidra.ListDataItemsResponse.newBuilder();
		if (response != null && response.dataItems() != null) {
			for (ListingContract.DataItemRecord row : response.dataItems()) {
				out.addDataItems(toDataItemRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse listingListBookmarks(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListBookmarksRequest protoRequest = unpackPayload(request,
			libghidra.ListBookmarksRequest.class,
			libghidra.ListBookmarksRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		ListingContract.ListBookmarksResponse response = callbacks.listBookmarks(
			new ListingContract.ListBookmarksRequest(
				start,
				end,
				limit,
				offset,
				protoRequest.getTypeFilter(),
				protoRequest.getCategoryFilter()));
		libghidra.ListBookmarksResponse.Builder out =
			libghidra.ListBookmarksResponse.newBuilder();
		if (response != null && response.bookmarks() != null) {
			for (ListingContract.BookmarkRecord row : response.bookmarks()) {
				out.addBookmarks(toBookmarkRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse listingAddBookmark(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.AddBookmarkRequest protoRequest = unpackPayload(request,
			libghidra.AddBookmarkRequest.class,
			libghidra.AddBookmarkRequest.getDefaultInstance());
		ListingContract.AddBookmarkResponse response = callbacks.addBookmark(
			new ListingContract.AddBookmarkRequest(
				protoRequest.getAddress(),
				protoRequest.getType(),
				protoRequest.getCategory(),
				protoRequest.getComment()));
		libghidra.AddBookmarkResponse proto = libghidra.AddBookmarkResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingDeleteBookmark(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteBookmarkRequest protoRequest = unpackPayload(request,
			libghidra.DeleteBookmarkRequest.class,
			libghidra.DeleteBookmarkRequest.getDefaultInstance());
		ListingContract.DeleteBookmarkResponse response = callbacks.deleteBookmark(
			new ListingContract.DeleteBookmarkRequest(
				protoRequest.getAddress(),
				protoRequest.getType(),
				protoRequest.getCategory()));
		libghidra.DeleteBookmarkResponse proto =
			libghidra.DeleteBookmarkResponse.newBuilder()
				.setDeleted(response != null && response.deleted())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingListBreakpoints(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListBreakpointsRequest protoRequest = unpackPayload(request,
			libghidra.ListBreakpointsRequest.class,
			libghidra.ListBreakpointsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		ListingContract.ListBreakpointsResponse response = callbacks.listBreakpoints(
			new ListingContract.ListBreakpointsRequest(
				start,
				end,
				limit,
				offset,
				protoRequest.getKindFilter(),
				protoRequest.getGroupFilter()));
		libghidra.ListBreakpointsResponse.Builder out =
			libghidra.ListBreakpointsResponse.newBuilder();
		if (response != null && response.breakpoints() != null) {
			for (ListingContract.BreakpointRecord row : response.breakpoints()) {
				out.addBreakpoints(toBreakpointRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse listingAddBreakpoint(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.AddBreakpointRequest protoRequest = unpackPayload(request,
			libghidra.AddBreakpointRequest.class,
			libghidra.AddBreakpointRequest.getDefaultInstance());
		ListingContract.AddBreakpointResponse response = callbacks.addBreakpoint(
			new ListingContract.AddBreakpointRequest(
				protoRequest.getAddress(),
				protoRequest.getKind(),
				protoRequest.getSize(),
				protoRequest.getEnabled(),
				protoRequest.getCondition(),
				protoRequest.getGroup()));
		libghidra.AddBreakpointResponse proto = libghidra.AddBreakpointResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingSetBreakpointEnabled(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetBreakpointEnabledRequest protoRequest = unpackPayload(request,
			libghidra.SetBreakpointEnabledRequest.class,
			libghidra.SetBreakpointEnabledRequest.getDefaultInstance());
		ListingContract.SetBreakpointEnabledResponse response = callbacks.setBreakpointEnabled(
			new ListingContract.SetBreakpointEnabledRequest(
				protoRequest.getAddress(),
				protoRequest.getEnabled()));
		libghidra.SetBreakpointEnabledResponse proto =
			libghidra.SetBreakpointEnabledResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingSetBreakpointKind(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetBreakpointKindRequest protoRequest = unpackPayload(request,
			libghidra.SetBreakpointKindRequest.class,
			libghidra.SetBreakpointKindRequest.getDefaultInstance());
		ListingContract.SetBreakpointKindResponse response = callbacks.setBreakpointKind(
			new ListingContract.SetBreakpointKindRequest(
				protoRequest.getAddress(),
				protoRequest.getKind()));
		libghidra.SetBreakpointKindResponse proto =
			libghidra.SetBreakpointKindResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingSetBreakpointSize(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetBreakpointSizeRequest protoRequest = unpackPayload(request,
			libghidra.SetBreakpointSizeRequest.class,
			libghidra.SetBreakpointSizeRequest.getDefaultInstance());
		ListingContract.SetBreakpointSizeResponse response = callbacks.setBreakpointSize(
			new ListingContract.SetBreakpointSizeRequest(
				protoRequest.getAddress(),
				protoRequest.getSize()));
		libghidra.SetBreakpointSizeResponse proto =
			libghidra.SetBreakpointSizeResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingSetBreakpointCondition(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetBreakpointConditionRequest protoRequest = unpackPayload(request,
			libghidra.SetBreakpointConditionRequest.class,
			libghidra.SetBreakpointConditionRequest.getDefaultInstance());
		ListingContract.SetBreakpointConditionResponse response = callbacks.setBreakpointCondition(
			new ListingContract.SetBreakpointConditionRequest(
				protoRequest.getAddress(),
				protoRequest.getCondition()));
		libghidra.SetBreakpointConditionResponse proto =
			libghidra.SetBreakpointConditionResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingSetBreakpointGroup(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetBreakpointGroupRequest protoRequest = unpackPayload(request,
			libghidra.SetBreakpointGroupRequest.class,
			libghidra.SetBreakpointGroupRequest.getDefaultInstance());
		ListingContract.SetBreakpointGroupResponse response = callbacks.setBreakpointGroup(
			new ListingContract.SetBreakpointGroupRequest(
				protoRequest.getAddress(),
				protoRequest.getGroup()));
		libghidra.SetBreakpointGroupResponse proto =
			libghidra.SetBreakpointGroupResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingDeleteBreakpoint(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteBreakpointRequest protoRequest = unpackPayload(request,
			libghidra.DeleteBreakpointRequest.class,
			libghidra.DeleteBreakpointRequest.getDefaultInstance());
		ListingContract.DeleteBreakpointResponse response = callbacks.deleteBreakpoint(
			new ListingContract.DeleteBreakpointRequest(
				protoRequest.getAddress()));
		libghidra.DeleteBreakpointResponse proto =
			libghidra.DeleteBreakpointResponse.newBuilder()
				.setDeleted(response != null && response.deleted())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse listingListDefinedStrings(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListDefinedStringsRequest protoRequest = unpackPayload(request,
			libghidra.ListDefinedStringsRequest.class,
			libghidra.ListDefinedStringsRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		ListingContract.ListDefinedStringsResponse response = callbacks.listDefinedStrings(
			new ListingContract.ListDefinedStringsRequest(
				start, end, limit, offset));
		libghidra.ListDefinedStringsResponse.Builder out =
			libghidra.ListDefinedStringsResponse.newBuilder();
		if (response != null && response.strings() != null) {
			for (ListingContract.DefinedStringRecord row : response.strings()) {
				out.addStrings(libghidra.DefinedStringRecord.newBuilder()
					.setAddress(row.address())
					.setValue(row.value() != null ? row.value() : "")
					.setLength(row.length())
					.setDataType(row.dataType() != null ? row.dataType() : "")
					.setEncoding(row.encoding() != null ? row.encoding() : "")
					.build());
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse typesGetType(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.GetTypeRequest protoRequest = unpackPayload(request,
			libghidra.GetTypeRequest.class,
			libghidra.GetTypeRequest.getDefaultInstance());
		TypesContract.GetTypeResponse response = callbacks.getType(
			new TypesContract.GetTypeRequest(
				protoRequest.getPath()));
		libghidra.GetTypeResponse proto = libghidra.GetTypeResponse.newBuilder()
			.setType(toTypeRecord(response != null ? response.type() : null))
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesListTypes(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListTypesRequest protoRequest = unpackPayload(request,
			libghidra.ListTypesRequest.class,
			libghidra.ListTypesRequest.getDefaultInstance());
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		TypesContract.ListTypesResponse response = callbacks.listTypes(
			new TypesContract.ListTypesRequest(
				protoRequest.getQuery(),
				limit,
				offset));
		libghidra.ListTypesResponse.Builder out = libghidra.ListTypesResponse.newBuilder();
		if (response != null && response.types() != null) {
			for (TypesContract.TypeRecord row : response.types()) {
				out.addTypes(toTypeRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse typesListTypeAliases(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListTypeAliasesRequest protoRequest = unpackPayload(request,
			libghidra.ListTypeAliasesRequest.class,
			libghidra.ListTypeAliasesRequest.getDefaultInstance());
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		TypesContract.ListTypeAliasesResponse response = callbacks.listTypeAliases(
			new TypesContract.ListTypeAliasesRequest(
				protoRequest.getQuery(),
				limit,
				offset));
		libghidra.ListTypeAliasesResponse.Builder out =
			libghidra.ListTypeAliasesResponse.newBuilder();
		if (response != null && response.aliases() != null) {
			for (TypesContract.TypeAliasRecord row : response.aliases()) {
				out.addAliases(toTypeAliasRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse typesListTypeUnions(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListTypeUnionsRequest protoRequest = unpackPayload(request,
			libghidra.ListTypeUnionsRequest.class,
			libghidra.ListTypeUnionsRequest.getDefaultInstance());
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		TypesContract.ListTypeUnionsResponse response = callbacks.listTypeUnions(
			new TypesContract.ListTypeUnionsRequest(
				protoRequest.getQuery(),
				limit,
				offset));
		libghidra.ListTypeUnionsResponse.Builder out =
			libghidra.ListTypeUnionsResponse.newBuilder();
		if (response != null && response.unions() != null) {
			for (TypesContract.TypeUnionRecord row : response.unions()) {
				out.addUnions(toTypeUnionRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse typesListTypeEnums(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListTypeEnumsRequest protoRequest = unpackPayload(request,
			libghidra.ListTypeEnumsRequest.class,
			libghidra.ListTypeEnumsRequest.getDefaultInstance());
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		TypesContract.ListTypeEnumsResponse response = callbacks.listTypeEnums(
			new TypesContract.ListTypeEnumsRequest(
				protoRequest.getQuery(),
				limit,
				offset));
		libghidra.ListTypeEnumsResponse.Builder out =
			libghidra.ListTypeEnumsResponse.newBuilder();
		if (response != null && response.enums() != null) {
			for (TypesContract.TypeEnumRecord row : response.enums()) {
				out.addEnums(toTypeEnumRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse typesListTypeEnumMembers(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListTypeEnumMembersRequest protoRequest = unpackPayload(request,
			libghidra.ListTypeEnumMembersRequest.class,
			libghidra.ListTypeEnumMembersRequest.getDefaultInstance());
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		TypesContract.ListTypeEnumMembersResponse response = callbacks.listTypeEnumMembers(
			new TypesContract.ListTypeEnumMembersRequest(
				protoRequest.getType(),
				limit,
				offset));
		libghidra.ListTypeEnumMembersResponse.Builder out =
			libghidra.ListTypeEnumMembersResponse.newBuilder();
		if (response != null && response.members() != null) {
			for (TypesContract.TypeEnumMemberRecord row : response.members()) {
				out.addMembers(toTypeEnumMemberRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse typesListTypeMembers(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListTypeMembersRequest protoRequest = unpackPayload(request,
			libghidra.ListTypeMembersRequest.class,
			libghidra.ListTypeMembersRequest.getDefaultInstance());
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		TypesContract.ListTypeMembersResponse response = callbacks.listTypeMembers(
			new TypesContract.ListTypeMembersRequest(
				protoRequest.getType(),
				limit,
				offset));
		libghidra.ListTypeMembersResponse.Builder out =
			libghidra.ListTypeMembersResponse.newBuilder();
		if (response != null && response.members() != null) {
			for (TypesContract.TypeMemberRecord row : response.members()) {
				out.addMembers(toTypeMemberRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse typesGetFunctionSignature(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.GetFunctionSignatureRequest protoRequest = unpackPayload(request,
			libghidra.GetFunctionSignatureRequest.class,
			libghidra.GetFunctionSignatureRequest.getDefaultInstance());
		TypesContract.GetFunctionSignatureResponse response = callbacks.getFunctionSignature(
			new TypesContract.GetFunctionSignatureRequest(
				protoRequest.getAddress()));
		libghidra.GetFunctionSignatureResponse proto =
			libghidra.GetFunctionSignatureResponse.newBuilder()
				.setSignature(toSignatureRecord(response != null ? response.signature() : null))
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesListFunctionSignatures(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ListFunctionSignaturesRequest protoRequest = unpackPayload(request,
			libghidra.ListFunctionSignaturesRequest.class,
			libghidra.ListFunctionSignaturesRequest.getDefaultInstance());
		long start = protoRequest.hasRange() ? protoRequest.getRange().getStart() : 0L;
		long end = protoRequest.hasRange() ? protoRequest.getRange().getEnd() : 0L;
		int limit = protoRequest.hasPage() ? (int) protoRequest.getPage().getLimit() : 0;
		int offset = protoRequest.hasPage() ? (int) protoRequest.getPage().getOffset() : 0;
		TypesContract.ListFunctionSignaturesResponse response = callbacks.listFunctionSignatures(
			new TypesContract.ListFunctionSignaturesRequest(
				start,
				end,
				limit,
				offset));
		libghidra.ListFunctionSignaturesResponse.Builder out =
			libghidra.ListFunctionSignaturesResponse.newBuilder();
		if (response != null && response.signatures() != null) {
			for (TypesContract.FunctionSignatureRecord row : response.signatures()) {
				out.addSignatures(toSignatureRecord(row));
			}
		}
		return ok(out.build(), 0L);
	}

	private libghidra.RpcResponse typesSetFunctionSignature(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetFunctionSignatureRequest protoRequest = unpackPayload(request,
			libghidra.SetFunctionSignatureRequest.class,
			libghidra.SetFunctionSignatureRequest.getDefaultInstance());
		TypesContract.SetFunctionSignatureResponse response = callbacks.setFunctionSignature(
			new TypesContract.SetFunctionSignatureRequest(
				protoRequest.getAddress(),
				protoRequest.getPrototype(),
				protoRequest.getCallingConvention()));
		if (response != null && !response.updated() && response.errorMessage() != null &&
			!response.errorMessage().isBlank()) {
			return error(
				response.errorCode() != null && !response.errorCode().isBlank()
					? response.errorCode()
					: "set_function_signature_failed",
				response.errorMessage());
		}
		libghidra.SetFunctionSignatureResponse proto =
			libghidra.SetFunctionSignatureResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.setFunctionName(nullable(response != null ? response.functionName() : null))
				.setPrototype(nullable(response != null ? response.prototype() : null))
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesRenameFunctionParameter(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.RenameFunctionParameterRequest protoRequest = unpackPayload(request,
			libghidra.RenameFunctionParameterRequest.class,
			libghidra.RenameFunctionParameterRequest.getDefaultInstance());
		TypesContract.RenameFunctionParameterResponse response = callbacks.renameFunctionParameter(
			new TypesContract.RenameFunctionParameterRequest(
				protoRequest.getAddress(),
				protoRequest.getOrdinal(),
				protoRequest.getNewName()));
		if (response != null && !response.updated() && response.errorMessage() != null &&
			!response.errorMessage().isBlank()) {
			return error(
				response.errorCode() != null && !response.errorCode().isBlank()
					? response.errorCode()
					: "rename_function_parameter_failed",
				response.errorMessage());
		}
		libghidra.RenameFunctionParameterResponse proto =
			libghidra.RenameFunctionParameterResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.setName(nullable(response != null ? response.name() : null))
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesSetFunctionParameterType(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetFunctionParameterTypeRequest protoRequest = unpackPayload(request,
			libghidra.SetFunctionParameterTypeRequest.class,
			libghidra.SetFunctionParameterTypeRequest.getDefaultInstance());
		TypesContract.SetFunctionParameterTypeResponse response = callbacks.setFunctionParameterType(
			new TypesContract.SetFunctionParameterTypeRequest(
				protoRequest.getAddress(),
				protoRequest.getOrdinal(),
				protoRequest.getDataType()));
		if (response != null && !response.updated() && response.errorMessage() != null &&
			!response.errorMessage().isBlank()) {
			return error(
				response.errorCode() != null && !response.errorCode().isBlank()
					? response.errorCode()
					: "set_function_parameter_type_failed",
				response.errorMessage());
		}
		libghidra.SetFunctionParameterTypeResponse proto =
			libghidra.SetFunctionParameterTypeResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.setDataType(nullable(response != null ? response.dataType() : null))
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesRenameFunctionLocal(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.RenameFunctionLocalRequest protoRequest = unpackPayload(request,
			libghidra.RenameFunctionLocalRequest.class,
			libghidra.RenameFunctionLocalRequest.getDefaultInstance());
		TypesContract.RenameFunctionLocalResponse response = callbacks.renameFunctionLocal(
			new TypesContract.RenameFunctionLocalRequest(
				protoRequest.getAddress(),
				protoRequest.getLocalId(),
				protoRequest.getNewName()));
		if (response != null && !response.updated() && response.errorMessage() != null &&
			!response.errorMessage().isBlank()) {
			return error(
				response.errorCode() != null && !response.errorCode().isBlank()
					? response.errorCode()
					: "rename_function_local_failed",
				response.errorMessage());
		}
		libghidra.RenameFunctionLocalResponse proto =
			libghidra.RenameFunctionLocalResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.setLocalId(nullable(response != null ? response.localId() : null))
				.setName(nullable(response != null ? response.name() : null))
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesSetFunctionLocalType(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetFunctionLocalTypeRequest protoRequest = unpackPayload(request,
			libghidra.SetFunctionLocalTypeRequest.class,
			libghidra.SetFunctionLocalTypeRequest.getDefaultInstance());
		TypesContract.SetFunctionLocalTypeResponse response = callbacks.setFunctionLocalType(
			new TypesContract.SetFunctionLocalTypeRequest(
				protoRequest.getAddress(),
				protoRequest.getLocalId(),
				protoRequest.getDataType()));
		if (response != null && !response.updated() && response.errorMessage() != null &&
			!response.errorMessage().isBlank()) {
			return error(
				response.errorCode() != null && !response.errorCode().isBlank()
					? response.errorCode()
					: "set_function_local_type_failed",
				response.errorMessage());
		}
		libghidra.SetFunctionLocalTypeResponse proto =
			libghidra.SetFunctionLocalTypeResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.setLocalId(nullable(response != null ? response.localId() : null))
				.setDataType(nullable(response != null ? response.dataType() : null))
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesApplyDataType(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ApplyDataTypeRequest protoRequest = unpackPayload(request,
			libghidra.ApplyDataTypeRequest.class,
			libghidra.ApplyDataTypeRequest.getDefaultInstance());
		TypesContract.ApplyDataTypeResponse response = callbacks.applyDataType(
			new TypesContract.ApplyDataTypeRequest(
				protoRequest.getAddress(),
				protoRequest.getDataType()));
		libghidra.ApplyDataTypeResponse proto = libghidra.ApplyDataTypeResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.setDataType(nullable(response != null ? response.dataType() : null))
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesCreateType(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.CreateTypeRequest protoRequest = unpackPayload(request,
			libghidra.CreateTypeRequest.class,
			libghidra.CreateTypeRequest.getDefaultInstance());
		TypesContract.CreateTypeResponse response = callbacks.createType(
			new TypesContract.CreateTypeRequest(
				protoRequest.getName(),
				protoRequest.getKind(),
				protoRequest.getSize()));
		libghidra.CreateTypeResponse proto = libghidra.CreateTypeResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesDeleteType(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteTypeRequest protoRequest = unpackPayload(request,
			libghidra.DeleteTypeRequest.class,
			libghidra.DeleteTypeRequest.getDefaultInstance());
		TypesContract.DeleteTypeResponse response = callbacks.deleteType(
			new TypesContract.DeleteTypeRequest(
				protoRequest.getType()));
		libghidra.DeleteTypeResponse proto = libghidra.DeleteTypeResponse.newBuilder()
			.setDeleted(response != null && response.deleted())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesRenameType(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.RenameTypeRequest protoRequest = unpackPayload(request,
			libghidra.RenameTypeRequest.class,
			libghidra.RenameTypeRequest.getDefaultInstance());
		TypesContract.RenameTypeResponse response = callbacks.renameType(
			new TypesContract.RenameTypeRequest(
				protoRequest.getType(),
				protoRequest.getNewName()));
		libghidra.RenameTypeResponse proto = libghidra.RenameTypeResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.setName(nullable(response != null ? response.name() : null))
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesCreateTypeAlias(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.CreateTypeAliasRequest protoRequest = unpackPayload(request,
			libghidra.CreateTypeAliasRequest.class,
			libghidra.CreateTypeAliasRequest.getDefaultInstance());
		TypesContract.CreateTypeAliasResponse response = callbacks.createTypeAlias(
			new TypesContract.CreateTypeAliasRequest(
				protoRequest.getName(),
				protoRequest.getTargetType()));
		libghidra.CreateTypeAliasResponse proto = libghidra.CreateTypeAliasResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesDeleteTypeAlias(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteTypeAliasRequest protoRequest = unpackPayload(request,
			libghidra.DeleteTypeAliasRequest.class,
			libghidra.DeleteTypeAliasRequest.getDefaultInstance());
		TypesContract.DeleteTypeAliasResponse response = callbacks.deleteTypeAlias(
			new TypesContract.DeleteTypeAliasRequest(
				protoRequest.getType()));
		libghidra.DeleteTypeAliasResponse proto = libghidra.DeleteTypeAliasResponse.newBuilder()
			.setDeleted(response != null && response.deleted())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesSetTypeAliasTarget(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetTypeAliasTargetRequest protoRequest = unpackPayload(request,
			libghidra.SetTypeAliasTargetRequest.class,
			libghidra.SetTypeAliasTargetRequest.getDefaultInstance());
		TypesContract.SetTypeAliasTargetResponse response = callbacks.setTypeAliasTarget(
			new TypesContract.SetTypeAliasTargetRequest(
				protoRequest.getType(),
				protoRequest.getTargetType()));
		libghidra.SetTypeAliasTargetResponse proto =
			libghidra.SetTypeAliasTargetResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesCreateTypeEnum(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.CreateTypeEnumRequest protoRequest = unpackPayload(request,
			libghidra.CreateTypeEnumRequest.class,
			libghidra.CreateTypeEnumRequest.getDefaultInstance());
		TypesContract.CreateTypeEnumResponse response = callbacks.createTypeEnum(
			new TypesContract.CreateTypeEnumRequest(
				protoRequest.getName(),
				protoRequest.getWidth(),
				protoRequest.getSigned()));
		libghidra.CreateTypeEnumResponse proto = libghidra.CreateTypeEnumResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesDeleteTypeEnum(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteTypeEnumRequest protoRequest = unpackPayload(request,
			libghidra.DeleteTypeEnumRequest.class,
			libghidra.DeleteTypeEnumRequest.getDefaultInstance());
		TypesContract.DeleteTypeEnumResponse response = callbacks.deleteTypeEnum(
			new TypesContract.DeleteTypeEnumRequest(
				protoRequest.getType()));
		libghidra.DeleteTypeEnumResponse proto = libghidra.DeleteTypeEnumResponse.newBuilder()
			.setDeleted(response != null && response.deleted())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesAddTypeEnumMember(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.AddTypeEnumMemberRequest protoRequest = unpackPayload(request,
			libghidra.AddTypeEnumMemberRequest.class,
			libghidra.AddTypeEnumMemberRequest.getDefaultInstance());
		TypesContract.AddTypeEnumMemberResponse response = callbacks.addTypeEnumMember(
			new TypesContract.AddTypeEnumMemberRequest(
				protoRequest.getType(),
				protoRequest.getName(),
				protoRequest.getValue()));
		libghidra.AddTypeEnumMemberResponse proto =
			libghidra.AddTypeEnumMemberResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesDeleteTypeEnumMember(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteTypeEnumMemberRequest protoRequest = unpackPayload(request,
			libghidra.DeleteTypeEnumMemberRequest.class,
			libghidra.DeleteTypeEnumMemberRequest.getDefaultInstance());
		TypesContract.DeleteTypeEnumMemberResponse response = callbacks.deleteTypeEnumMember(
			new TypesContract.DeleteTypeEnumMemberRequest(
				protoRequest.getType(),
				protoRequest.getOrdinal()));
		libghidra.DeleteTypeEnumMemberResponse proto =
			libghidra.DeleteTypeEnumMemberResponse.newBuilder()
				.setDeleted(response != null && response.deleted())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesRenameTypeEnumMember(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.RenameTypeEnumMemberRequest protoRequest = unpackPayload(request,
			libghidra.RenameTypeEnumMemberRequest.class,
			libghidra.RenameTypeEnumMemberRequest.getDefaultInstance());
		TypesContract.RenameTypeEnumMemberResponse response = callbacks.renameTypeEnumMember(
			new TypesContract.RenameTypeEnumMemberRequest(
				protoRequest.getType(),
				protoRequest.getOrdinal(),
				protoRequest.getNewName()));
		libghidra.RenameTypeEnumMemberResponse proto =
			libghidra.RenameTypeEnumMemberResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesSetTypeEnumMemberValue(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetTypeEnumMemberValueRequest protoRequest = unpackPayload(request,
			libghidra.SetTypeEnumMemberValueRequest.class,
			libghidra.SetTypeEnumMemberValueRequest.getDefaultInstance());
		TypesContract.SetTypeEnumMemberValueResponse response = callbacks.setTypeEnumMemberValue(
			new TypesContract.SetTypeEnumMemberValueRequest(
				protoRequest.getType(),
				protoRequest.getOrdinal(),
				protoRequest.getValue()));
		libghidra.SetTypeEnumMemberValueResponse proto =
			libghidra.SetTypeEnumMemberValueResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesAddTypeMember(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.AddTypeMemberRequest protoRequest = unpackPayload(request,
			libghidra.AddTypeMemberRequest.class,
			libghidra.AddTypeMemberRequest.getDefaultInstance());
		TypesContract.AddTypeMemberResponse response = callbacks.addTypeMember(
			new TypesContract.AddTypeMemberRequest(
				protoRequest.getType(),
				protoRequest.getName(),
				protoRequest.getMemberType(),
				protoRequest.getSize()));
		libghidra.AddTypeMemberResponse proto = libghidra.AddTypeMemberResponse.newBuilder()
			.setUpdated(response != null && response.updated())
			.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesDeleteTypeMember(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.DeleteTypeMemberRequest protoRequest = unpackPayload(request,
			libghidra.DeleteTypeMemberRequest.class,
			libghidra.DeleteTypeMemberRequest.getDefaultInstance());
		TypesContract.DeleteTypeMemberResponse response = callbacks.deleteTypeMember(
			new TypesContract.DeleteTypeMemberRequest(
				protoRequest.getType(),
				protoRequest.getOrdinal()));
		libghidra.DeleteTypeMemberResponse proto =
			libghidra.DeleteTypeMemberResponse.newBuilder()
				.setDeleted(response != null && response.deleted())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesRenameTypeMember(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.RenameTypeMemberRequest protoRequest = unpackPayload(request,
			libghidra.RenameTypeMemberRequest.class,
			libghidra.RenameTypeMemberRequest.getDefaultInstance());
		TypesContract.RenameTypeMemberResponse response = callbacks.renameTypeMember(
			new TypesContract.RenameTypeMemberRequest(
				protoRequest.getType(),
				protoRequest.getOrdinal(),
				protoRequest.getNewName()));
		libghidra.RenameTypeMemberResponse proto =
			libghidra.RenameTypeMemberResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesSetTypeMemberType(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetTypeMemberTypeRequest protoRequest = unpackPayload(request,
			libghidra.SetTypeMemberTypeRequest.class,
			libghidra.SetTypeMemberTypeRequest.getDefaultInstance());
		TypesContract.SetTypeMemberTypeResponse response = callbacks.setTypeMemberType(
			new TypesContract.SetTypeMemberTypeRequest(
				protoRequest.getType(),
				protoRequest.getOrdinal(),
				protoRequest.getMemberType()));
		libghidra.SetTypeMemberTypeResponse proto =
			libghidra.SetTypeMemberTypeResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesSetTypeMemberComment(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetTypeMemberCommentRequest protoRequest = unpackPayload(request,
			libghidra.SetTypeMemberCommentRequest.class,
			libghidra.SetTypeMemberCommentRequest.getDefaultInstance());
		TypesContract.SetTypeMemberCommentResponse response = callbacks.setTypeMemberComment(
			new TypesContract.SetTypeMemberCommentRequest(
				protoRequest.getType(),
				protoRequest.getOrdinal(),
				protoRequest.getComment()));
		libghidra.SetTypeMemberCommentResponse proto =
			libghidra.SetTypeMemberCommentResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesSetTypeEnumMemberComment(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.SetTypeEnumMemberCommentRequest protoRequest = unpackPayload(request,
			libghidra.SetTypeEnumMemberCommentRequest.class,
			libghidra.SetTypeEnumMemberCommentRequest.getDefaultInstance());
		TypesContract.SetTypeEnumMemberCommentResponse response = callbacks.setTypeEnumMemberComment(
			new TypesContract.SetTypeEnumMemberCommentRequest(
				protoRequest.getType(),
				protoRequest.getOrdinal(),
				protoRequest.getComment()));
		libghidra.SetTypeEnumMemberCommentResponse proto =
			libghidra.SetTypeEnumMemberCommentResponse.newBuilder()
				.setUpdated(response != null && response.updated())
				.build();
		return ok(proto, 0L);
	}

	private libghidra.RpcResponse typesParseDeclarations(libghidra.RpcRequest request)
			throws InvalidProtocolBufferException {
		libghidra.ParseDeclarationsRequest protoRequest = unpackPayload(request,
			libghidra.ParseDeclarationsRequest.class,
			libghidra.ParseDeclarationsRequest.getDefaultInstance());
		TypesContract.ParseDeclarationsResponse response = callbacks.parseDeclarations(
			new TypesContract.ParseDeclarationsRequest(
				protoRequest.getSourceText()));
		libghidra.ParseDeclarationsResponse.Builder builder =
			libghidra.ParseDeclarationsResponse.newBuilder()
				.setTypesCreated(response != null ? response.typesCreated() : 0);
		if (response != null && response.typeNames() != null) {
			builder.addAllTypeNames(response.typeNames());
		}
		if (response != null && response.errors() != null) {
			builder.addAllErrors(response.errors());
		}
		return ok(builder.build(), 0L);
	}

	private static libghidra.DecompileRecord toDecompileRecord(DecompilerContract.DecompileRecord row) {
		if (row == null) {
			return libghidra.DecompileRecord.getDefaultInstance();
		}
		libghidra.DecompileRecord.Builder builder = libghidra.DecompileRecord.newBuilder()
			.setFunctionEntryAddress(row.functionEntryAddress())
			.setFunctionName(nullable(row.functionName()))
			.setPrototype(nullable(row.prototype()))
			.setPseudocode(nullable(row.pseudocode()))
			.setCompleted(row.completed())
			.setIsFallback(row.isFallback())
			.setErrorMessage(nullable(row.errorMessage()));
		if (row.locals() != null) {
			for (DecompilerContract.DecompileLocalRecord local : row.locals()) {
				builder.addLocals(toDecompileLocalRecord(local));
			}
		}
		if (row.tokens() != null) {
			for (DecompilerContract.DecompileTokenRecord token : row.tokens()) {
				builder.addTokens(toDecompileTokenRecord(token));
			}
		}
		return builder.build();
	}

	private static libghidra.DecompileTokenRecord toDecompileTokenRecord(DecompilerContract.DecompileTokenRecord row) {
		if (row == null) {
			return libghidra.DecompileTokenRecord.getDefaultInstance();
		}
		libghidra.DecompileTokenRecord.Builder builder = libghidra.DecompileTokenRecord.newBuilder()
			.setText(nullable(row.text()))
			.setKind(toProtoDecompileTokenKind(row.kind()))
			.setLineNumber(row.lineNumber())
			.setColumnOffset(row.columnOffset())
			.setVarName(nullable(row.varName()))
			.setVarType(nullable(row.varType()))
			.setVarStorage(nullable(row.varStorage()));
		return builder.build();
	}

	private static libghidra.DecompileTokenKind toProtoDecompileTokenKind(DecompilerContract.DecompileTokenKind kind) {
		if (kind == null) {
			return libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_UNSPECIFIED;
		}
		return switch (kind) {
			case KEYWORD -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_KEYWORD;
			case COMMENT -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_COMMENT;
			case TYPE -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_TYPE;
			case FUNCTION -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_FUNCTION;
			case VARIABLE -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_VARIABLE;
			case CONST -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_CONST;
			case PARAMETER -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_PARAMETER;
			case GLOBAL -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_GLOBAL;
			case DEFAULT -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_DEFAULT;
			case ERROR -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_ERROR;
			case SPECIAL -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_SPECIAL;
			case UNSPECIFIED -> libghidra.DecompileTokenKind.DECOMPILE_TOKEN_KIND_UNSPECIFIED;
		};
	}

	private static libghidra.DecompileLocalRecord toDecompileLocalRecord(
			DecompilerContract.DecompileLocalRecord row) {
		if (row == null) {
			return libghidra.DecompileLocalRecord.getDefaultInstance();
		}
		return libghidra.DecompileLocalRecord.newBuilder()
			.setLocalId(nullable(row.localId()))
			.setKind(toDecompileLocalKind(row.kind()))
			.setName(nullable(row.name()))
			.setDataType(nullable(row.dataType()))
			.setStorage(nullable(row.storage()))
			.setOrdinal(row.ordinal())
			.build();
	}

	private static libghidra.DecompileLocalKind toDecompileLocalKind(
			DecompilerContract.DecompileLocalKind kind) {
		if (kind == null) {
			return libghidra.DecompileLocalKind.DECOMPILE_LOCAL_KIND_UNSPECIFIED;
		}
		switch (kind) {
			case PARAM:
				return libghidra.DecompileLocalKind.DECOMPILE_LOCAL_KIND_PARAM;
			case LOCAL:
				return libghidra.DecompileLocalKind.DECOMPILE_LOCAL_KIND_LOCAL;
			case TEMP:
				return libghidra.DecompileLocalKind.DECOMPILE_LOCAL_KIND_TEMP;
			case UNSPECIFIED:
			default:
				return libghidra.DecompileLocalKind.DECOMPILE_LOCAL_KIND_UNSPECIFIED;
		}
	}

	private static libghidra.InstructionRecord toInstructionRecord(ListingContract.InstructionRecord row) {
		if (row == null) {
			return libghidra.InstructionRecord.getDefaultInstance();
		}
		return libghidra.InstructionRecord.newBuilder()
			.setAddress(row.address())
			.setMnemonic(nullable(row.mnemonic()))
			.setOperandText(nullable(row.operandText()))
			.setDisassembly(nullable(row.disassembly()))
			.setLength(row.length())
			.build();
	}

	private static libghidra.CommentRecord toCommentRecord(ListingContract.CommentRecord row) {
		if (row == null) {
			return libghidra.CommentRecord.getDefaultInstance();
		}
		return libghidra.CommentRecord.newBuilder()
			.setAddress(row.address())
			.setKind(toProtoCommentKind(row.kind()))
			.setText(nullable(row.text()))
			.build();
	}

	private static libghidra.BookmarkRecord toBookmarkRecord(ListingContract.BookmarkRecord row) {
		if (row == null) {
			return libghidra.BookmarkRecord.getDefaultInstance();
		}
		return libghidra.BookmarkRecord.newBuilder()
			.setAddress(row.address())
			.setType(nullable(row.type()))
			.setCategory(nullable(row.category()))
			.setComment(nullable(row.comment()))
			.build();
	}

	private static libghidra.DataItemRecord toDataItemRecord(ListingContract.DataItemRecord row) {
		if (row == null) {
			return libghidra.DataItemRecord.getDefaultInstance();
		}
		return libghidra.DataItemRecord.newBuilder()
			.setAddress(row.address())
			.setEndAddress(row.endAddress())
			.setName(nullable(row.name()))
			.setDataType(nullable(row.dataType()))
			.setSize(row.size())
			.setValueRepr(nullable(row.valueRepr()))
			.build();
	}

	private static libghidra.BreakpointRecord toBreakpointRecord(ListingContract.BreakpointRecord row) {
		if (row == null) {
			return libghidra.BreakpointRecord.getDefaultInstance();
		}
		return libghidra.BreakpointRecord.newBuilder()
			.setAddress(row.address())
			.setEnabled(row.enabled())
			.setKind(nullable(row.kind()))
			.setSize(row.size())
			.setCondition(nullable(row.condition()))
			.setGroup(nullable(row.group()))
			.build();
	}

	private static libghidra.TypeRecord toTypeRecord(TypesContract.TypeRecord row) {
		if (row == null) {
			return libghidra.TypeRecord.getDefaultInstance();
		}
		return libghidra.TypeRecord.newBuilder()
			.setTypeId(row.typeId())
			.setName(nullable(row.name()))
			.setPathName(nullable(row.pathName()))
			.setCategoryPath(nullable(row.categoryPath()))
			.setDisplayName(nullable(row.displayName()))
			.setKind(nullable(row.kind()))
			.setLength(row.length())
			.setIsNotYetDefined(row.isNotYetDefined())
			.setSourceArchive(nullable(row.sourceArchive()))
			.setUniversalId(nullable(row.universalId()))
			.build();
	}

	private static libghidra.TypeAliasRecord toTypeAliasRecord(TypesContract.TypeAliasRecord row) {
		if (row == null) {
			return libghidra.TypeAliasRecord.getDefaultInstance();
		}
		return libghidra.TypeAliasRecord.newBuilder()
			.setTypeId(row.typeId())
			.setPathName(nullable(row.pathName()))
			.setName(nullable(row.name()))
			.setTargetType(nullable(row.targetType()))
			.setDeclaration(nullable(row.declaration()))
			.build();
	}

	private static libghidra.TypeUnionRecord toTypeUnionRecord(TypesContract.TypeUnionRecord row) {
		if (row == null) {
			return libghidra.TypeUnionRecord.getDefaultInstance();
		}
		return libghidra.TypeUnionRecord.newBuilder()
			.setTypeId(row.typeId())
			.setPathName(nullable(row.pathName()))
			.setName(nullable(row.name()))
			.setSize(row.size())
			.setDeclaration(nullable(row.declaration()))
			.build();
	}

	private static libghidra.TypeEnumRecord toTypeEnumRecord(TypesContract.TypeEnumRecord row) {
		if (row == null) {
			return libghidra.TypeEnumRecord.getDefaultInstance();
		}
		return libghidra.TypeEnumRecord.newBuilder()
			.setTypeId(row.typeId())
			.setPathName(nullable(row.pathName()))
			.setName(nullable(row.name()))
			.setWidth(row.width())
			.setSigned(row.signed())
			.setDeclaration(nullable(row.declaration()))
			.build();
	}

	private static libghidra.TypeEnumMemberRecord toTypeEnumMemberRecord(
			TypesContract.TypeEnumMemberRecord row) {
		if (row == null) {
			return libghidra.TypeEnumMemberRecord.getDefaultInstance();
		}
		return libghidra.TypeEnumMemberRecord.newBuilder()
			.setTypeId(row.typeId())
			.setTypePathName(nullable(row.typePathName()))
			.setTypeName(nullable(row.typeName()))
			.setOrdinal(row.ordinal())
			.setName(nullable(row.name()))
			.setValue(row.value())
			.setComment(nullable(row.comment()))
			.build();
	}

	private static libghidra.TypeMemberRecord toTypeMemberRecord(TypesContract.TypeMemberRecord row) {
		if (row == null) {
			return libghidra.TypeMemberRecord.getDefaultInstance();
		}
		return libghidra.TypeMemberRecord.newBuilder()
			.setParentTypeId(row.parentTypeId())
			.setParentTypePathName(nullable(row.parentTypePathName()))
			.setParentTypeName(nullable(row.parentTypeName()))
			.setOrdinal(row.ordinal())
			.setName(nullable(row.name()))
			.setMemberType(nullable(row.memberType()))
			.setOffset(row.offset())
			.setSize(row.size())
			.setComment(nullable(row.comment()))
			.build();
	}

	private static libghidra.FunctionRecord toFunctionRecord(FunctionsContract.FunctionRecord row) {
		if (row == null) {
			return libghidra.FunctionRecord.getDefaultInstance();
		}
		return libghidra.FunctionRecord.newBuilder()
			.setEntryAddress(row.entryAddress())
			.setName(nullable(row.name()))
			.setStartAddress(row.startAddress())
			.setEndAddress(row.endAddress())
			.setSize(row.size())
			.setNamespaceName(nullable(row.namespaceName()))
			.setPrototype(nullable(row.prototype()))
			.setIsThunk(row.isThunk())
			.setParameterCount(row.parameterCount())
			.build();
	}

	private static libghidra.SymbolRecord toSymbolRecord(SymbolsContract.SymbolRecord row) {
		if (row == null) {
			return libghidra.SymbolRecord.getDefaultInstance();
		}
		return libghidra.SymbolRecord.newBuilder()
			.setSymbolId(row.symbolId())
			.setAddress(row.address())
			.setName(nullable(row.name()))
			.setFullName(nullable(row.fullName()))
			.setType(nullable(row.type()))
			.setNamespaceName(nullable(row.namespaceName()))
			.setSource(nullable(row.source()))
			.setIsPrimary(row.isPrimary())
			.setIsExternal(row.isExternal())
			.setIsDynamic(row.isDynamic())
			.build();
	}

	private static libghidra.XrefRecord toXrefRecord(XrefsContract.XrefRecord row) {
		if (row == null) {
			return libghidra.XrefRecord.getDefaultInstance();
		}
		return libghidra.XrefRecord.newBuilder()
			.setFromAddress(row.fromAddress())
			.setToAddress(row.toAddress())
			.setOperandIndex(row.operandIndex())
			.setRefType(nullable(row.refType()))
			.setIsPrimary(row.isPrimary())
			.setSource(nullable(row.source()))
			.setSymbolId(row.symbolId())
			.setIsExternal(row.isExternal())
			.setIsMemory(row.isMemory())
			.setIsFlow(row.isFlow())
			.build();
	}

	private static libghidra.ParameterRecord toParameterRecord(TypesContract.ParameterRecord row) {
		if (row == null) {
			return libghidra.ParameterRecord.getDefaultInstance();
		}
		return libghidra.ParameterRecord.newBuilder()
			.setOrdinal(row.ordinal())
			.setName(nullable(row.name()))
			.setDataType(nullable(row.dataType()))
			.setFormalDataType(nullable(row.formalDataType()))
			.setIsAutoParameter(row.isAutoParameter())
			.setIsForcedIndirect(row.isForcedIndirect())
			.build();
	}

	private static libghidra.FunctionSignatureRecord toSignatureRecord(
			TypesContract.FunctionSignatureRecord row) {
		if (row == null) {
			return libghidra.FunctionSignatureRecord.getDefaultInstance();
		}
		libghidra.FunctionSignatureRecord.Builder out =
			libghidra.FunctionSignatureRecord.newBuilder()
				.setFunctionEntryAddress(row.functionEntryAddress())
				.setFunctionName(nullable(row.functionName()))
				.setPrototype(nullable(row.prototype()))
				.setReturnType(nullable(row.returnType()))
				.setHasVarArgs(row.hasVarArgs())
				.setCallingConvention(nullable(row.callingConvention()));
		if (row.parameters() != null) {
			for (TypesContract.ParameterRecord param : row.parameters()) {
				out.addParameters(toParameterRecord(param));
			}
		}
		return out.build();
	}

	private static SessionContract.ShutdownPolicy toPolicy(libghidra.ShutdownPolicy policy) {
		if (policy == null) {
			return SessionContract.ShutdownPolicy.UNSPECIFIED;
		}
		switch (policy) {
			case SHUTDOWN_POLICY_SAVE:
				return SessionContract.ShutdownPolicy.SAVE;
			case SHUTDOWN_POLICY_DISCARD:
				return SessionContract.ShutdownPolicy.DISCARD;
			case SHUTDOWN_POLICY_NONE:
				return SessionContract.ShutdownPolicy.NONE;
			default:
				return SessionContract.ShutdownPolicy.UNSPECIFIED;
		}
	}

	private static ListingContract.CommentKind toCommentKind(libghidra.CommentKind kind) {
		if (kind == null) {
			return ListingContract.CommentKind.UNSPECIFIED;
		}
		switch (kind) {
			case COMMENT_KIND_EOL:
				return ListingContract.CommentKind.EOL;
			case COMMENT_KIND_PRE:
				return ListingContract.CommentKind.PRE;
			case COMMENT_KIND_POST:
				return ListingContract.CommentKind.POST;
			case COMMENT_KIND_PLATE:
				return ListingContract.CommentKind.PLATE;
			case COMMENT_KIND_REPEATABLE:
				return ListingContract.CommentKind.REPEATABLE;
			case COMMENT_KIND_UNSPECIFIED:
			default:
				return ListingContract.CommentKind.UNSPECIFIED;
		}
	}

	private static libghidra.CommentKind toProtoCommentKind(ListingContract.CommentKind kind) {
		if (kind == null) {
			return libghidra.CommentKind.COMMENT_KIND_UNSPECIFIED;
		}
		switch (kind) {
			case EOL:
				return libghidra.CommentKind.COMMENT_KIND_EOL;
			case PRE:
				return libghidra.CommentKind.COMMENT_KIND_PRE;
			case POST:
				return libghidra.CommentKind.COMMENT_KIND_POST;
			case PLATE:
				return libghidra.CommentKind.COMMENT_KIND_PLATE;
			case REPEATABLE:
				return libghidra.CommentKind.COMMENT_KIND_REPEATABLE;
			case UNSPECIFIED:
			default:
				return libghidra.CommentKind.COMMENT_KIND_UNSPECIFIED;
		}
	}

	private static List<String> copyStrings(List<String> in) {
		if (in == null || in.isEmpty()) {
			return List.of();
		}
		List<String> out = new ArrayList<>(in.size());
		for (String item : in) {
			out.add(nullable(item));
		}
		return out;
	}

	private static <T extends Message> T unpackPayload(
			libghidra.RpcRequest request,
			Class<T> payloadClass,
			T defaultInstance) throws InvalidProtocolBufferException {
		if (request == null || !request.hasPayload()) {
			return defaultInstance;
		}
		Any any = request.getPayload();
		if (any == null || any.equals(Any.getDefaultInstance())) {
			return defaultInstance;
		}
		return any.unpack(payloadClass);
	}

	private static String nullable(String value) {
		return value != null ? value : "";
	}

	private static ByteString toByteString(byte[] data) {
		return data != null ? ByteString.copyFrom(data) : ByteString.EMPTY;
	}

	private static libghidra.RpcResponse ok(Message payload, long revision) {
		libghidra.RpcResponse.Builder out = libghidra.RpcResponse.newBuilder()
			.setSuccess(true)
			.setRevision(revision);
		if (payload != null) {
			out.setPayload(Any.pack(payload));
		}
		return out.build();
	}

	private static libghidra.RpcResponse error(String code, String message) {
		return libghidra.RpcResponse.newBuilder()
			.setSuccess(false)
			.setErrorCode(nullable(code))
			.setErrorMessage(nullable(message))
			.build();
	}
}
