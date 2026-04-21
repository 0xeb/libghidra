package libghidra.host;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import libghidra.host.contract.FunctionsContract;
import libghidra.host.contract.ListingContract;
import libghidra.host.contract.SessionContract;
import libghidra.host.contract.SymbolsContract;
import libghidra.host.contract.DecompilerContract;
import libghidra.host.contract.TypesContract;
import libghidra.host.contract.XrefsContract;
import libghidra.host.http.LibGhidraHttpServer;
import libghidra.host.runtime.HostState;
import libghidra.host.runtime.RuntimeBundle;
import libghidra.host.runtime.SessionRuntime;
import libghidra.host.service.FunctionsServiceHandler;
import libghidra.host.service.HealthServiceHandler;
import libghidra.host.service.ListingServiceHandler;
import libghidra.host.service.MemoryServiceHandler;
import libghidra.host.service.SessionServiceHandler;
import libghidra.host.service.SymbolsServiceHandler;
import libghidra.host.service.DecompilerServiceHandler;
import libghidra.host.service.TypesServiceHandler;
import libghidra.host.service.XrefsServiceHandler;

public final class LibGhidraHeadlessHost implements AutoCloseable {

	public enum ShutdownPolicy {
		SAVE,
		DISCARD,
		NONE
	}

	public static ShutdownPolicy parseShutdownPolicy(String raw) {
		if (raw == null || raw.isBlank()) {
			return ShutdownPolicy.SAVE;
		}
		String normalized = raw.trim().toLowerCase();
		switch (normalized) {
			case "save":
				return ShutdownPolicy.SAVE;
			case "discard":
				return ShutdownPolicy.DISCARD;
			case "none":
				return ShutdownPolicy.NONE;
			default:
				return ShutdownPolicy.SAVE;
		}
	}

	private final Object stateLock = new Object();
	private final RuntimeBundle runtimes;
	private final HealthServiceHandler healthHandler;
	private final SessionServiceHandler sessionHandler;
	private final MemoryServiceHandler memoryHandler;
	private final FunctionsServiceHandler functionsHandler;
	private final SymbolsServiceHandler symbolsHandler;
	private final XrefsServiceHandler xrefsHandler;
	private final TypesServiceHandler typesHandler;
	private final DecompilerServiceHandler decompilerHandler;
	private final ListingServiceHandler listingHandler;
	private final LibGhidraHttpServer server = new LibGhidraHttpServer();

	private final String bindAddress;
	private final int listenPort;
	private final String authToken;
	private final ShutdownPolicy shutdownPolicy;
	private final AtomicBoolean shutdownAccepted = new AtomicBoolean(false);
	private final AtomicBoolean shutdownPolicyApplied = new AtomicBoolean(false);

	private int boundPort;
	private boolean closed;

	public LibGhidraHeadlessHost(
			Program program,
			String bindAddress,
			int listenPort,
			String authToken,
			ShutdownPolicy shutdownPolicy) {
		this(new RuntimeBundle("headless"), bindAddress, listenPort, authToken, shutdownPolicy);
		runtimes.session().bindProgram(program, "headless");
	}

	public LibGhidraHeadlessHost(
			ProjectData projectData,
			Object programConsumer,
			TaskMonitor taskMonitor,
			String projectPath,
			String projectName,
			Program program,
			String programPath,
			String bindAddress,
			int listenPort,
			String authToken,
			ShutdownPolicy shutdownPolicy) {
		this(
			createManagedRuntimeBundle(projectData, programConsumer, taskMonitor, projectPath, projectName),
			bindAddress,
			listenPort,
			authToken,
			shutdownPolicy);
		runtimes.session().bindProgram(program, "headless", programPath);
	}

	private LibGhidraHeadlessHost(
			RuntimeBundle runtimes,
			String bindAddress,
			int listenPort,
			String authToken,
			ShutdownPolicy shutdownPolicy) {
		this.runtimes = runtimes;
		healthHandler = new HealthServiceHandler(runtimes.health());
		sessionHandler = new SessionServiceHandler(runtimes.session());
		memoryHandler = new MemoryServiceHandler(runtimes.memory());
		functionsHandler = new FunctionsServiceHandler(runtimes.functions());
		symbolsHandler = new SymbolsServiceHandler(runtimes.symbols());
		xrefsHandler = new XrefsServiceHandler(runtimes.xrefs());
		typesHandler = new TypesServiceHandler(runtimes.types());
		decompilerHandler = new DecompilerServiceHandler(runtimes.decompiler());
		listingHandler = new ListingServiceHandler(runtimes.listing());
		this.bindAddress = bindAddress != null && !bindAddress.isBlank() ? bindAddress : "127.0.0.1";
		this.listenPort = Math.max(0, listenPort);
		this.authToken = authToken != null ? authToken : "";
		this.shutdownPolicy = shutdownPolicy != null ? shutdownPolicy : ShutdownPolicy.SAVE;
	}

	public int startServer() throws IOException {
		synchronized (stateLock) {
			if (closed) {
				throw new IllegalStateException("headless host already closed");
			}
			shutdownAccepted.set(false);
			shutdownPolicyApplied.set(false);
			boundPort = server.start(bindAddress, listenPort, authToken, newCallbacks());
			return boundPort;
		}
	}

	public int startServerWithRetry(int maxAttempts, long initialBackoffMs, long maxBackoffMs)
			throws IOException, InterruptedException {
		int attempts = Math.max(1, maxAttempts);
		long backoffMs = Math.max(1L, initialBackoffMs);
		long backoffCapMs = Math.max(backoffMs, maxBackoffMs);
		IOException lastFailure = null;
		for (int attempt = 1; attempt <= attempts; attempt++) {
			try {
				return startServer();
			}
			catch (IOException e) {
				lastFailure = e;
				if (attempt >= attempts) {
					throw e;
				}
				Thread.sleep(backoffMs);
				backoffMs = Math.min(backoffCapMs, backoffMs * 2L);
			}
		}
		throw lastFailure != null ? lastFailure : new IOException("failed to start headless host");
	}

	public void stopServer() {
		synchronized (stateLock) {
			server.stop();
		}
	}

	public boolean isRunning() {
		synchronized (stateLock) {
			return server.isRunning();
		}
	}

	public int getBoundPort() {
		synchronized (stateLock) {
			return boundPort;
		}
	}

	public void waitUntilStopped(int timeoutSeconds) throws InterruptedException {
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(Math.max(1, timeoutSeconds));
		while (isRunning() && System.nanoTime() < deadline) {
			Thread.sleep(50L);
		}
	}

	@Override
	public void close() {
		synchronized (stateLock) {
			if (closed) {
				return;
			}
			server.stop();
			try {
				if (!shutdownPolicyApplied.get()) {
					applyShutdownPolicy();
				}
				runtimes.session().releaseOwnedProgram();
			}
			catch (Exception e) {
				ghidra.util.Msg.error(this, "shutdown policy failed: " + e.getMessage(), e);
			}
			closed = true;
		}
	}

	public String getShutdownPolicyName() {
		return shutdownPolicy.name().toLowerCase();
	}

	private LibGhidraHttpServer.Callbacks newCallbacks() {
		return new LibGhidraHttpServer.Callbacks() {
			@Override
			public libghidra.host.contract.HealthContract.HealthStatusResponse healthStatus(
					libghidra.host.contract.HealthContract.HealthStatusRequest request) {
				return healthHandler.getStatus(request);
			}

			@Override
			public libghidra.host.contract.HealthContract.CapabilityResponse capabilities(
					libghidra.host.contract.HealthContract.CapabilityRequest request) {
				return healthHandler.getCapabilities(request);
			}

			@Override
			public SessionContract.OpenProgramResponse openProgram(
					SessionContract.OpenProgramRequest request) {
				return sessionHandler.openProgram(request);
			}

			@Override
			public SessionContract.CloseProgramResponse closeProgram(
					SessionContract.CloseProgramRequest request) {
				return sessionHandler.closeProgram(request);
			}

			@Override
			public SessionContract.SaveProgramResponse saveProgram(
					SessionContract.SaveProgramRequest request) {
				return sessionHandler.saveProgram(request);
			}

			@Override
			public SessionContract.DiscardProgramResponse discardProgram(
					SessionContract.DiscardProgramRequest request) {
				return sessionHandler.discardProgram(request);
			}

			@Override
			public SessionContract.GetRevisionResponse getRevision(
					SessionContract.GetRevisionRequest request) {
				return sessionHandler.getRevision(request);
			}

			@Override
			public SessionContract.ShutdownResponse shutdown(SessionContract.ShutdownRequest request) {
				SessionContract.ShutdownResponse response = sessionHandler.shutdown(request);
				if (response != null && response.accepted()) {
					shutdownAccepted.set(true);
					shutdownPolicyApplied.set(true);
				}
				return response;
			}

			@Override
			public void afterRpcResponse(String methodName) {
				if ("libghidra.SessionService/Shutdown".equals(methodName) &&
					shutdownAccepted.compareAndSet(true, false)) {
					stopServerAfterResponseFlush();
				}
			}

			@Override
			public libghidra.host.contract.MemoryContract.ReadBytesResponse readBytes(
					libghidra.host.contract.MemoryContract.ReadBytesRequest request) {
				return memoryHandler.readBytes(request);
			}

			@Override
			public libghidra.host.contract.MemoryContract.WriteBytesResponse writeBytes(
					libghidra.host.contract.MemoryContract.WriteBytesRequest request) {
				return memoryHandler.writeBytes(request);
			}

			@Override
			public libghidra.host.contract.MemoryContract.PatchBytesBatchResponse patchBytes(
					libghidra.host.contract.MemoryContract.PatchBytesBatchRequest request) {
				return memoryHandler.patchBytes(request);
			}

			@Override
			public libghidra.host.contract.MemoryContract.ListMemoryBlocksResponse listMemoryBlocks(
					libghidra.host.contract.MemoryContract.ListMemoryBlocksRequest request) {
				return memoryHandler.listMemoryBlocks(request);
			}

			@Override
			public FunctionsContract.GetFunctionResponse getFunction(
					FunctionsContract.GetFunctionRequest request) {
				return functionsHandler.getFunction(request);
			}

			@Override
			public FunctionsContract.ListFunctionsResponse listFunctions(
					FunctionsContract.ListFunctionsRequest request) {
				return functionsHandler.listFunctions(request);
			}

			@Override
			public FunctionsContract.RenameFunctionResponse renameFunction(
					FunctionsContract.RenameFunctionRequest request) {
				return functionsHandler.renameFunction(request);
			}

			@Override
			public FunctionsContract.ListBasicBlocksResponse listBasicBlocks(
					FunctionsContract.ListBasicBlocksRequest request) {
				return functionsHandler.listBasicBlocks(request);
			}

			@Override
			public FunctionsContract.ListCFGEdgesResponse listCFGEdges(
					FunctionsContract.ListCFGEdgesRequest request) {
				return functionsHandler.listCFGEdges(request);
			}

			@Override
			public FunctionsContract.ListFunctionTagsResponse listFunctionTags(
					FunctionsContract.ListFunctionTagsRequest request) {
				return functionsHandler.listFunctionTags(request);
			}

			@Override
			public FunctionsContract.CreateFunctionTagResponse createFunctionTag(
					FunctionsContract.CreateFunctionTagRequest request) {
				return functionsHandler.createFunctionTag(request);
			}

			@Override
			public FunctionsContract.DeleteFunctionTagResponse deleteFunctionTag(
					FunctionsContract.DeleteFunctionTagRequest request) {
				return functionsHandler.deleteFunctionTag(request);
			}

			@Override
			public FunctionsContract.ListFunctionTagMappingsResponse listFunctionTagMappings(
					FunctionsContract.ListFunctionTagMappingsRequest request) {
				return functionsHandler.listFunctionTagMappings(request);
			}

			@Override
			public FunctionsContract.TagFunctionResponse tagFunction(
					FunctionsContract.TagFunctionRequest request) {
				return functionsHandler.tagFunction(request);
			}

			@Override
			public FunctionsContract.UntagFunctionResponse untagFunction(
					FunctionsContract.UntagFunctionRequest request) {
				return functionsHandler.untagFunction(request);
			}

			@Override
			public FunctionsContract.ListSwitchTablesResponse listSwitchTables(
					FunctionsContract.ListSwitchTablesRequest request) {
				return functionsHandler.listSwitchTables(request);
			}

			@Override
			public FunctionsContract.ListDominatorsResponse listDominators(
					FunctionsContract.ListDominatorsRequest request) {
				return functionsHandler.listDominators(request);
			}

			@Override
			public FunctionsContract.ListPostDominatorsResponse listPostDominators(
					FunctionsContract.ListPostDominatorsRequest request) {
				return functionsHandler.listPostDominators(request);
			}

			@Override
			public FunctionsContract.ListLoopsResponse listLoops(
					FunctionsContract.ListLoopsRequest request) {
				return functionsHandler.listLoops(request);
			}

			@Override
			public SymbolsContract.GetSymbolResponse getSymbol(
					SymbolsContract.GetSymbolRequest request) {
				return symbolsHandler.getSymbol(request);
			}

			@Override
			public SymbolsContract.ListSymbolsResponse listSymbols(
					SymbolsContract.ListSymbolsRequest request) {
				return symbolsHandler.listSymbols(request);
			}

			@Override
			public SymbolsContract.RenameSymbolResponse renameSymbol(
					SymbolsContract.RenameSymbolRequest request) {
				return symbolsHandler.renameSymbol(request);
			}

			@Override
			public SymbolsContract.DeleteSymbolResponse deleteSymbol(
					SymbolsContract.DeleteSymbolRequest request) {
				return symbolsHandler.deleteSymbol(request);
			}

			@Override
			public XrefsContract.ListXrefsResponse listXrefs(
					XrefsContract.ListXrefsRequest request) {
				return xrefsHandler.listXrefs(request);
			}

			@Override
			public TypesContract.GetTypeResponse getType(
					TypesContract.GetTypeRequest request) {
				return typesHandler.getType(request);
			}

			@Override
			public TypesContract.ListTypesResponse listTypes(
					TypesContract.ListTypesRequest request) {
				return typesHandler.listTypes(request);
			}

			@Override
			public TypesContract.ListTypeAliasesResponse listTypeAliases(
					TypesContract.ListTypeAliasesRequest request) {
				return typesHandler.listTypeAliases(request);
			}

			@Override
			public TypesContract.ListTypeUnionsResponse listTypeUnions(
					TypesContract.ListTypeUnionsRequest request) {
				return typesHandler.listTypeUnions(request);
			}

			@Override
			public TypesContract.ListTypeEnumsResponse listTypeEnums(
					TypesContract.ListTypeEnumsRequest request) {
				return typesHandler.listTypeEnums(request);
			}

			@Override
			public TypesContract.ListTypeEnumMembersResponse listTypeEnumMembers(
					TypesContract.ListTypeEnumMembersRequest request) {
				return typesHandler.listTypeEnumMembers(request);
			}

			@Override
			public TypesContract.ListTypeMembersResponse listTypeMembers(
					TypesContract.ListTypeMembersRequest request) {
				return typesHandler.listTypeMembers(request);
			}

			@Override
			public TypesContract.GetFunctionSignatureResponse getFunctionSignature(
					TypesContract.GetFunctionSignatureRequest request) {
				return typesHandler.getFunctionSignature(request);
			}

			@Override
			public TypesContract.ListFunctionSignaturesResponse listFunctionSignatures(
					TypesContract.ListFunctionSignaturesRequest request) {
				return typesHandler.listFunctionSignatures(request);
			}

			@Override
			public TypesContract.SetFunctionSignatureResponse setFunctionSignature(
					TypesContract.SetFunctionSignatureRequest request) {
				return typesHandler.setFunctionSignature(request);
			}

			@Override
			public TypesContract.RenameFunctionParameterResponse renameFunctionParameter(
					TypesContract.RenameFunctionParameterRequest request) {
				return typesHandler.renameFunctionParameter(request);
			}

			@Override
			public TypesContract.SetFunctionParameterTypeResponse setFunctionParameterType(
					TypesContract.SetFunctionParameterTypeRequest request) {
				return typesHandler.setFunctionParameterType(request);
			}

			@Override
			public TypesContract.RenameFunctionLocalResponse renameFunctionLocal(
					TypesContract.RenameFunctionLocalRequest request) {
				return typesHandler.renameFunctionLocal(request);
			}

			@Override
			public TypesContract.SetFunctionLocalTypeResponse setFunctionLocalType(
					TypesContract.SetFunctionLocalTypeRequest request) {
				return typesHandler.setFunctionLocalType(request);
			}

			@Override
			public TypesContract.ApplyDataTypeResponse applyDataType(
					TypesContract.ApplyDataTypeRequest request) {
				return typesHandler.applyDataType(request);
			}

			@Override
			public TypesContract.CreateTypeResponse createType(
					TypesContract.CreateTypeRequest request) {
				return typesHandler.createType(request);
			}

			@Override
			public TypesContract.DeleteTypeResponse deleteType(
					TypesContract.DeleteTypeRequest request) {
				return typesHandler.deleteType(request);
			}

			@Override
			public TypesContract.RenameTypeResponse renameType(
					TypesContract.RenameTypeRequest request) {
				return typesHandler.renameType(request);
			}

			@Override
			public TypesContract.CreateTypeAliasResponse createTypeAlias(
					TypesContract.CreateTypeAliasRequest request) {
				return typesHandler.createTypeAlias(request);
			}

			@Override
			public TypesContract.DeleteTypeAliasResponse deleteTypeAlias(
					TypesContract.DeleteTypeAliasRequest request) {
				return typesHandler.deleteTypeAlias(request);
			}

			@Override
			public TypesContract.SetTypeAliasTargetResponse setTypeAliasTarget(
					TypesContract.SetTypeAliasTargetRequest request) {
				return typesHandler.setTypeAliasTarget(request);
			}

			@Override
			public TypesContract.CreateTypeEnumResponse createTypeEnum(
					TypesContract.CreateTypeEnumRequest request) {
				return typesHandler.createTypeEnum(request);
			}

			@Override
			public TypesContract.DeleteTypeEnumResponse deleteTypeEnum(
					TypesContract.DeleteTypeEnumRequest request) {
				return typesHandler.deleteTypeEnum(request);
			}

			@Override
			public TypesContract.AddTypeEnumMemberResponse addTypeEnumMember(
					TypesContract.AddTypeEnumMemberRequest request) {
				return typesHandler.addTypeEnumMember(request);
			}

			@Override
			public TypesContract.DeleteTypeEnumMemberResponse deleteTypeEnumMember(
					TypesContract.DeleteTypeEnumMemberRequest request) {
				return typesHandler.deleteTypeEnumMember(request);
			}

			@Override
			public TypesContract.RenameTypeEnumMemberResponse renameTypeEnumMember(
					TypesContract.RenameTypeEnumMemberRequest request) {
				return typesHandler.renameTypeEnumMember(request);
			}

			@Override
			public TypesContract.SetTypeEnumMemberValueResponse setTypeEnumMemberValue(
					TypesContract.SetTypeEnumMemberValueRequest request) {
				return typesHandler.setTypeEnumMemberValue(request);
			}

			@Override
			public TypesContract.AddTypeMemberResponse addTypeMember(
					TypesContract.AddTypeMemberRequest request) {
				return typesHandler.addTypeMember(request);
			}

			@Override
			public TypesContract.DeleteTypeMemberResponse deleteTypeMember(
					TypesContract.DeleteTypeMemberRequest request) {
				return typesHandler.deleteTypeMember(request);
			}

			@Override
			public TypesContract.RenameTypeMemberResponse renameTypeMember(
					TypesContract.RenameTypeMemberRequest request) {
				return typesHandler.renameTypeMember(request);
			}

			@Override
			public TypesContract.SetTypeMemberTypeResponse setTypeMemberType(
					TypesContract.SetTypeMemberTypeRequest request) {
				return typesHandler.setTypeMemberType(request);
			}

			@Override
			public TypesContract.SetTypeMemberCommentResponse setTypeMemberComment(
					TypesContract.SetTypeMemberCommentRequest request) {
				return typesHandler.setTypeMemberComment(request);
			}

			@Override
			public TypesContract.SetTypeEnumMemberCommentResponse setTypeEnumMemberComment(
					TypesContract.SetTypeEnumMemberCommentRequest request) {
				return typesHandler.setTypeEnumMemberComment(request);
			}

			@Override
			public TypesContract.ParseDeclarationsResponse parseDeclarations(
					TypesContract.ParseDeclarationsRequest request) {
				return typesHandler.parseDeclarations(request);
			}

			@Override
			public DecompilerContract.DecompileFunctionResponse decompileFunction(
					DecompilerContract.DecompileFunctionRequest request) {
				return decompilerHandler.decompileFunction(request);
			}

			@Override
			public DecompilerContract.ListDecompilationsResponse listDecompilations(
					DecompilerContract.ListDecompilationsRequest request) {
				return decompilerHandler.listDecompilations(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.GetInstructionResponse getInstruction(
					libghidra.host.contract.ListingContract.GetInstructionRequest request) {
				return listingHandler.getInstruction(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.ListInstructionsResponse listInstructions(
					libghidra.host.contract.ListingContract.ListInstructionsRequest request) {
				return listingHandler.listInstructions(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.GetCommentsResponse getComments(
					libghidra.host.contract.ListingContract.GetCommentsRequest request) {
				return listingHandler.getComments(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.SetCommentResponse setComment(
					libghidra.host.contract.ListingContract.SetCommentRequest request) {
				return listingHandler.setComment(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.DeleteCommentResponse deleteComment(
					libghidra.host.contract.ListingContract.DeleteCommentRequest request) {
				return listingHandler.deleteComment(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.RenameDataItemResponse renameDataItem(
					libghidra.host.contract.ListingContract.RenameDataItemRequest request) {
				return listingHandler.renameDataItem(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.DeleteDataItemResponse deleteDataItem(
					libghidra.host.contract.ListingContract.DeleteDataItemRequest request) {
				return listingHandler.deleteDataItem(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.ListDataItemsResponse listDataItems(
					libghidra.host.contract.ListingContract.ListDataItemsRequest request) {
				return listingHandler.listDataItems(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.ListBookmarksResponse listBookmarks(
					libghidra.host.contract.ListingContract.ListBookmarksRequest request) {
				return listingHandler.listBookmarks(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.AddBookmarkResponse addBookmark(
					libghidra.host.contract.ListingContract.AddBookmarkRequest request) {
				return listingHandler.addBookmark(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.DeleteBookmarkResponse deleteBookmark(
					libghidra.host.contract.ListingContract.DeleteBookmarkRequest request) {
				return listingHandler.deleteBookmark(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.ListBreakpointsResponse listBreakpoints(
					libghidra.host.contract.ListingContract.ListBreakpointsRequest request) {
				return listingHandler.listBreakpoints(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.AddBreakpointResponse addBreakpoint(
					libghidra.host.contract.ListingContract.AddBreakpointRequest request) {
				return listingHandler.addBreakpoint(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.SetBreakpointEnabledResponse setBreakpointEnabled(
					libghidra.host.contract.ListingContract.SetBreakpointEnabledRequest request) {
				return listingHandler.setBreakpointEnabled(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.SetBreakpointKindResponse setBreakpointKind(
					libghidra.host.contract.ListingContract.SetBreakpointKindRequest request) {
				return listingHandler.setBreakpointKind(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.SetBreakpointSizeResponse setBreakpointSize(
					libghidra.host.contract.ListingContract.SetBreakpointSizeRequest request) {
				return listingHandler.setBreakpointSize(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.SetBreakpointConditionResponse setBreakpointCondition(
					libghidra.host.contract.ListingContract.SetBreakpointConditionRequest request) {
				return listingHandler.setBreakpointCondition(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.SetBreakpointGroupResponse setBreakpointGroup(
					libghidra.host.contract.ListingContract.SetBreakpointGroupRequest request) {
				return listingHandler.setBreakpointGroup(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.DeleteBreakpointResponse deleteBreakpoint(
					libghidra.host.contract.ListingContract.DeleteBreakpointRequest request) {
				return listingHandler.deleteBreakpoint(request);
			}

			@Override
			public libghidra.host.contract.ListingContract.ListDefinedStringsResponse listDefinedStrings(
					libghidra.host.contract.ListingContract.ListDefinedStringsRequest request) {
				return listingHandler.listDefinedStrings(request);
			}
		};
	}

	private void stopServerAfterResponseFlush() {
		Thread stopper = new Thread(() -> {
			try {
				Thread.sleep(150L);
			}
			catch (InterruptedException ignored) {
				Thread.currentThread().interrupt();
			}
			stopServer();
		}, "libghidra-headless-stop");
		stopper.setDaemon(true);
		stopper.start();
	}

	private void applyShutdownPolicy() {
		switch (shutdownPolicy) {
			case SAVE:
				sessionHandler.shutdown(
					new SessionContract.ShutdownRequest(SessionContract.ShutdownPolicy.SAVE));
				break;
			case DISCARD:
				sessionHandler.shutdown(
					new SessionContract.ShutdownRequest(SessionContract.ShutdownPolicy.DISCARD));
				break;
			case NONE:
			default:
				sessionHandler.shutdown(
					new SessionContract.ShutdownRequest(SessionContract.ShutdownPolicy.NONE));
				break;
		}
	}

	private static RuntimeBundle createManagedRuntimeBundle(
			ProjectData projectData,
			Object programConsumer,
			TaskMonitor taskMonitor,
			String projectPath,
			String projectName) {
		HostState state = new HostState("headless");
		SessionRuntime session = SessionRuntime.forManagedHeadless(
			state,
			projectData,
			programConsumer,
			taskMonitor,
			projectPath,
			projectName);
		return new RuntimeBundle(state, session);
	}
}
