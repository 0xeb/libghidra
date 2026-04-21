package libghidra.host.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.protobuf.InvalidProtocolBufferException;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import libghidra.host.contract.FunctionsContract;
import libghidra.host.contract.HealthContract;
import libghidra.host.contract.ListingContract;
import libghidra.host.contract.MemoryContract;
import libghidra.host.contract.SessionContract;
import libghidra.host.contract.SymbolsContract;
import libghidra.host.contract.DecompilerContract;
import libghidra.host.contract.TypesContract;
import libghidra.host.contract.XrefsContract;
import libghidra.host.rpc.RpcDispatcher;

public final class LibGhidraHttpServer {
	private static final int MAX_WORKERS =
		Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
	private static final int MAX_QUEUE_DEPTH = MAX_WORKERS * 4;
	private static final int MAX_IN_FLIGHT_RPC = MAX_WORKERS * 2;

	public interface Callbacks {
		HealthContract.HealthStatusResponse healthStatus(HealthContract.HealthStatusRequest request);
		HealthContract.CapabilityResponse capabilities(HealthContract.CapabilityRequest request);
		SessionContract.OpenProgramResponse openProgram(SessionContract.OpenProgramRequest request);
		SessionContract.CloseProgramResponse closeProgram(SessionContract.CloseProgramRequest request);
		SessionContract.SaveProgramResponse saveProgram(SessionContract.SaveProgramRequest request);
		SessionContract.DiscardProgramResponse discardProgram(SessionContract.DiscardProgramRequest request);
		SessionContract.GetRevisionResponse getRevision(SessionContract.GetRevisionRequest request);
		SessionContract.ShutdownResponse shutdown(SessionContract.ShutdownRequest request);
		MemoryContract.ReadBytesResponse readBytes(MemoryContract.ReadBytesRequest request);
		MemoryContract.WriteBytesResponse writeBytes(MemoryContract.WriteBytesRequest request);
		MemoryContract.PatchBytesBatchResponse patchBytes(MemoryContract.PatchBytesBatchRequest request);
		MemoryContract.ListMemoryBlocksResponse listMemoryBlocks(
			MemoryContract.ListMemoryBlocksRequest request);
		FunctionsContract.GetFunctionResponse getFunction(
			FunctionsContract.GetFunctionRequest request);
		FunctionsContract.ListFunctionsResponse listFunctions(
			FunctionsContract.ListFunctionsRequest request);
		FunctionsContract.RenameFunctionResponse renameFunction(
			FunctionsContract.RenameFunctionRequest request);
		FunctionsContract.ListBasicBlocksResponse listBasicBlocks(
			FunctionsContract.ListBasicBlocksRequest request);
		FunctionsContract.ListCFGEdgesResponse listCFGEdges(
			FunctionsContract.ListCFGEdgesRequest request);
		FunctionsContract.ListFunctionTagsResponse listFunctionTags(
			FunctionsContract.ListFunctionTagsRequest request);
		FunctionsContract.CreateFunctionTagResponse createFunctionTag(
			FunctionsContract.CreateFunctionTagRequest request);
		FunctionsContract.DeleteFunctionTagResponse deleteFunctionTag(
			FunctionsContract.DeleteFunctionTagRequest request);
		FunctionsContract.ListFunctionTagMappingsResponse listFunctionTagMappings(
			FunctionsContract.ListFunctionTagMappingsRequest request);
		FunctionsContract.TagFunctionResponse tagFunction(
			FunctionsContract.TagFunctionRequest request);
		FunctionsContract.UntagFunctionResponse untagFunction(
			FunctionsContract.UntagFunctionRequest request);
		FunctionsContract.ListSwitchTablesResponse listSwitchTables(
			FunctionsContract.ListSwitchTablesRequest request);
		FunctionsContract.ListDominatorsResponse listDominators(
			FunctionsContract.ListDominatorsRequest request);
		FunctionsContract.ListPostDominatorsResponse listPostDominators(
			FunctionsContract.ListPostDominatorsRequest request);
		FunctionsContract.ListLoopsResponse listLoops(
			FunctionsContract.ListLoopsRequest request);
		SymbolsContract.GetSymbolResponse getSymbol(
			SymbolsContract.GetSymbolRequest request);
		SymbolsContract.ListSymbolsResponse listSymbols(
			SymbolsContract.ListSymbolsRequest request);
		SymbolsContract.RenameSymbolResponse renameSymbol(
			SymbolsContract.RenameSymbolRequest request);
		SymbolsContract.DeleteSymbolResponse deleteSymbol(
			SymbolsContract.DeleteSymbolRequest request);
		XrefsContract.ListXrefsResponse listXrefs(
			XrefsContract.ListXrefsRequest request);
		TypesContract.GetTypeResponse getType(
			TypesContract.GetTypeRequest request);
		TypesContract.ListTypesResponse listTypes(
			TypesContract.ListTypesRequest request);
		TypesContract.ListTypeAliasesResponse listTypeAliases(
			TypesContract.ListTypeAliasesRequest request);
		TypesContract.ListTypeUnionsResponse listTypeUnions(
			TypesContract.ListTypeUnionsRequest request);
		TypesContract.ListTypeEnumsResponse listTypeEnums(
			TypesContract.ListTypeEnumsRequest request);
		TypesContract.ListTypeEnumMembersResponse listTypeEnumMembers(
			TypesContract.ListTypeEnumMembersRequest request);
		TypesContract.ListTypeMembersResponse listTypeMembers(
			TypesContract.ListTypeMembersRequest request);
		TypesContract.GetFunctionSignatureResponse getFunctionSignature(
			TypesContract.GetFunctionSignatureRequest request);
		TypesContract.ListFunctionSignaturesResponse listFunctionSignatures(
			TypesContract.ListFunctionSignaturesRequest request);
		TypesContract.SetFunctionSignatureResponse setFunctionSignature(
			TypesContract.SetFunctionSignatureRequest request);
		TypesContract.RenameFunctionParameterResponse renameFunctionParameter(
			TypesContract.RenameFunctionParameterRequest request);
		TypesContract.SetFunctionParameterTypeResponse setFunctionParameterType(
			TypesContract.SetFunctionParameterTypeRequest request);
		TypesContract.RenameFunctionLocalResponse renameFunctionLocal(
			TypesContract.RenameFunctionLocalRequest request);
		TypesContract.SetFunctionLocalTypeResponse setFunctionLocalType(
			TypesContract.SetFunctionLocalTypeRequest request);
		TypesContract.ApplyDataTypeResponse applyDataType(
			TypesContract.ApplyDataTypeRequest request);
		TypesContract.CreateTypeResponse createType(
			TypesContract.CreateTypeRequest request);
		TypesContract.DeleteTypeResponse deleteType(
			TypesContract.DeleteTypeRequest request);
		TypesContract.RenameTypeResponse renameType(
			TypesContract.RenameTypeRequest request);
		TypesContract.CreateTypeAliasResponse createTypeAlias(
			TypesContract.CreateTypeAliasRequest request);
		TypesContract.DeleteTypeAliasResponse deleteTypeAlias(
			TypesContract.DeleteTypeAliasRequest request);
		TypesContract.SetTypeAliasTargetResponse setTypeAliasTarget(
			TypesContract.SetTypeAliasTargetRequest request);
		TypesContract.CreateTypeEnumResponse createTypeEnum(
			TypesContract.CreateTypeEnumRequest request);
		TypesContract.DeleteTypeEnumResponse deleteTypeEnum(
			TypesContract.DeleteTypeEnumRequest request);
		TypesContract.AddTypeEnumMemberResponse addTypeEnumMember(
			TypesContract.AddTypeEnumMemberRequest request);
		TypesContract.DeleteTypeEnumMemberResponse deleteTypeEnumMember(
			TypesContract.DeleteTypeEnumMemberRequest request);
		TypesContract.RenameTypeEnumMemberResponse renameTypeEnumMember(
			TypesContract.RenameTypeEnumMemberRequest request);
		TypesContract.SetTypeEnumMemberValueResponse setTypeEnumMemberValue(
			TypesContract.SetTypeEnumMemberValueRequest request);
		TypesContract.AddTypeMemberResponse addTypeMember(
			TypesContract.AddTypeMemberRequest request);
		TypesContract.DeleteTypeMemberResponse deleteTypeMember(
			TypesContract.DeleteTypeMemberRequest request);
		TypesContract.RenameTypeMemberResponse renameTypeMember(
			TypesContract.RenameTypeMemberRequest request);
		TypesContract.SetTypeMemberTypeResponse setTypeMemberType(
			TypesContract.SetTypeMemberTypeRequest request);
		TypesContract.SetTypeMemberCommentResponse setTypeMemberComment(
			TypesContract.SetTypeMemberCommentRequest request);
		TypesContract.SetTypeEnumMemberCommentResponse setTypeEnumMemberComment(
			TypesContract.SetTypeEnumMemberCommentRequest request);
		TypesContract.ParseDeclarationsResponse parseDeclarations(
			TypesContract.ParseDeclarationsRequest request);
		DecompilerContract.DecompileFunctionResponse decompileFunction(
			DecompilerContract.DecompileFunctionRequest request);
		DecompilerContract.ListDecompilationsResponse listDecompilations(
			DecompilerContract.ListDecompilationsRequest request);
		ListingContract.GetInstructionResponse getInstruction(
			ListingContract.GetInstructionRequest request);
		ListingContract.ListInstructionsResponse listInstructions(
			ListingContract.ListInstructionsRequest request);
		ListingContract.GetCommentsResponse getComments(
			ListingContract.GetCommentsRequest request);
		ListingContract.SetCommentResponse setComment(
			ListingContract.SetCommentRequest request);
		ListingContract.DeleteCommentResponse deleteComment(
			ListingContract.DeleteCommentRequest request);
		ListingContract.RenameDataItemResponse renameDataItem(
			ListingContract.RenameDataItemRequest request);
		ListingContract.DeleteDataItemResponse deleteDataItem(
			ListingContract.DeleteDataItemRequest request);
		ListingContract.ListDataItemsResponse listDataItems(
			ListingContract.ListDataItemsRequest request);
		ListingContract.ListBookmarksResponse listBookmarks(
			ListingContract.ListBookmarksRequest request);
		ListingContract.AddBookmarkResponse addBookmark(
			ListingContract.AddBookmarkRequest request);
		ListingContract.DeleteBookmarkResponse deleteBookmark(
			ListingContract.DeleteBookmarkRequest request);
		ListingContract.ListBreakpointsResponse listBreakpoints(
			ListingContract.ListBreakpointsRequest request);
		ListingContract.AddBreakpointResponse addBreakpoint(
			ListingContract.AddBreakpointRequest request);
		ListingContract.SetBreakpointEnabledResponse setBreakpointEnabled(
			ListingContract.SetBreakpointEnabledRequest request);
		ListingContract.SetBreakpointKindResponse setBreakpointKind(
			ListingContract.SetBreakpointKindRequest request);
		ListingContract.SetBreakpointSizeResponse setBreakpointSize(
			ListingContract.SetBreakpointSizeRequest request);
		ListingContract.SetBreakpointConditionResponse setBreakpointCondition(
			ListingContract.SetBreakpointConditionRequest request);
		ListingContract.SetBreakpointGroupResponse setBreakpointGroup(
			ListingContract.SetBreakpointGroupRequest request);
		ListingContract.DeleteBreakpointResponse deleteBreakpoint(
			ListingContract.DeleteBreakpointRequest request);
		ListingContract.ListDefinedStringsResponse listDefinedStrings(
			ListingContract.ListDefinedStringsRequest request);
		default void afterRpcResponse(String methodName) {
			// no-op
		}
	}

	private final Object stateLock = new Object();
	private HttpServer server;
	private ExecutorService executor;
	private String authToken;
	private Callbacks callbacks;
	private final Semaphore rpcSlots = new Semaphore(MAX_IN_FLIGHT_RPC, true);

	public int start(String bind, int port, String token, Callbacks cb) throws IOException {
		synchronized (stateLock) {
			if (server != null) {
				return server.getAddress().getPort();
			}
			HttpServer nextServer = HttpServer.create(new InetSocketAddress(bind, port), 0);
			AtomicInteger threadIds = new AtomicInteger(1);
			ExecutorService nextExecutor = new ThreadPoolExecutor(
				MAX_WORKERS,
				MAX_WORKERS,
				60L,
				TimeUnit.SECONDS,
				new ArrayBlockingQueue<>(MAX_QUEUE_DEPTH),
				r -> {
					Thread t = new Thread(r,
						"libghidra-http-" + threadIds.getAndIncrement());
					t.setDaemon(true);
					return t;
				},
				new ThreadPoolExecutor.CallerRunsPolicy());
			nextServer.setExecutor(nextExecutor);

			nextServer.createContext("/", this::handleRoot);
			nextServer.createContext("/help", this::handleHelp);
			nextServer.createContext("/rpc", this::handleRpc);

			authToken = token != null ? token.trim() : "";
			callbacks = cb;
			server = nextServer;
			executor = nextExecutor;
			try {
				server.start();
				return server.getAddress().getPort();
			}
			catch (RuntimeException e) {
				try {
					nextServer.stop(0);
				}
				catch (Exception ignored) {
					// best effort cleanup
				}
				nextExecutor.shutdownNow();
				server = null;
				executor = null;
				authToken = "";
				callbacks = null;
				throw e;
			}
		}
	}

	public void stop() {
		synchronized (stateLock) {
			if (server != null) {
				server.stop(0);
				server = null;
			}
			if (executor != null) {
				executor.shutdown();
				executor = null;
			}
			authToken = "";
			callbacks = null;
		}
	}

	public boolean isRunning() {
		synchronized (stateLock) {
			return server != null;
		}
	}

	private void handleRoot(HttpExchange exchange) throws IOException {
		if (!checkAuth(exchange)) {
			return;
		}
		if (!"GET".equals(exchange.getRequestMethod())) {
			respond(exchange, 405, "text/plain", "method not allowed");
			return;
		}
		String text =
			"libghidra host\n" +
			"POST /rpc (application/x-protobuf; body=libghidra.RpcRequest)\n" +
			"GET  /help\n";
		respond(exchange, 200, "text/plain", text);
	}

	private void handleHelp(HttpExchange exchange) throws IOException {
		if (!checkAuth(exchange)) {
			return;
		}
		if (!"GET".equals(exchange.getRequestMethod())) {
			respond(exchange, 405, "text/plain", "method not allowed");
			return;
		}
		String text =
			"libghidra transport\n" +
			"POST /rpc (application/x-protobuf; body=libghidra.RpcRequest)\n" +
			"\n" +
			"Method names currently implemented over /rpc:\n" +
			"- libghidra.HealthService/GetStatus\n" +
			"- libghidra.HealthService/GetCapabilities\n" +
			"- libghidra.SessionService/OpenProgram\n" +
			"- libghidra.SessionService/CloseProgram\n" +
			"- libghidra.SessionService/SaveProgram\n" +
			"- libghidra.SessionService/DiscardProgram\n" +
			"- libghidra.SessionService/GetRevision\n" +
			"- libghidra.SessionService/Shutdown\n" +
			"- libghidra.MemoryService/*\n" +
			"- libghidra.FunctionsService/*\n" +
			"- libghidra.SymbolsService/*\n" +
			"- libghidra.XrefsService/*\n" +
			"- libghidra.DecompilerService/*\n" +
			"- libghidra.ListingService/*\n" +
			"- libghidra.TypesService/* (full types surface)\n";
		respond(exchange, 200, "text/plain", text);
	}

	private void handleRpc(HttpExchange exchange) throws IOException {
		if (!checkAuth(exchange)) {
			return;
		}
		if (!"POST".equals(exchange.getRequestMethod())) {
			respondRpcError(exchange, 405, "invalid_method", "POST required");
			return;
		}
		Callbacks cb = callbacks;
		if (cb == null) {
			respondRpcError(exchange, 500, "internal_error", "callbacks not configured");
			return;
		}
		if (!rpcSlots.tryAcquire()) {
			respondRpcError(exchange, 200, "server_busy", "server is busy; retry later");
			return;
		}
		try {
		byte[] body = readBodyBytes(exchange);
		libghidra.RpcRequest request;
		try {
			request = libghidra.RpcRequest.parseFrom(body);
		}
		catch (InvalidProtocolBufferException e) {
			respondRpcError(exchange, 200, "invalid_payload",
				e.getMessage() != null ? e.getMessage() : "failed to parse RpcRequest");
			return;
		}
		libghidra.RpcResponse response = new RpcDispatcher(cb).dispatch(request);
		respondBytes(exchange, 200, "application/x-protobuf", response.toByteArray());
		try {
			cb.afterRpcResponse(request.getMethod());
		}
		catch (RuntimeException e) {
			ghidra.util.Msg.error(this,
				"afterRpcResponse failed for " + request.getMethod() + ": " + e.getMessage(), e);
		}
		}
		finally {
			rpcSlots.release();
		}
	}

	private boolean checkAuth(HttpExchange exchange) throws IOException {
		if (authToken == null || authToken.isEmpty()) {
			return true;
		}
		Headers headers = exchange.getRequestHeaders();
		String auth = headers.getFirst("Authorization");
		String expected = "Bearer " + authToken;
		if (!expected.equals(auth)) {
			exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer");
			String path = exchange.getRequestURI() != null ? exchange.getRequestURI().getPath() : "";
			if ("/rpc".equals(path)) {
				respondRpcError(exchange, 401, "unauthorized", "unauthorized");
			}
			else {
				respond(exchange, 401, "text/plain", "unauthorized");
			}
			return false;
		}
		return true;
	}

	private static void respondRpcError(
		HttpExchange exchange, int code, String errorCode, String errorMessage) throws IOException {
		libghidra.RpcResponse response = libghidra.RpcResponse.newBuilder()
			.setSuccess(false)
			.setErrorCode(errorCode != null ? errorCode : "error")
			.setErrorMessage(errorMessage != null ? errorMessage : "")
			.build();
		respondBytes(exchange, code, "application/x-protobuf", response.toByteArray());
	}

	private static byte[] readBodyBytes(HttpExchange exchange) throws IOException {
		try (InputStream in = exchange.getRequestBody()) {
			return in.readAllBytes();
		}
	}

	private static void respond(HttpExchange exchange, int code, String contentType, String body)
			throws IOException {
		byte[] data = body.getBytes(StandardCharsets.UTF_8);
		respondBytes(exchange, code, contentType + "; charset=utf-8", data);
	}

	private static void respondBytes(HttpExchange exchange, int code, String contentType, byte[] body)
			throws IOException {
		byte[] data = body != null ? body : new byte[0];
		exchange.getResponseHeaders().set("Content-Type", contentType);
		exchange.sendResponseHeaders(code, data.length);
		exchange.getResponseBody().write(data);
		exchange.close();
	}
}
