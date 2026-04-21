/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package libghidra.host;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;

import com.google.protobuf.Any;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import libghidra.host.contract.FunctionsContract;
import libghidra.host.contract.ListingContract;
import libghidra.host.contract.SessionContract;
import libghidra.host.contract.SymbolsContract;
import libghidra.host.contract.DecompilerContract;
import libghidra.host.contract.TypesContract;
import libghidra.host.contract.XrefsContract;
import libghidra.host.http.LibGhidraHttpServer;
import libghidra.host.runtime.RuntimeBundle;
import libghidra.host.service.FunctionsServiceHandler;
import libghidra.host.service.HealthServiceHandler;
import libghidra.host.service.ListingServiceHandler;
import libghidra.host.service.MemoryServiceHandler;
import libghidra.host.service.SessionServiceHandler;
import libghidra.host.service.SymbolsServiceHandler;
import libghidra.host.service.DecompilerServiceHandler;
import libghidra.host.service.TypesServiceHandler;
import libghidra.host.service.XrefsServiceHandler;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Typed libghidra host for Ghidra",
	description = "Starts a local libghidra host inside Ghidra for external SDK clients"
)
//@formatter:on
public class LibGhidraHostPlugin extends ProgramPlugin {

	private static final int STATUS_PROBE_CONNECT_TIMEOUT_MS = 1000;
	private static final int STATUS_PROBE_READ_TIMEOUT_MS = 2000;

	private final Object stateLock = new Object();
	private final RuntimeBundle runtimes = new RuntimeBundle("gui");
	private final HealthServiceHandler healthHandler = new HealthServiceHandler(runtimes.health());
	private final SessionServiceHandler sessionHandler = new SessionServiceHandler(runtimes.session());
	private final MemoryServiceHandler memoryHandler = new MemoryServiceHandler(runtimes.memory());
	private final FunctionsServiceHandler functionsHandler = new FunctionsServiceHandler(runtimes.functions());
	private final SymbolsServiceHandler symbolsHandler = new SymbolsServiceHandler(runtimes.symbols());
	private final XrefsServiceHandler xrefsHandler = new XrefsServiceHandler(runtimes.xrefs());
	private final TypesServiceHandler typesHandler = new TypesServiceHandler(runtimes.types());
	private final DecompilerServiceHandler decompilerHandler =
		new DecompilerServiceHandler(runtimes.decompiler());
	private final ListingServiceHandler listingHandler = new ListingServiceHandler(runtimes.listing());

	private DockingAction startServerAction;
	private DockingAction stopServerAction;
	private DockingAction statusAction;

	private LibGhidraHttpServer server;
	private int boundPort;
	private final int configuredPort;
	private final String configuredBind;
	private String activeBind;
	private String lastRequestedBind;
	private int lastRequestedPort;
	private final String authToken;

	public LibGhidraHostPlugin(PluginTool tool) {
		super(tool);
		configuredBind = System.getProperty("libghidra.host.bind", "127.0.0.1");
		configuredPort = Integer.getInteger("libghidra.host.port", Integer.valueOf(18080)).intValue();
		lastRequestedBind = configuredBind;
		lastRequestedPort = configuredPort;
		authToken = System.getProperty("libghidra.host.token", "");
		createActions();
		updateActionStateLocked();
	}

	@Override
	protected void programActivated(Program program) {
		super.programActivated(program);
		runtimes.session().bindProgram(program, "gui");
		synchronized (stateLock) {
			updateActionStateLocked();
		}
	}

	@Override
	protected void programDeactivated(Program program) {
		super.programDeactivated(program);
		runtimes.session().unbindProgram(program);
		synchronized (stateLock) {
			updateActionStateLocked();
		}
	}

	@Override
	public void dispose() {
		stopServerInternal();
		super.dispose();
	}

	private void createActions() {
		startServerAction = new DockingAction("Start libghidra Host", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				startServer();
			}
		};
		startServerAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "libghidra Host", "Start Server..." }));
		tool.addAction(startServerAction);

		stopServerAction = new DockingAction("Stop libghidra Host", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				stopServer();
			}
		};
		stopServerAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "libghidra Host", "Stop Server" }));
		tool.addAction(stopServerAction);

		statusAction = new DockingAction("libghidra Host Status", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showServerStatus();
			}
		};
		statusAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "libghidra Host", "Status" }));
		tool.addAction(statusAction);
	}

	private void startServer() {
		ServerEndpoint endpoint;
		synchronized (stateLock) {
			if (server != null && server.isRunning()) {
				showInfoDialog(
					"libghidra Host",
					"libghidra Host is already running.\n" +
						"URL: " + runningUrlLocked() + "\n" +
						"Program: " + currentProgramName());
				return;
			}
		}

		endpoint = promptForServerEndpoint();
		if (endpoint == null) {
			return;
		}

		synchronized (stateLock) {
			if (server != null && server.isRunning()) {
				showInfoDialog(
					"libghidra Host",
					"libghidra Host is already running.\n" +
						"URL: " + runningUrlLocked() + "\n" +
						"Program: " + currentProgramName());
				return;
			}
			try {
				if (server == null) {
					server = new LibGhidraHttpServer();
				}
				activeBind = endpoint.bind;
				lastRequestedBind = endpoint.bind;
				lastRequestedPort = endpoint.port;
				boundPort = server.start(endpoint.bind, endpoint.port, authToken,
					new LibGhidraHttpServer.Callbacks() {
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
						public SessionContract.ShutdownResponse shutdown(
								SessionContract.ShutdownRequest request) {
							return sessionHandler.shutdown(request);
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
					});
				updateActionStateLocked();
				showInfoDialog(
					"libghidra Host Started",
					"libghidra Host server is running.\n" +
						"URL: " + runningUrlLocked() + "\n" +
						"Program: " + currentProgramName());
			}
			catch (Exception e) {
				activeBind = null;
				boundPort = 0;
				String attemptedUrl = endpointUrl(endpoint.bind, endpoint.port);
				Msg.error(this,
					"Failed to start libghidra Host server at " + attemptedUrl + ": " +
						e.getMessage(),
					e);
				Msg.showError(
					this,
					tool.getToolFrame(),
					"libghidra Host Failed",
					"Failed to start libghidra Host server at:\n" + attemptedUrl + "\n\n" +
						e.getMessage(),
					e);
			}
		}
	}

	private void stopServer() {
		synchronized (stateLock) {
			boolean wasRunning = server != null && server.isRunning();
			String stoppedUrl = wasRunning ? runningUrlLocked() : null;
			stopServerInternal();
			if (wasRunning) {
				showInfoDialog(
					"libghidra Host Stopped",
					"libghidra Host server has stopped.\n" +
						"Last URL: " + stoppedUrl + "\n" +
						"Program: " + currentProgramName());
			}
		}
	}

	private void stopServerInternal() {
		synchronized (stateLock) {
			if (server != null) {
				try {
					server.stop();
				}
				catch (RuntimeException e) {
					Msg.error(this, "Failed to stop libghidra Host server cleanly: " + e.getMessage(), e);
				}
				finally {
					server = null;
				}
			}
			activeBind = null;
			boundPort = 0;
			updateActionStateLocked();
		}
	}

	private void updateActionStateLocked() {
		boolean running = server != null && server.isRunning();
		if (startServerAction != null) {
			startServerAction.setEnabled(!running);
		}
		if (stopServerAction != null) {
			stopServerAction.setEnabled(running);
		}
		if (statusAction != null) {
			statusAction.setEnabled(true);
		}
	}

	private String statusText() {
		synchronized (stateLock) {
			boolean running = server != null && server.isRunning();
			if (!running) {
				return "API host server: stopped\n" +
					"Next start URL: " + nextStartUrlLocked() + "\n" +
					"Program: " + currentProgramName();
			}
			return "API host server: running\n" +
				"URL: " + runningUrlLocked() + "\n" +
				"Program: " + currentProgramName();
		}
	}

	private void showServerStatus() {
		synchronized (stateLock) {
			if (statusAction != null) {
				statusAction.setEnabled(false);
			}
		}

		Thread probeThread = new Thread(() -> {
			HostStatusSnapshot snapshot = collectHostStatusSnapshot();
			SwingUtilities.invokeLater(() -> {
				synchronized (stateLock) {
					updateActionStateLocked();
				}
				presentHostStatus(snapshot);
			});
		}, "libghidra-status-probe");
		probeThread.setDaemon(true);
		probeThread.start();
	}

	private HostStatusSnapshot collectHostStatusSnapshot() {
		boolean running;
		String runningUrl;
		String nextStartUrl;
		String programName;
		synchronized (stateLock) {
			running = server != null && server.isRunning();
			runningUrl = running ? runningUrlLocked() : null;
			nextStartUrl = nextStartUrlLocked();
			programName = currentProgramName();
		}
		if (!running) {
			return new HostStatusSnapshot(false, null, nextStartUrl, programName, null);
		}
		return new HostStatusSnapshot(
			true,
			runningUrl,
			nextStartUrl,
			programName,
			probeServerHealth(runningUrl));
	}

	private HostProbeResult probeServerHealth(String baseUrl) {
		HttpURLConnection connection = null;
		try {
			byte[] requestBytes = libghidra.RpcRequest.newBuilder()
				.setMethod("libghidra.HealthService/GetStatus")
				.setPayload(Any.pack(libghidra.HealthStatusRequest.getDefaultInstance()))
				.build()
				.toByteArray();
			URL rpcUrl = URI.create(baseUrl + "/rpc").toURL();
			connection = (HttpURLConnection) rpcUrl.openConnection();
			connection.setRequestMethod("POST");
			connection.setDoOutput(true);
			connection.setConnectTimeout(STATUS_PROBE_CONNECT_TIMEOUT_MS);
			connection.setReadTimeout(STATUS_PROBE_READ_TIMEOUT_MS);
			connection.setRequestProperty("Content-Type", "application/x-protobuf");
			connection.setRequestProperty("Accept", "application/x-protobuf");
			if (authToken != null && !authToken.isBlank()) {
				connection.setRequestProperty("Authorization", "Bearer " + authToken);
			}
			connection.setFixedLengthStreamingMode(requestBytes.length);
			try (OutputStream out = connection.getOutputStream()) {
				out.write(requestBytes);
			}

			int responseCode = connection.getResponseCode();
			InputStream stream = responseCode >= 400 ? connection.getErrorStream() : connection.getInputStream();
			if (stream == null) {
				return HostProbeResult.unreachable("HTTP " + responseCode + " with no response body.");
			}

			byte[] responseBytes;
			try (InputStream in = stream) {
				responseBytes = in.readAllBytes();
			}
			libghidra.RpcResponse rpcResponse = libghidra.RpcResponse.parseFrom(responseBytes);
			if (!rpcResponse.getSuccess()) {
				String message = rpcResponse.getErrorMessage();
				if (message == null || message.isBlank()) {
					message = rpcResponse.getErrorCode();
				}
				return HostProbeResult.unreachable("RPC error: " + message);
			}
			if (!rpcResponse.hasPayload()) {
				return HostProbeResult.unreachable("RPC response did not include a health payload.");
			}
			libghidra.HealthStatusResponse health =
				rpcResponse.getPayload().unpack(libghidra.HealthStatusResponse.class);
			return HostProbeResult.reachable(health);
		}
		catch (SocketTimeoutException e) {
			return HostProbeResult.unreachable(
				"Timed out after " + STATUS_PROBE_CONNECT_TIMEOUT_MS + "/" +
					STATUS_PROBE_READ_TIMEOUT_MS + " ms (connect/read).");
		}
		catch (Exception e) {
			String message = e.getMessage();
			if (message == null || message.isBlank()) {
				message = e.getClass().getSimpleName();
			}
			return HostProbeResult.unreachable(message);
		}
		finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	private void presentHostStatus(HostStatusSnapshot snapshot) {
		String message = formatHostStatus(snapshot);
		if (!snapshot.running() || snapshot.probe() == null || snapshot.probe().reachable()) {
			showInfoDialog("Ghidra libghidra Host Status", message);
			return;
		}

		int choice = OptionDialog.showYesNoDialogWithNoAsDefaultButton(
			tool.getToolFrame(),
			"libghidra Host Unresponsive",
			message + "\n\nReset the local host state now?");
		if (choice == OptionDialog.YES_OPTION) {
			stopServerInternal();
			showInfoDialog(
				"libghidra Host Reset",
				"Cleared the local host state.\n" +
					"Next start URL: " + nextStartUrl() + "\n" +
					"Program: " + currentProgramName());
			return;
		}
		Msg.showWarn(this, tool.getToolFrame(), "libghidra Host Unresponsive", message);
	}

	private String formatHostStatus(HostStatusSnapshot snapshot) {
		if (!snapshot.running()) {
			return "API host server: stopped\n" +
				"Next start URL: " + snapshot.nextStartUrl() + "\n" +
				"Program: " + snapshot.programName();
		}

		StringBuilder message = new StringBuilder();
		message.append("API host server: running (local state)\n");
		message.append("URL: ").append(snapshot.runningUrl()).append('\n');
		message.append("Program: ").append(snapshot.programName()).append('\n');

		HostProbeResult probe = snapshot.probe();
		if (probe == null) {
			message.append("RPC probe: unavailable");
			return message.toString();
		}
		if (!probe.reachable()) {
			message.append("RPC probe: unresponsive\n");
			message.append("Detail: ").append(probe.detail()).append('\n');
			message.append("The server may be wedged or stale.");
			return message.toString();
		}

		libghidra.HealthStatusResponse health = probe.health();
		message.append("RPC probe: reachable\n");
		message.append("Service health: ").append(health.getOk() ? "ok" : "degraded").append('\n');
		message.append("Service: ").append(health.getServiceName());
		if (!health.getServiceVersion().isBlank()) {
			message.append(' ').append(health.getServiceVersion());
		}
		message.append('\n');
		message.append("Host mode: ").append(health.getHostMode()).append('\n');
		message.append("Program revision: ").append(health.getProgramRevision());
		if (health.getWarningsCount() > 0) {
			message.append('\n');
			message.append("Warnings:");
			for (String warning : health.getWarningsList()) {
				message.append("\n- ").append(warning);
			}
		}
		return message.toString();
	}

	private ServerEndpoint promptForServerEndpoint() {
		String value = nextStartUrl();
		while (true) {
			InputDialog dialog =
				new InputDialog("Start libghidra Host", "Host URL or host:port", value);
			tool.showDialog(dialog);
			if (dialog.isCanceled()) {
				return null;
			}

			value = dialog.getValue();
			try {
				return parseServerEndpoint(value);
			}
			catch (IllegalArgumentException e) {
				Msg.showError(
					this,
					tool.getToolFrame(),
					"Invalid libghidra Host URL",
					e.getMessage() +
						"\n\nEnter a full URL like http://127.0.0.1:18080 or host:port.");
			}
		}
	}

	private ServerEndpoint parseServerEndpoint(String value) {
		String trimmed = value == null ? "" : value.trim();
		if (trimmed.isEmpty()) {
			throw new IllegalArgumentException("Start URL cannot be empty.");
		}

		String candidate = trimmed.contains("://") ? trimmed : "http://" + trimmed;
		URI uri;
		try {
			uri = new URI(candidate);
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException("Invalid server URL: " + trimmed, e);
		}

		String scheme = uri.getScheme();
		if (scheme != null && !"http".equalsIgnoreCase(scheme)) {
			throw new IllegalArgumentException("Only http:// URLs are supported.");
		}
		if (uri.getUserInfo() != null) {
			throw new IllegalArgumentException("User information is not supported in the host URL.");
		}
		String path = uri.getPath();
		if (path != null && !path.isEmpty() && !"/".equals(path)) {
			throw new IllegalArgumentException("The host URL must not include a path.");
		}
		if (uri.getQuery() != null || uri.getFragment() != null) {
			throw new IllegalArgumentException("The host URL must not include query or fragment data.");
		}

		String bind = uri.getHost();
		if (bind == null || bind.isBlank()) {
			throw new IllegalArgumentException("The host URL must include a bind address.");
		}

		int port = uri.getPort();
		if (port == -1) {
			synchronized (stateLock) {
				port = lastRequestedPort;
			}
		}
		if (port < 1 || port > 65535) {
			throw new IllegalArgumentException("Port must be between 1 and 65535.");
		}
		return new ServerEndpoint(bind, port);
	}

	private String nextStartUrl() {
		synchronized (stateLock) {
			return nextStartUrlLocked();
		}
	}

	private String nextStartUrlLocked() {
		return endpointUrl(lastRequestedBind, lastRequestedPort);
	}

	private String runningUrlLocked() {
		return endpointUrl(activeBind != null ? activeBind : configuredBind, boundPort);
	}

	private String endpointUrl(String bind, int port) {
		return "http://" + bind + ":" + port;
	}

	private String currentProgramName() {
		return currentProgram != null ? currentProgram.getName() : "<none>";
	}

	private void showInfoDialog(String title, String message) {
		Msg.info(this, message);
		Msg.showInfo(this, tool.getToolFrame(), title, message);
	}

	private record HostStatusSnapshot(
		boolean running,
		String runningUrl,
		String nextStartUrl,
		String programName,
		HostProbeResult probe) {
	}

	private record HostProbeResult(
		boolean reachable,
		String detail,
		libghidra.HealthStatusResponse health) {

		private static HostProbeResult reachable(libghidra.HealthStatusResponse health) {
			return new HostProbeResult(true, null, health);
		}

		private static HostProbeResult unreachable(String detail) {
			return new HostProbeResult(false, detail, null);
		}
	}

	private static class ServerEndpoint {
		private final String bind;
		private final int port;

		ServerEndpoint(String bind, int port) {
			this.bind = bind;
			this.port = port;
		}
	}
}
