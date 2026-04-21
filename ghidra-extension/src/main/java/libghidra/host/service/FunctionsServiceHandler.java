package libghidra.host.service;

import libghidra.host.contract.FunctionsContract;
import libghidra.host.runtime.FunctionsOperations;

public final class FunctionsServiceHandler {

	private final FunctionsOperations runtime;

	public FunctionsServiceHandler(FunctionsOperations runtime) {
		this.runtime = runtime;
	}

	public FunctionsContract.GetFunctionResponse getFunction(
			FunctionsContract.GetFunctionRequest request) {
		if (request == null) {
			request = new FunctionsContract.GetFunctionRequest(
				0L);
		}
		return runtime.getFunction(request);
	}

	public FunctionsContract.ListFunctionsResponse listFunctions(
			FunctionsContract.ListFunctionsRequest request) {
		if (request == null) {
			request = new FunctionsContract.ListFunctionsRequest(
				0L,
				0L,
				0,
				0);
		}
		return runtime.listFunctions(request);
	}

	public FunctionsContract.RenameFunctionResponse renameFunction(
			FunctionsContract.RenameFunctionRequest request) {
		if (request == null) {
			request = new FunctionsContract.RenameFunctionRequest(
				0L,
				"");
		}
		return runtime.renameFunction(request);
	}

	public FunctionsContract.ListBasicBlocksResponse listBasicBlocks(
			FunctionsContract.ListBasicBlocksRequest request) {
		if (request == null) {
			request = new FunctionsContract.ListBasicBlocksRequest(
				0L, 0L, 0, 0);
		}
		return runtime.listBasicBlocks(request);
	}

	public FunctionsContract.ListCFGEdgesResponse listCFGEdges(
			FunctionsContract.ListCFGEdgesRequest request) {
		if (request == null) {
			request = new FunctionsContract.ListCFGEdgesRequest(
				0L, 0L, 0, 0);
		}
		return runtime.listCFGEdges(request);
	}

	public FunctionsContract.ListFunctionTagsResponse listFunctionTags(
			FunctionsContract.ListFunctionTagsRequest request) {
		if (request == null) {
			request = new FunctionsContract.ListFunctionTagsRequest(
				);
		}
		return runtime.listFunctionTags(request);
	}

	public FunctionsContract.CreateFunctionTagResponse createFunctionTag(
			FunctionsContract.CreateFunctionTagRequest request) {
		if (request == null) {
			request = new FunctionsContract.CreateFunctionTagRequest(
				"",
				"");
		}
		return runtime.createFunctionTag(request);
	}

	public FunctionsContract.DeleteFunctionTagResponse deleteFunctionTag(
			FunctionsContract.DeleteFunctionTagRequest request) {
		if (request == null) {
			request = new FunctionsContract.DeleteFunctionTagRequest(
				"");
		}
		return runtime.deleteFunctionTag(request);
	}

	public FunctionsContract.ListFunctionTagMappingsResponse listFunctionTagMappings(
			FunctionsContract.ListFunctionTagMappingsRequest request) {
		if (request == null) {
			request = new FunctionsContract.ListFunctionTagMappingsRequest(
				0L);
		}
		return runtime.listFunctionTagMappings(request);
	}

	public FunctionsContract.TagFunctionResponse tagFunction(
			FunctionsContract.TagFunctionRequest request) {
		if (request == null) {
			request = new FunctionsContract.TagFunctionRequest(
				0L,
				"");
		}
		return runtime.tagFunction(request);
	}

	public FunctionsContract.UntagFunctionResponse untagFunction(
			FunctionsContract.UntagFunctionRequest request) {
		if (request == null) {
			request = new FunctionsContract.UntagFunctionRequest(
				0L,
				"");
		}
		return runtime.untagFunction(request);
	}

	public FunctionsContract.ListSwitchTablesResponse listSwitchTables(
			FunctionsContract.ListSwitchTablesRequest request) {
		if (request == null) {
			request = new FunctionsContract.ListSwitchTablesRequest(0L, 0L, 0, 0);
		}
		return runtime.listSwitchTables(request);
	}

	public FunctionsContract.ListDominatorsResponse listDominators(
			FunctionsContract.ListDominatorsRequest request) {
		if (request == null) {
			request = new FunctionsContract.ListDominatorsRequest(0L, 0L, 0, 0);
		}
		return runtime.listDominators(request);
	}

	public FunctionsContract.ListPostDominatorsResponse listPostDominators(
			FunctionsContract.ListPostDominatorsRequest request) {
		if (request == null) {
			request = new FunctionsContract.ListPostDominatorsRequest(0L, 0L, 0, 0);
		}
		return runtime.listPostDominators(request);
	}

	public FunctionsContract.ListLoopsResponse listLoops(
			FunctionsContract.ListLoopsRequest request) {
		if (request == null) {
			request = new FunctionsContract.ListLoopsRequest(0L, 0L, 0, 0);
		}
		return runtime.listLoops(request);
	}
}
