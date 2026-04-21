package libghidra.host.service;

import libghidra.host.contract.ListingContract;
import libghidra.host.runtime.ListingOperations;

public final class ListingServiceHandler {

	private final ListingOperations runtime;

	public ListingServiceHandler(ListingOperations runtime) {
		this.runtime = runtime;
	}

	public ListingContract.GetInstructionResponse getInstruction(
			ListingContract.GetInstructionRequest request) {
		if (request == null) {
			request = new ListingContract.GetInstructionRequest(
				0L);
		}
		return runtime.getInstruction(request);
	}

	public ListingContract.ListInstructionsResponse listInstructions(
			ListingContract.ListInstructionsRequest request) {
		if (request == null) {
			request = new ListingContract.ListInstructionsRequest(
				0L,
				0L,
				0,
				0);
		}
		return runtime.listInstructions(request);
	}

	public ListingContract.GetCommentsResponse getComments(
			ListingContract.GetCommentsRequest request) {
		if (request == null) {
			request = new ListingContract.GetCommentsRequest(
				0L,
				0L,
				0,
				0);
		}
		return runtime.getComments(request);
	}

	public ListingContract.SetCommentResponse setComment(ListingContract.SetCommentRequest request) {
		if (request == null) {
			request = new ListingContract.SetCommentRequest(
				0L,
				ListingContract.CommentKind.UNSPECIFIED,
				"");
		}
		return runtime.setComment(request);
	}

	public ListingContract.DeleteCommentResponse deleteComment(
			ListingContract.DeleteCommentRequest request) {
		if (request == null) {
			request = new ListingContract.DeleteCommentRequest(
				0L,
				ListingContract.CommentKind.UNSPECIFIED);
		}
		return runtime.deleteComment(request);
	}

	public ListingContract.RenameDataItemResponse renameDataItem(
			ListingContract.RenameDataItemRequest request) {
		if (request == null) {
			request = new ListingContract.RenameDataItemRequest(
				0L,
				"");
		}
		return runtime.renameDataItem(request);
	}

	public ListingContract.DeleteDataItemResponse deleteDataItem(
			ListingContract.DeleteDataItemRequest request) {
		if (request == null) {
			request = new ListingContract.DeleteDataItemRequest(
				0L);
		}
		return runtime.deleteDataItem(request);
	}

	public ListingContract.ListDataItemsResponse listDataItems(
			ListingContract.ListDataItemsRequest request) {
		if (request == null) {
			request = new ListingContract.ListDataItemsRequest(
				0L,
				0L,
				0,
				0);
		}
		return runtime.listDataItems(request);
	}

	public ListingContract.ListBookmarksResponse listBookmarks(
			ListingContract.ListBookmarksRequest request) {
		if (request == null) {
			request = new ListingContract.ListBookmarksRequest(
				0L,
				0L,
				0,
				0,
				"",
				"");
		}
		return runtime.listBookmarks(request);
	}

	public ListingContract.AddBookmarkResponse addBookmark(
			ListingContract.AddBookmarkRequest request) {
		if (request == null) {
			request = new ListingContract.AddBookmarkRequest(
				0L,
				"",
				"",
				"");
		}
		return runtime.addBookmark(request);
	}

	public ListingContract.DeleteBookmarkResponse deleteBookmark(
			ListingContract.DeleteBookmarkRequest request) {
		if (request == null) {
			request = new ListingContract.DeleteBookmarkRequest(
				0L,
				"",
				"");
		}
		return runtime.deleteBookmark(request);
	}

	public ListingContract.ListBreakpointsResponse listBreakpoints(
			ListingContract.ListBreakpointsRequest request) {
		if (request == null) {
			request = new ListingContract.ListBreakpointsRequest(
				0L,
				0L,
				0,
				0,
				"",
				"");
		}
		return runtime.listBreakpoints(request);
	}

	public ListingContract.AddBreakpointResponse addBreakpoint(
			ListingContract.AddBreakpointRequest request) {
		if (request == null) {
			request = new ListingContract.AddBreakpointRequest(
				0L,
				"",
				1L,
				true,
				"",
				"");
		}
		return runtime.addBreakpoint(request);
	}

	public ListingContract.SetBreakpointEnabledResponse setBreakpointEnabled(
			ListingContract.SetBreakpointEnabledRequest request) {
		if (request == null) {
			request = new ListingContract.SetBreakpointEnabledRequest(
				0L,
				false);
		}
		return runtime.setBreakpointEnabled(request);
	}

	public ListingContract.SetBreakpointKindResponse setBreakpointKind(
			ListingContract.SetBreakpointKindRequest request) {
		if (request == null) {
			request = new ListingContract.SetBreakpointKindRequest(
				0L,
				"");
		}
		return runtime.setBreakpointKind(request);
	}

	public ListingContract.SetBreakpointSizeResponse setBreakpointSize(
			ListingContract.SetBreakpointSizeRequest request) {
		if (request == null) {
			request = new ListingContract.SetBreakpointSizeRequest(
				0L,
				1L);
		}
		return runtime.setBreakpointSize(request);
	}

	public ListingContract.SetBreakpointConditionResponse setBreakpointCondition(
			ListingContract.SetBreakpointConditionRequest request) {
		if (request == null) {
			request = new ListingContract.SetBreakpointConditionRequest(
				0L,
				"");
		}
		return runtime.setBreakpointCondition(request);
	}

	public ListingContract.SetBreakpointGroupResponse setBreakpointGroup(
			ListingContract.SetBreakpointGroupRequest request) {
		if (request == null) {
			request = new ListingContract.SetBreakpointGroupRequest(
				0L,
				"");
		}
		return runtime.setBreakpointGroup(request);
	}

	public ListingContract.DeleteBreakpointResponse deleteBreakpoint(
			ListingContract.DeleteBreakpointRequest request) {
		if (request == null) {
			request = new ListingContract.DeleteBreakpointRequest(
				0L);
		}
		return runtime.deleteBreakpoint(request);
	}

	public ListingContract.ListDefinedStringsResponse listDefinedStrings(
			ListingContract.ListDefinedStringsRequest request) {
		if (request == null) {
			request = new ListingContract.ListDefinedStringsRequest(
				0L, 0L, 0, 0);
		}
		return runtime.listDefinedStrings(request);
	}
}
