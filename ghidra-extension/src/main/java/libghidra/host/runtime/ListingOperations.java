package libghidra.host.runtime;

import libghidra.host.contract.ListingContract;

public interface ListingOperations {

	ListingContract.GetInstructionResponse getInstruction(ListingContract.GetInstructionRequest request);

	ListingContract.ListInstructionsResponse listInstructions(
		ListingContract.ListInstructionsRequest request);

	ListingContract.GetCommentsResponse getComments(ListingContract.GetCommentsRequest request);

	ListingContract.SetCommentResponse setComment(ListingContract.SetCommentRequest request);

	ListingContract.DeleteCommentResponse deleteComment(ListingContract.DeleteCommentRequest request);

	ListingContract.RenameDataItemResponse renameDataItem(
		ListingContract.RenameDataItemRequest request);

	ListingContract.DeleteDataItemResponse deleteDataItem(
		ListingContract.DeleteDataItemRequest request);

	ListingContract.ListDataItemsResponse listDataItems(ListingContract.ListDataItemsRequest request);

	ListingContract.ListBookmarksResponse listBookmarks(
		ListingContract.ListBookmarksRequest request);

	ListingContract.AddBookmarkResponse addBookmark(ListingContract.AddBookmarkRequest request);

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
}
