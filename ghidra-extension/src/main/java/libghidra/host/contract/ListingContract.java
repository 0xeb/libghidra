package libghidra.host.contract;

import java.util.List;

public final class ListingContract {

	private ListingContract() {
	}

	public enum CommentKind {
		UNSPECIFIED,
		EOL,
		PRE,
		POST,
		PLATE,
		REPEATABLE
	}

	public record InstructionRecord(
		long address,
		String mnemonic,
		String operandText,
		String disassembly,
		int length) {
	}

	public record GetInstructionRequest(
		long address) {
	}

	public record GetInstructionResponse(InstructionRecord instruction) {
	}

	public record ListInstructionsRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset) {
	}

	public record ListInstructionsResponse(List<InstructionRecord> instructions) {
	}

	public record CommentRecord(
		long address,
		CommentKind kind,
		String text) {
	}

	public record GetCommentsRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset) {
	}

	public record GetCommentsResponse(List<CommentRecord> comments) {
	}

	public record SetCommentRequest(
		long address,
		CommentKind kind,
		String text) {
	}

	public record SetCommentResponse(
		boolean updated,
		String errorCode,
		String errorMessage) {
	}

	public record DeleteCommentRequest(
		long address,
		CommentKind kind) {
	}

	public record DeleteCommentResponse(
		boolean deleted,
		String errorCode,
		String errorMessage) {
	}

	public record RenameDataItemRequest(
		long address,
		String newName) {
	}

	public record RenameDataItemResponse(
		boolean updated,
		String name) {
	}

	public record DeleteDataItemRequest(
		long address) {
	}

	public record DeleteDataItemResponse(boolean deleted) {
	}

	public record DataItemRecord(
		long address,
		long endAddress,
		String name,
		String dataType,
		long size,
		String valueRepr) {
	}

	public record ListDataItemsRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset) {
	}

	public record ListDataItemsResponse(List<DataItemRecord> dataItems) {
	}

	public record BookmarkRecord(
		long address,
		String type,
		String category,
		String comment) {
	}

	public record ListBookmarksRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset,
		String typeFilter,
		String categoryFilter) {
	}

	public record ListBookmarksResponse(List<BookmarkRecord> bookmarks) {
	}

	public record AddBookmarkRequest(
		long address,
		String type,
		String category,
		String comment) {
	}

	public record AddBookmarkResponse(boolean updated) {
	}

	public record DeleteBookmarkRequest(
		long address,
		String type,
		String category) {
	}

	public record DeleteBookmarkResponse(boolean deleted) {
	}

	public record BreakpointRecord(
		long address,
		boolean enabled,
		String kind,
		long size,
		String condition,
		String group) {
	}

	public record ListBreakpointsRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset,
		String kindFilter,
		String groupFilter) {
	}

	public record ListBreakpointsResponse(List<BreakpointRecord> breakpoints) {
	}

	public record AddBreakpointRequest(
		long address,
		String kind,
		long size,
		boolean enabled,
		String condition,
		String group) {
	}

	public record AddBreakpointResponse(boolean updated) {
	}

	public record SetBreakpointEnabledRequest(
		long address,
		boolean enabled) {
	}

	public record SetBreakpointEnabledResponse(boolean updated) {
	}

	public record SetBreakpointKindRequest(
		long address,
		String kind) {
	}

	public record SetBreakpointKindResponse(boolean updated) {
	}

	public record SetBreakpointSizeRequest(
		long address,
		long size) {
	}

	public record SetBreakpointSizeResponse(boolean updated) {
	}

	public record SetBreakpointConditionRequest(
		long address,
		String condition) {
	}

	public record SetBreakpointConditionResponse(boolean updated) {
	}

	public record SetBreakpointGroupRequest(
		long address,
		String group) {
	}

	public record SetBreakpointGroupResponse(boolean updated) {
	}

	public record DeleteBreakpointRequest(
		long address) {
	}

	public record DeleteBreakpointResponse(boolean deleted) {
	}

	public record DefinedStringRecord(
		long address,
		String value,
		int length,
		String dataType,
		String encoding) {
	}

	public record ListDefinedStringsRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset) {
	}

	public record ListDefinedStringsResponse(List<DefinedStringRecord> strings) {
	}
}
