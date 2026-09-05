// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import libghidra.host.contract.ListingContract;

public final class ListingRuntime extends RuntimeSupport implements ListingOperations {

	private interface BreakpointMutation {
		boolean apply(BreakpointBookmarkStore.BreakpointRecord row);
	}

	public ListingRuntime(HostState state) {
		super(state);
	}

	@Override
	public ListingContract.GetInstructionResponse getInstruction(
			ListingContract.GetInstructionRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.GetInstructionResponse(null);
			}
			try {
				Address address = toAddress(program, request.address());
				Instruction instruction = program.getListing().getInstructionAt(address);
				if (instruction == null) {
					return new ListingContract.GetInstructionResponse(null);
				}
				return new ListingContract.GetInstructionResponse(
					RuntimeMappers.toInstructionRecord(instruction));
			}
			catch (IllegalArgumentException e) {
				return new ListingContract.GetInstructionResponse(null);
			}
		}
	}

	@Override
	public ListingContract.ListInstructionsResponse listInstructions(
			ListingContract.ListInstructionsRequest request) {
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
					return new ListingContract.ListInstructionsResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 256;

				Address start = toAddress(program, startOffset);
				InstructionIterator it = program.getListing().getInstructions(start, true);
				List<ListingContract.InstructionRecord> rows = new ArrayList<>();
				int seen = 0;
				while (it.hasNext()) {
					checkCancelled();
					Instruction instruction = it.next();
					long address = instruction.getAddress().getOffset();
					if (Long.compareUnsigned(address, startOffset) < 0) {
						continue;
					}
					// Inclusive end, consistent with the rest of this handler and the
					// C++ client's [addr, addr] point-query convention.
					if (Long.compareUnsigned(address, endOffset) > 0) {
						break;
					}
					if (seen++ < offset) {
						continue;
					}
					rows.add(RuntimeMappers.toInstructionRecord(instruction));
					if (rows.size() >= limit) {
						break;
					}
				}
				return new ListingContract.ListInstructionsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new ListingContract.ListInstructionsResponse(List.of());
			}
		}
	}

	@Override
	public ListingContract.ListInstructionOperandsResponse listInstructionOperands(
			ListingContract.ListInstructionOperandsRequest request) {
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
					return new ListingContract.ListInstructionOperandsResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 4096;

				Address start = toAddress(program, startOffset);
				InstructionIterator it = program.getListing().getInstructions(start, true);
				List<ListingContract.InstructionOperandRecord> rows = new ArrayList<>();
				int seen = 0;
				outer:
				while (it.hasNext()) {
					checkCancelled();
					Instruction instruction = it.next();
					long address = instruction.getAddress().getOffset();
					if (Long.compareUnsigned(address, startOffset) < 0) {
						continue;
					}
					// Inclusive end, matching listInstructions / the C++ [addr, addr] point query.
					if (Long.compareUnsigned(address, endOffset) > 0) {
						break;
					}
					int numOperands = instruction.getNumOperands();
					for (int i = 0; i < numOperands; i++) {
						if (seen++ < offset) {
							continue;
						}
						rows.add(RuntimeMappers.toInstructionOperandRecord(instruction, i));
						if (rows.size() >= limit) {
							break outer;
						}
					}
				}
				return new ListingContract.ListInstructionOperandsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new ListingContract.ListInstructionOperandsResponse(List.of());
			}
		}
	}


	@Override
	public ListingContract.GetCommentsResponse getComments(ListingContract.GetCommentsRequest request) {
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
					return new ListingContract.GetCommentsResponse(List.of());
				}

				Listing listing = program.getListing();

				// Fast path: exact-address query (start == end, both nonzero).
				// O(1) lookup instead of range iteration — prevents lock convoy.
				// Unsigned compare so a top-bit-set address (negative when signed)
				// still takes the O(1) fast path, like the rest of this method.
				if (Long.compareUnsigned(startOffset, 0) > 0 && startOffset == endOffset) {
					Address addr = toAddress(program, startOffset);
					CodeUnit codeUnit = listing.getCodeUnitAt(addr);
					if (codeUnit == null) {
						return new ListingContract.GetCommentsResponse(List.of());
					}
					List<ListingContract.CommentRecord> result = new ArrayList<>(5);
					long address = codeUnit.getAddress().getOffset();
					RuntimeMappers.appendCommentIfPresent(
						result, address, ListingContract.CommentKind.EOL,
						codeUnit.getComment(CommentType.EOL));
					RuntimeMappers.appendCommentIfPresent(
						result, address, ListingContract.CommentKind.PRE,
						codeUnit.getComment(CommentType.PRE));
					RuntimeMappers.appendCommentIfPresent(
						result, address, ListingContract.CommentKind.POST,
						codeUnit.getComment(CommentType.POST));
					RuntimeMappers.appendCommentIfPresent(
						result, address, ListingContract.CommentKind.PLATE,
						codeUnit.getComment(CommentType.PLATE));
					RuntimeMappers.appendCommentIfPresent(
						result, address, ListingContract.CommentKind.REPEATABLE,
						codeUnit.getComment(CommentType.REPEATABLE));
					return new ListingContract.GetCommentsResponse(result);
				}

				// Range path: iterate only addresses that actually carry comments.
				// Clamp the end to the start space's max (an unbounded request carries
				// endOffset = -1/INT64_MAX) and intersect with loaded memory. Walking every
				// code unit is still prohibitively expensive on large programs even after
				// that intersection; Listing's comment iterator uses its comment index.
				Address start = toAddress(program, startOffset);
				long spaceMax = start.getAddressSpace().getMaxAddress().getOffset();
				long clampedEnd = Long.compareUnsigned(endOffset, spaceMax) > 0 ? spaceMax : endOffset;
				Address end = toAddress(program, clampedEnd);
				AddressSet set = new AddressSet(start, end).intersect(program.getMemory());
				AddressIterator it = listing.getCommentAddressIterator(set, true);
				int pageOffset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 512;
				int seen = 0;
				List<ListingContract.CommentRecord> rows = new ArrayList<>();
				while (it.hasNext()) {
					checkCancelled();
					Address commentAddress = it.next();
					CodeUnit codeUnit = listing.getCodeUnitAt(commentAddress);
					if (codeUnit == null) {
						continue;
					}
					long address = codeUnit.getAddress().getOffset();
					List<ListingContract.CommentRecord> atAddress = new ArrayList<>(5);
					RuntimeMappers.appendCommentIfPresent(
						atAddress, address, ListingContract.CommentKind.EOL,
						codeUnit.getComment(CommentType.EOL));
					RuntimeMappers.appendCommentIfPresent(
						atAddress, address, ListingContract.CommentKind.PRE,
						codeUnit.getComment(CommentType.PRE));
					RuntimeMappers.appendCommentIfPresent(
						atAddress, address, ListingContract.CommentKind.POST,
						codeUnit.getComment(CommentType.POST));
					RuntimeMappers.appendCommentIfPresent(
						atAddress, address, ListingContract.CommentKind.PLATE,
						codeUnit.getComment(CommentType.PLATE));
					RuntimeMappers.appendCommentIfPresent(
						atAddress, address, ListingContract.CommentKind.REPEATABLE,
						codeUnit.getComment(CommentType.REPEATABLE));
					for (ListingContract.CommentRecord comment : atAddress) {
						if (seen++ < pageOffset) {
							continue;
						}
						rows.add(comment);
						if (rows.size() >= limit) {
							return new ListingContract.GetCommentsResponse(rows);
						}
					}
				}
				return new ListingContract.GetCommentsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new ListingContract.GetCommentsResponse(List.of());
			}
		}
	}

	@Override
	public ListingContract.SetCommentResponse setComment(ListingContract.SetCommentRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.SetCommentResponse(false, "not_loaded", "no current program");
			}
			CommentType type = toCommentType(request.kind());
			if (type == null) {
				return new ListingContract.SetCommentResponse(
					false,
					"invalid_argument",
					"unsupported comment kind");
			}
			int tx = program.startTransaction("libghidra set comment");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				program.getListing().setComment(address, type, request.text());
				commit = true;
				return new ListingContract.SetCommentResponse(true, "", "");
			}
			catch (IllegalArgumentException e) {
				return new ListingContract.SetCommentResponse(
					false,
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
	public ListingContract.DeleteCommentResponse deleteComment(
			ListingContract.DeleteCommentRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.DeleteCommentResponse(false, "not_loaded", "no current program");
			}
			CommentType type = toCommentType(request.kind());
			if (type == null) {
				return new ListingContract.DeleteCommentResponse(
					false,
					"invalid_argument",
					"unsupported comment kind");
			}
			int tx = program.startTransaction("libghidra delete comment");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				String current = program.getListing().getComment(type, address);
				if (current == null || current.isBlank()) {
					return new ListingContract.DeleteCommentResponse(
						false,
						"not_found",
						"no comment of the requested kind exists at 0x" +
							Long.toHexString(request.address()));
				}
				program.getListing().setComment(address, type, null);
				commit = true;
				return new ListingContract.DeleteCommentResponse(true, "", "");
			}
			catch (IllegalArgumentException e) {
				return new ListingContract.DeleteCommentResponse(
					false,
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
	public ListingContract.RenameDataItemResponse renameDataItem(
			ListingContract.RenameDataItemRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.RenameDataItemResponse(false, "");
			}
			String newName = request.newName() != null ? request.newName().trim() : "";
			if (newName.isEmpty()) {
				return new ListingContract.RenameDataItemResponse(false, "");
			}
			int tx = program.startTransaction("libghidra rename data item");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				Listing listing = program.getListing();
				Data data = listing.getDataAt(address);
				if (data == null) {
					return new ListingContract.RenameDataItemResponse(false, "");
				}
				SymbolTable symbolTable = program.getSymbolTable();
				Symbol symbol = symbolTable.getPrimarySymbol(address);
				if (symbol != null && !symbol.isDeleted()) {
					symbol.setName(newName, SourceType.USER_DEFINED);
				}
				else {
					symbolTable.createLabel(address, newName, SourceType.USER_DEFINED);
				}
				commit = true;
				return new ListingContract.RenameDataItemResponse(true, newName);
			}
			catch (InvalidInputException | DuplicateNameException | IllegalArgumentException e) {
				Msg.error(this, "renameDataItem failed: " + e.getMessage(), e);
				return new ListingContract.RenameDataItemResponse(false, "");
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public ListingContract.DeleteDataItemResponse deleteDataItem(
			ListingContract.DeleteDataItemRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.DeleteDataItemResponse(false);
			}
			int tx = program.startTransaction("libghidra delete data item");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				Listing listing = program.getListing();
				Data data = listing.getDataAt(address);
				if (data == null) {
					return new ListingContract.DeleteDataItemResponse(false);
				}
				listing.clearCodeUnits(address, data.getMaxAddress(), false);
				commit = true;
				return new ListingContract.DeleteDataItemResponse(true);
			}
			catch (IllegalArgumentException e) {
				Msg.error(this, "deleteDataItem failed: " + e.getMessage(), e);
				return new ListingContract.DeleteDataItemResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public ListingContract.ListDataItemsResponse listDataItems(
			ListingContract.ListDataItemsRequest request) {
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
					return new ListingContract.ListDataItemsResponse(List.of());
				}
				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 512;

				Listing listing = program.getListing();
				SymbolTable symbolTable = program.getSymbolTable();
				Address start = toAddress(program, startOffset);
				DataIterator it = listing.getDefinedData(start, true);
				List<ListingContract.DataItemRecord> rows = new ArrayList<>();
				int seen = 0;
				while (it.hasNext()) {
					checkCancelled();
					Data data = it.next();
					if (data == null) {
						continue;
					}
					Address address = data.getAddress();
					long addressOffset = address.getOffset();
					// Inclusive [start, end] to match the C++ client's point-query
					// convention [addr, addr] (read_data_items_at) — an exclusive end
					// dropped the exact address.
					if (Long.compareUnsigned(addressOffset, startOffset) < 0) {
						continue;
					}
					if (Long.compareUnsigned(addressOffset, endOffset) > 0) {
						break;
					}
					if (seen++ < offset) {
						continue;
					}
					long endAddress = data.getMaxAddress() != null
							? data.getMaxAddress().getOffset()
							: addressOffset;
					Symbol symbol = symbolTable.getPrimarySymbol(address);
					String name = symbol != null && !symbol.isDeleted() ? symbol.getName() : "";
					String dataType = data.getDataType() != null
							? nullableString(data.getDataType().getName())
							: "";
					String valueRepr = nullableString(data.getDefaultValueRepresentation());
					long size = Math.max(0, data.getLength());
					rows.add(new ListingContract.DataItemRecord(
						addressOffset,
						endAddress,
						name,
						dataType,
						size,
						valueRepr));
					if (rows.size() >= limit) {
						break;
					}
				}
				return new ListingContract.ListDataItemsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new ListingContract.ListDataItemsResponse(List.of());
			}
		}
	}

	@Override
	public ListingContract.ListBookmarksResponse listBookmarks(
			ListingContract.ListBookmarksRequest request) {
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
					return new ListingContract.ListBookmarksResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 512;
				String typeFilter = request != null ? nullableString(request.typeFilter()).trim() : "";
				String categoryFilter = request != null ? nullableString(request.categoryFilter()).trim() : "";

				BookmarkManager manager = program.getBookmarkManager();
				if (manager == null) {
					return new ListingContract.ListBookmarksResponse(List.of());
				}

				List<ListingContract.BookmarkRecord> rows = new ArrayList<>();
				int seen = 0;
				for (var it = manager.getBookmarksIterator(); it.hasNext();) {
					checkCancelled();
					Bookmark bookmark = it.next();
					if (bookmark == null) {
						continue;
					}
					long address = bookmark.getAddress().getOffset();
					// Inclusive [start, end]: the C++ client issues point queries as
					// [addr, addr] (read_bookmarks_at / find_bookmark) and full scans as
					// [0, MAX]. An exclusive end (address >= endOffset) dropped the exact
					// address on a point query, so every filtered bookmark read and every
					// set_bookmark_* find-existing came back empty.
					if (Long.compareUnsigned(address, startOffset) < 0 || Long.compareUnsigned(address, endOffset) > 0) {
						continue;
					}
					if (!typeFilter.isEmpty() && !typeFilter.equals(bookmark.getTypeString())) {
						continue;
					}
					if (!categoryFilter.isEmpty() && !categoryFilter.equals(bookmark.getCategory())) {
						continue;
					}
					if (seen++ < offset) {
						continue;
					}
					rows.add(new ListingContract.BookmarkRecord(
						address,
						nullableString(bookmark.getTypeString()),
						nullableString(bookmark.getCategory()),
						nullableString(bookmark.getComment())));
					if (rows.size() >= limit) {
						break;
					}
				}
				return new ListingContract.ListBookmarksResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new ListingContract.ListBookmarksResponse(List.of());
			}
		}
	}

	@Override
	public ListingContract.AddBookmarkResponse addBookmark(ListingContract.AddBookmarkRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.AddBookmarkResponse(false);
			}
			String type = request.type() != null ? request.type().trim() : "";
			String category = request.category() != null ? request.category().trim() : "";
			// Only `type` is required. An empty `category` is valid in native Ghidra
			// (BookmarkManager.setBookmark accepts an empty category sub-label), so do
			// not reject it here.
			if (type.isEmpty()) {
				return new ListingContract.AddBookmarkResponse(false);
			}
			int tx = program.startTransaction("libghidra add bookmark");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				BookmarkManager manager = program.getBookmarkManager();
				if (manager == null) {
					return new ListingContract.AddBookmarkResponse(false);
				}
				manager.setBookmark(
					address,
					type,
					category,
					request.comment() != null ? request.comment() : "");
				commit = true;
				return new ListingContract.AddBookmarkResponse(true);
			}
			catch (IllegalArgumentException e) {
				Msg.error(this, "addBookmark failed: " + e.getMessage(), e);
				return new ListingContract.AddBookmarkResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public ListingContract.DeleteBookmarkResponse deleteBookmark(
			ListingContract.DeleteBookmarkRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.DeleteBookmarkResponse(false);
			}
			String type = request.type() != null ? request.type().trim() : "";
			String category = request.category() != null ? request.category().trim() : "";
			// Only `type` is required; an empty `category` is valid (mirrors addBookmark
			// and native Ghidra's getBookmark, which matches an empty category sub-label).
			if (type.isEmpty()) {
				return new ListingContract.DeleteBookmarkResponse(false);
			}
			int tx = program.startTransaction("libghidra delete bookmark");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				BookmarkManager manager = program.getBookmarkManager();
				if (manager == null) {
					return new ListingContract.DeleteBookmarkResponse(false);
				}
				Bookmark bookmark = manager.getBookmark(address, type, category);
				if (bookmark == null) {
					return new ListingContract.DeleteBookmarkResponse(false);
				}
				manager.removeBookmark(bookmark);
				commit = true;
				return new ListingContract.DeleteBookmarkResponse(true);
			}
			catch (IllegalArgumentException e) {
				Msg.error(this, "deleteBookmark failed: " + e.getMessage(), e);
				return new ListingContract.DeleteBookmarkResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public ListingContract.ListBreakpointsResponse listBreakpoints(
			ListingContract.ListBreakpointsRequest request) {
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
					return new ListingContract.ListBreakpointsResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 512;
				String kindFilter = request != null ? nullableString(request.kindFilter()).trim() : "";
				String groupFilter = request != null ? nullableString(request.groupFilter()).trim() : "";

				BookmarkManager manager = program.getBookmarkManager();
				if (manager == null) {
					return new ListingContract.ListBreakpointsResponse(List.of());
				}

				List<ListingContract.BreakpointRecord> rows = new ArrayList<>();
				int seen = 0;
				for (Bookmark bookmark : BreakpointBookmarkStore.all(manager)) {
					checkCancelled();
					BreakpointBookmarkStore.BreakpointRecord row =
						BreakpointBookmarkStore.fromBookmark(bookmark);
					// Inclusive [start, end] to match the C++ client's point-query
					// convention [addr, addr] (read_breakpoints_at) — an exclusive end
					// dropped the exact address.
					if (Long.compareUnsigned(row.address, startOffset) < 0 || Long.compareUnsigned(row.address, endOffset) > 0) {
						continue;
					}
					if (!kindFilter.isEmpty() &&
						!kindFilter.equalsIgnoreCase(nullableString(row.kind).trim())) {
						continue;
					}
					if (!groupFilter.isEmpty() &&
						!groupFilter.equalsIgnoreCase(nullableString(row.group).trim())) {
						continue;
					}
					if (seen++ < offset) {
						continue;
					}
					rows.add(new ListingContract.BreakpointRecord(
						row.address,
						row.enabled,
						nullableString(row.kind),
						Math.max(1L, row.size),
						nullableString(row.condition),
						nullableString(row.group)));
					if (rows.size() >= limit) {
						break;
					}
				}
				return new ListingContract.ListBreakpointsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new ListingContract.ListBreakpointsResponse(List.of());
			}
		}
	}

	@Override
	public ListingContract.AddBreakpointResponse addBreakpoint(
			ListingContract.AddBreakpointRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.AddBreakpointResponse(false);
			}
			String kind = nullableString(request.kind()).trim();
			if (kind.isEmpty()) {
				kind = "software";
			}
			long size = Math.max(1L, request.size());
			int tx = program.startTransaction("libghidra add breakpoint");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				BookmarkManager manager = program.getBookmarkManager();
				if (manager == null) {
					return new ListingContract.AddBreakpointResponse(false);
				}
				BreakpointBookmarkStore.BreakpointRecord row;
				Bookmark bookmark = BreakpointBookmarkStore.findAt(manager, address);
				if (bookmark != null) {
					row = BreakpointBookmarkStore.fromBookmark(bookmark);
				}
				else {
					row = new BreakpointBookmarkStore.BreakpointRecord();
				}
				row.address = address.getOffset();
				row.enabled = request.enabled();
				row.kind = kind;
				row.size = size;
				row.condition = nullableString(request.condition());
				row.group = nullableString(request.group()).trim();
				BreakpointBookmarkStore.upsert(manager, address, row);
				commit = true;
				return new ListingContract.AddBreakpointResponse(true);
			}
			catch (IllegalArgumentException e) {
				Msg.error(this, "addBreakpoint failed: " + e.getMessage(), e);
				return new ListingContract.AddBreakpointResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public ListingContract.SetBreakpointEnabledResponse setBreakpointEnabled(
			ListingContract.SetBreakpointEnabledRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.SetBreakpointEnabledResponse(false);
			}
			boolean updated = updateBreakpointInProgram(
				request.address(),
				"libghidra set breakpoint enabled",
				row -> {
					row.enabled = request.enabled();
					return true;
				});
			return new ListingContract.SetBreakpointEnabledResponse(updated);
		}
	}

	@Override
	public ListingContract.SetBreakpointKindResponse setBreakpointKind(
			ListingContract.SetBreakpointKindRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.SetBreakpointKindResponse(false);
			}
			String kind = nullableString(request.kind()).trim();
			if (kind.isEmpty()) {
				return new ListingContract.SetBreakpointKindResponse(false);
			}
			boolean updated = updateBreakpointInProgram(
				request.address(),
				"libghidra set breakpoint kind",
				row -> {
					row.kind = kind;
					return true;
				});
			return new ListingContract.SetBreakpointKindResponse(updated);
		}
	}

	@Override
	public ListingContract.SetBreakpointSizeResponse setBreakpointSize(
			ListingContract.SetBreakpointSizeRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null || request.size() <= 0) {
				return new ListingContract.SetBreakpointSizeResponse(false);
			}
			long size = request.size();
			boolean updated = updateBreakpointInProgram(
				request.address(),
				"libghidra set breakpoint size",
				row -> {
					row.size = size;
					return true;
				});
			return new ListingContract.SetBreakpointSizeResponse(updated);
		}
	}

	@Override
	public ListingContract.SetBreakpointConditionResponse setBreakpointCondition(
			ListingContract.SetBreakpointConditionRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.SetBreakpointConditionResponse(false);
			}
			boolean updated = updateBreakpointInProgram(
				request.address(),
				"libghidra set breakpoint condition",
				row -> {
					row.condition = nullableString(request.condition());
					return true;
				});
			return new ListingContract.SetBreakpointConditionResponse(updated);
		}
	}

	@Override
	public ListingContract.SetBreakpointGroupResponse setBreakpointGroup(
			ListingContract.SetBreakpointGroupRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.SetBreakpointGroupResponse(false);
			}
			boolean updated = updateBreakpointInProgram(
				request.address(),
				"libghidra set breakpoint group",
				row -> {
					row.group = nullableString(request.group()).trim();
					return true;
				});
			return new ListingContract.SetBreakpointGroupResponse(updated);
		}
	}

	@Override
	public ListingContract.DeleteBreakpointResponse deleteBreakpoint(
			ListingContract.DeleteBreakpointRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new ListingContract.DeleteBreakpointResponse(false);
			}
			int tx = program.startTransaction("libghidra delete breakpoint");
			boolean commit = false;
			try {
				Address address = toAddress(program, request.address());
				BookmarkManager manager = program.getBookmarkManager();
				if (manager == null) {
					return new ListingContract.DeleteBreakpointResponse(false);
				}
				boolean removed = BreakpointBookmarkStore.removeAt(manager, address);
				if (removed) {
					commit = true;
				}
				return new ListingContract.DeleteBreakpointResponse(removed);
			}
			catch (IllegalArgumentException e) {
				Msg.error(this, "deleteBreakpoint failed: " + e.getMessage(), e);
				return new ListingContract.DeleteBreakpointResponse(false);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		}
	}

	@Override
	public ListingContract.ListDefinedStringsResponse listDefinedStrings(
			ListingContract.ListDefinedStringsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			try {
				long defaultStart = programMinOffset(program);
				long startOff = request != null ? request.rangeStart() : defaultStart;
				long endOff = request != null ? request.rangeEnd() : -1L;
				if (startOff == 0) {
					startOff = defaultStart;
				}
				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 4096;

				List<ListingContract.DefinedStringRecord> rows = new ArrayList<>();
				int seen = 0;
				for (Data data : DefinedDataIterator.byDataType(
					program,
					dt -> dt instanceof ghidra.program.model.data.AbstractStringDataType)) {
					checkCancelled();
					long addr = data.getAddress().getOffset();
					if (Long.compareUnsigned(addr, startOff) < 0) {
						continue;
					}
					// Inclusive end to match the C++ client's point-query convention
					// [addr, addr] (read_strings_at) — an exclusive end dropped the
					// exact address. Iteration is ascending, so break past the end.
					if (Long.compareUnsigned(addr, endOff) > 0) {
						break;
					}
					if (seen++ < offset) {
						continue;
					}
					String value = "";
					Object val = data.getValue();
					if (val != null) {
						value = val.toString();
					}
					String encoding = "utf8";
					var dataType = data.getDataType();
					String dtName = dataType != null ? dataType.getName() : "string";
					String dtNameLower = dtName.toLowerCase(Locale.ROOT);
					if (dtNameLower.contains("unicode") ||
						dtNameLower.contains("utf16") ||
						dtNameLower.contains("wchar")) {
						encoding = "utf16";
					}
					rows.add(new ListingContract.DefinedStringRecord(
						data.getAddress().getOffset(),
						value,
						data.getLength(),
						dtName,
						encoding));
					if (rows.size() >= limit) {
						break;
					}
				}
				return new ListingContract.ListDefinedStringsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new ListingContract.ListDefinedStringsResponse(List.of());
			}
		}
	}

	private boolean updateBreakpointInProgram(
			long addressOffset,
			String txName,
			BreakpointMutation mutation) {
		Program program = currentProgram();
		if (program == null || mutation == null) {
			return false;
		}
		int tx = program.startTransaction(txName);
		boolean commit = false;
		try {
			Address address = toAddress(program, addressOffset);
			BookmarkManager manager = program.getBookmarkManager();
			if (manager == null) {
				return false;
			}
			Bookmark bookmark = BreakpointBookmarkStore.findAt(manager, address);
			if (bookmark == null) {
				return false;
			}
			BreakpointBookmarkStore.BreakpointRecord row =
				BreakpointBookmarkStore.fromBookmark(bookmark);
			row.address = address.getOffset();
			if (!mutation.apply(row)) {
				return false;
			}
			BreakpointBookmarkStore.upsert(manager, address, row);
			commit = true;
			return true;
		}
		catch (IllegalArgumentException e) {
			Msg.error(this, "updateBreakpointInProgram failed: " + e.getMessage(), e);
			return false;
		}
		finally {
			program.endTransaction(tx, commit);
		}
	}
}
