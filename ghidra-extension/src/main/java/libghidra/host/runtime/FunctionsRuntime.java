// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.jung.JungDirectedGraph;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.BlockCopy;
import ghidra.program.model.pcode.BlockGraph;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import libghidra.host.contract.FunctionsContract;

public final class FunctionsRuntime extends RuntimeSupport implements FunctionsOperations {

	public FunctionsRuntime(HostState state) {
		super(state);
	}

	@Override
	public FunctionsContract.GetFunctionResponse getFunction(
			FunctionsContract.GetFunctionRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new FunctionsContract.GetFunctionResponse(null);
			}
			try {
				Function function = FunctionSupport.resolveFunction(program, request.address());
				return new FunctionsContract.GetFunctionResponse(RuntimeMappers.toFunctionRecord(function));
			}
			catch (IllegalArgumentException e) {
				return new FunctionsContract.GetFunctionResponse(null);
			}
		}
	}

	@Override
	public FunctionsContract.ListFunctionsResponse listFunctions(
			FunctionsContract.ListFunctionsRequest request) {
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
					return new FunctionsContract.ListFunctionsResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 512;

				FunctionManager functionManager = program.getFunctionManager();
				Address start = toAddress(program, startOffset);
				FunctionIterator it = functionManager.getFunctions(start, true);
				List<FunctionsContract.FunctionRecord> rows = new ArrayList<>();
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
					if (Long.compareUnsigned(address, endOffset) > 0) {
						break;
					}
					if (seen++ < offset) {
						continue;
					}
					rows.add(RuntimeMappers.toFunctionRecord(function));
					if (rows.size() >= limit) {
						break;
					}
				}
				return new FunctionsContract.ListFunctionsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new FunctionsContract.ListFunctionsResponse(List.of());
			}
		}
	}

	@Override
	public FunctionsContract.RenameFunctionResponse renameFunction(
			FunctionsContract.RenameFunctionRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new FunctionsContract.RenameFunctionResponse(
					false,
					"",
					"not_loaded",
					"no current program");
			}
			String newName = request.newName() != null ? request.newName().trim() : "";
			if (newName.isEmpty()) {
				return new FunctionsContract.RenameFunctionResponse(
					false,
					"",
					"invalid_argument",
					"new function name is empty");
			}
			int tx = program.startTransaction("libghidra rename function");
			boolean commit = false;
			try {
				Function function = FunctionSupport.resolveFunction(program, request.address());
				if (function == null) {
					return new FunctionsContract.RenameFunctionResponse(
						false,
						"",
						"not_found",
						"function not found at 0x" + Long.toHexString(request.address()));
				}
				function.setName(newName, SourceType.USER_DEFINED);
				commit = true;
				return new FunctionsContract.RenameFunctionResponse(
					true,
					nullableString(function.getName()),
					"",
					"");
			}
			catch (IllegalArgumentException | DuplicateNameException | InvalidInputException e) {
				Msg.error(this, "renameFunction failed: " + e.getMessage(), e);
				String code = e instanceof DuplicateNameException ? "duplicate_name" : "invalid_argument";
				return new FunctionsContract.RenameFunctionResponse(
					false,
					"",
					code,
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
	public FunctionsContract.ListBasicBlocksResponse listBasicBlocks(
			FunctionsContract.ListBasicBlocksRequest request) {
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

				Address start = toAddress(program, startOff);
				SimpleBlockModel blockModel = new SimpleBlockModel(program);
				FunctionIterator funcIter = program.getFunctionManager().getFunctions(start, true);
				List<FunctionsContract.BasicBlockRecord> rows = new ArrayList<>();
				int seen = 0;
				while (funcIter.hasNext() && rows.size() < limit) {
					Function func = funcIter.next();
					long funcEntry = func.getEntryPoint().getOffset();
					if (Long.compareUnsigned(funcEntry, startOff) < 0) {
						continue;
					}
					if (Long.compareUnsigned(funcEntry, endOff) > 0) {
						break;
					}
					AddressSetView body = func.getBody();
					CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(body, TaskMonitor.DUMMY);
					while (blockIter.hasNext() && rows.size() < limit) {
						CodeBlock block = blockIter.next();
						if (seen++ < offset) {
							continue;
						}
						int inDeg = block.getNumSources(TaskMonitor.DUMMY);
						int outDeg = block.getNumDestinations(TaskMonitor.DUMMY);
						rows.add(new FunctionsContract.BasicBlockRecord(
							funcEntry,
							block.getMinAddress().getOffset(),
							block.getMaxAddress().getOffset(),
							inDeg,
							outDeg));
					}
				}
				return new FunctionsContract.ListBasicBlocksResponse(rows);
			}
			catch (IllegalArgumentException | CancelledException e) {
				return new FunctionsContract.ListBasicBlocksResponse(List.of());
			}
		}
	}

	@Override
	public FunctionsContract.ListCFGEdgesResponse listCFGEdges(
			FunctionsContract.ListCFGEdgesRequest request) {
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

				Address start = toAddress(program, startOff);
				SimpleBlockModel blockModel = new SimpleBlockModel(program);
				FunctionIterator funcIter = program.getFunctionManager().getFunctions(start, true);
				List<FunctionsContract.CFGEdgeRecord> rows = new ArrayList<>();
				int seen = 0;
				while (funcIter.hasNext() && rows.size() < limit) {
					Function func = funcIter.next();
					long funcEntry = func.getEntryPoint().getOffset();
					if (Long.compareUnsigned(funcEntry, startOff) < 0) {
						continue;
					}
					if (Long.compareUnsigned(funcEntry, endOff) > 0) {
						break;
					}
					AddressSetView body = func.getBody();
					CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(body, TaskMonitor.DUMMY);
					while (blockIter.hasNext() && rows.size() < limit) {
						CodeBlock block = blockIter.next();
						long srcStart = block.getMinAddress().getOffset();
						CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
						while (destIter.hasNext() && rows.size() < limit) {
							CodeBlockReference ref = destIter.next();
							if (seen++ < offset) {
								continue;
							}
							CodeBlock destBlock = ref.getDestinationBlock();
							long dstStart = destBlock.getMinAddress().getOffset();
							String edgeKind = classifyFlowType(ref.getFlowType());
							rows.add(new FunctionsContract.CFGEdgeRecord(
								funcEntry, srcStart, dstStart, edgeKind));
						}
					}
				}
				return new FunctionsContract.ListCFGEdgesResponse(rows);
			}
			catch (IllegalArgumentException | CancelledException e) {
				return new FunctionsContract.ListCFGEdgesResponse(List.of());
			}
		}
	}

	@Override
	public FunctionsContract.ListFunctionTagsResponse listFunctionTags(
			FunctionsContract.ListFunctionTagsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			FunctionTagManager mgr = program.getFunctionManager().getFunctionTagManager();
			List<FunctionsContract.FunctionTagRecord> rows = new ArrayList<>();
			for (FunctionTag tag : mgr.getAllFunctionTags()) {
				rows.add(new FunctionsContract.FunctionTagRecord(
					tag.getName(), tag.getComment()));
			}
			return new FunctionsContract.ListFunctionTagsResponse(rows);
		}
	}

	@Override
	public FunctionsContract.CreateFunctionTagResponse createFunctionTag(
			FunctionsContract.CreateFunctionTagRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new FunctionsContract.CreateFunctionTagResponse(false);
			}
			int txId = program.startTransaction("createFunctionTag");
			try {
				FunctionTagManager mgr = program.getFunctionManager().getFunctionTagManager();
				FunctionTag existing = mgr.getFunctionTag(request.name());
				if (existing != null) {
					return new FunctionsContract.CreateFunctionTagResponse(false);
				}
				mgr.createFunctionTag(request.name(), request.comment() != null ? request.comment() : "");
				return new FunctionsContract.CreateFunctionTagResponse(true);
			}
			finally {
				program.endTransaction(txId, true);
			}
		}
	}

	@Override
	public FunctionsContract.DeleteFunctionTagResponse deleteFunctionTag(
			FunctionsContract.DeleteFunctionTagRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new FunctionsContract.DeleteFunctionTagResponse(false);
			}
			int txId = program.startTransaction("deleteFunctionTag");
			try {
				FunctionTagManager mgr = program.getFunctionManager().getFunctionTagManager();
				FunctionTag tag = mgr.getFunctionTag(request.name());
				if (tag == null) {
					return new FunctionsContract.DeleteFunctionTagResponse(false);
				}
				tag.delete();
				return new FunctionsContract.DeleteFunctionTagResponse(true);
			}
			finally {
				program.endTransaction(txId, true);
			}
		}
	}

	@Override
	public FunctionsContract.ListFunctionTagMappingsResponse listFunctionTagMappings(
			FunctionsContract.ListFunctionTagMappingsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			List<FunctionsContract.FunctionTagMappingRecord> rows = new ArrayList<>();
			long filterEntry = request != null ? request.functionEntry() : 0;
			FunctionManager funcMgr = program.getFunctionManager();
			FunctionIterator funcIter = funcMgr.getFunctions(true);
			while (funcIter.hasNext()) {
				Function func = funcIter.next();
				long entry = func.getEntryPoint().getOffset();
				if (filterEntry != 0 && entry != filterEntry) {
					continue;
				}
				for (FunctionTag tag : func.getTags()) {
					rows.add(new FunctionsContract.FunctionTagMappingRecord(entry, tag.getName()));
				}
			}
			return new FunctionsContract.ListFunctionTagMappingsResponse(rows);
		}
	}

	@Override
	public FunctionsContract.TagFunctionResponse tagFunction(
			FunctionsContract.TagFunctionRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new FunctionsContract.TagFunctionResponse(false);
			}
			int txId = program.startTransaction("tagFunction");
			try {
				Function func = program.getFunctionManager().getFunctionAt(
					toAddress(program, request.functionEntry()));
				if (func == null) {
					return new FunctionsContract.TagFunctionResponse(false);
				}
				FunctionTagManager mgr = program.getFunctionManager().getFunctionTagManager();
				FunctionTag tag = mgr.getFunctionTag(request.tagName());
				if (tag == null) {
					tag = mgr.createFunctionTag(request.tagName(), "");
				}
				func.addTag(tag.getName());
				return new FunctionsContract.TagFunctionResponse(true);
			}
			finally {
				program.endTransaction(txId, true);
			}
		}
	}

	@Override
	public FunctionsContract.UntagFunctionResponse untagFunction(
			FunctionsContract.UntagFunctionRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new FunctionsContract.UntagFunctionResponse(false);
			}
			int txId = program.startTransaction("untagFunction");
			try {
				Function func = program.getFunctionManager().getFunctionAt(
					toAddress(program, request.functionEntry()));
				if (func == null) {
					return new FunctionsContract.UntagFunctionResponse(false);
				}
				func.removeTag(request.tagName());
				return new FunctionsContract.UntagFunctionResponse(true);
			}
			finally {
				program.endTransaction(txId, true);
			}
		}
	}

	// ---- Switch tables (requires decompilation) ----

	@Override
	public FunctionsContract.ListSwitchTablesResponse listSwitchTables(
			FunctionsContract.ListSwitchTablesRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			try {
				long defaultStart = programMinOffset(program);
				long startOff = request != null ? request.rangeStart() : defaultStart;
				long endOff = request != null ? request.rangeEnd() : -1L;
				if (startOff == 0) { startOff = defaultStart; }
				int pOffset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 4096;

				Address start = toAddress(program, startOff);
				try (DecompilerLease lease = state.leaseDecompiler(program)) {
					DecompInterface decompiler = lease.get();
					if (decompiler == null) {
						return new FunctionsContract.ListSwitchTablesResponse(List.of());
					}
					FunctionIterator funcIter = program.getFunctionManager().getFunctions(start, true);
					List<FunctionsContract.SwitchTableRecord> rows = new ArrayList<>();
					int seen = 0;
					while (funcIter.hasNext() && rows.size() < limit) {
						Function func = funcIter.next();
						long funcEntry = func.getEntryPoint().getOffset();
						if (Long.compareUnsigned(funcEntry, startOff) < 0) { continue; }
						if (Long.compareUnsigned(funcEntry, endOff) > 0) { break; }
						if (func.isExternal()) { continue; }

						DecompileResults results =
							decompiler.decompileFunction(func, 30, TaskMonitor.DUMMY);
						if (results == null) { continue; }
						HighFunction highFunc = results.getHighFunction();
						if (highFunc == null) { continue; }

						JumpTable[] jumpTables = highFunc.getJumpTables();
						if (jumpTables == null) { continue; }
						for (JumpTable jt : jumpTables) {
							if (jt == null || jt.isEmpty()) { continue; }
							if (seen++ < pOffset) { continue; }
							Address switchAddr = jt.getSwitchAddress();
							Address[] addresses = jt.getCases();
							Integer[] labels = jt.getLabelValues();
							long switchOff = switchAddr != null ? switchAddr.getOffset() : 0L;

							List<FunctionsContract.SwitchCaseRecord> cases = new ArrayList<>();
							long defaultAddr = 0L;
							if (addresses != null) {
								// getCases() includes the default-guard entry, which is NOT
								// a real jump target (JumpTable.java:105). Replicate Ghidra's
								// own detection, DecompilerSwitchAnalysisCmd.isDefaultCase
								// (:231-233): an entry is the default guard when its index is
								// past the label array, OR its getLabelValues() entry equals
								// the decompiler's DEFAULT_CASE_VALUE sentinel
								// (0xbad1abe1, DecompilerSwitchAnalysisCmd:43). Surface it as
								// the default target, not a phantom case.
								final int DEFAULT_CASE_VALUE = 0xbad1abe1;
								final int labelCount = labels != null ? labels.length : 0;
								for (int i = 0; i < addresses.length; i++) {
									if (addresses[i] == null) { continue; }
									long targetAddr = addresses[i].getOffset();
									boolean isDefault = (i == labelCount)
										|| (i < labelCount && labels[i] != null
											&& labels[i].intValue() == DEFAULT_CASE_VALUE);
									if (isDefault) {
										defaultAddr = targetAddr;
										continue;
									}
									long caseValue = (i < labelCount && labels[i] != null)
										? labels[i].longValue() : i;
									cases.add(new FunctionsContract.SwitchCaseRecord(caseValue, targetAddr));
								}
							}
							rows.add(new FunctionsContract.SwitchTableRecord(
								funcEntry, switchOff, cases.size(), cases, defaultAddr));
							if (rows.size() >= limit) { break; }
						}
					}
					return new FunctionsContract.ListSwitchTablesResponse(rows);
				}
			}
			catch (Exception e) {
				return new FunctionsContract.ListSwitchTablesResponse(List.of());
			}
		}
	}

	// ---- Dominators (from CFG via GraphAlgorithms) ----

	@Override
	public FunctionsContract.ListDominatorsResponse listDominators(
			FunctionsContract.ListDominatorsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			try {
				long defaultStart = programMinOffset(program);
				long startOff = request != null ? request.rangeStart() : defaultStart;
				long endOff = request != null ? request.rangeEnd() : -1L;
				if (startOff == 0) { startOff = defaultStart; }
				int pOffset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 4096;

				Address start = toAddress(program, startOff);
				SimpleBlockModel blockModel = new SimpleBlockModel(program);
				FunctionIterator funcIter = program.getFunctionManager().getFunctions(start, true);
				List<FunctionsContract.DominatorRecord> rows = new ArrayList<>();
				int seen = 0;
				while (funcIter.hasNext() && rows.size() < limit) {
					Function func = funcIter.next();
					long funcEntry = func.getEntryPoint().getOffset();
					if (Long.compareUnsigned(funcEntry, startOff) < 0) { continue; }
					if (Long.compareUnsigned(funcEntry, endOff) > 0) { break; }

					List<FunctionsContract.DominatorRecord> funcDoms;
					try {
						funcDoms = buildDominatorRecords(func, blockModel, false);
					} catch (IllegalArgumentException e) {
						// findDominanceTree throws when a function's CFG has no source
						// (entry inside a cycle) or no sink (returnless loop). Skip that
						// ONE function; the outer catch would otherwise return an empty
						// page, which the paginator reads as end-of-data and drops ALL
						// remaining dominator rows for the whole program.
						continue;
					}
					for (FunctionsContract.DominatorRecord dom : funcDoms) {
						if (seen++ < pOffset) { continue; }
						rows.add(dom);
						if (rows.size() >= limit) { break; }
					}
				}
				return new FunctionsContract.ListDominatorsResponse(rows);
			}
			catch (IllegalArgumentException | CancelledException e) {
				return new FunctionsContract.ListDominatorsResponse(List.of());
			}
		}
	}

	// ---- Post-dominators (from reversed CFG) ----

	@Override
	public FunctionsContract.ListPostDominatorsResponse listPostDominators(
			FunctionsContract.ListPostDominatorsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			try {
				long defaultStart = programMinOffset(program);
				long startOff = request != null ? request.rangeStart() : defaultStart;
				long endOff = request != null ? request.rangeEnd() : -1L;
				if (startOff == 0) { startOff = defaultStart; }
				int pOffset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 4096;

				Address start = toAddress(program, startOff);
				SimpleBlockModel blockModel = new SimpleBlockModel(program);
				FunctionIterator funcIter = program.getFunctionManager().getFunctions(start, true);
				List<FunctionsContract.PostDominatorRecord> rows = new ArrayList<>();
				int seen = 0;
				while (funcIter.hasNext() && rows.size() < limit) {
					Function func = funcIter.next();
					long funcEntry = func.getEntryPoint().getOffset();
					if (Long.compareUnsigned(funcEntry, startOff) < 0) { continue; }
					if (Long.compareUnsigned(funcEntry, endOff) > 0) { break; }

					List<FunctionsContract.DominatorRecord> reversedDoms;
					try {
						reversedDoms = buildDominatorRecords(func, blockModel, true);
					} catch (IllegalArgumentException e) {
						// See listDominators: skip a pathological CFG rather than let the
						// outer catch empty the whole page (paginator = end-of-data).
						continue;
					}
					for (FunctionsContract.DominatorRecord dom : reversedDoms) {
						if (seen++ < pOffset) { continue; }
						rows.add(new FunctionsContract.PostDominatorRecord(
							dom.functionEntry(), dom.blockAddress(),
							dom.idomAddress(), dom.depth(), dom.isEntry()));
						if (rows.size() >= limit) { break; }
					}
				}
				return new FunctionsContract.ListPostDominatorsResponse(rows);
			}
			catch (IllegalArgumentException | CancelledException e) {
				return new FunctionsContract.ListPostDominatorsResponse(List.of());
			}
		}
	}

	// ---- Loops (from decompiler structured blocks) ----

	@Override
	public FunctionsContract.ListLoopsResponse listLoops(
			FunctionsContract.ListLoopsRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			try {
				long defaultStart = programMinOffset(program);
				long startOff = request != null ? request.rangeStart() : defaultStart;
				long endOff = request != null ? request.rangeEnd() : -1L;
				if (startOff == 0) { startOff = defaultStart; }
				int pOffset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 4096;

				Address start = toAddress(program, startOff);
				try (DecompilerLease lease = state.leaseDecompiler(program)) {
					DecompInterface decompiler = lease.get();
					if (decompiler == null) {
						return new FunctionsContract.ListLoopsResponse(List.of());
					}
					SimpleBlockModel blockModel = new SimpleBlockModel(program);
					FunctionIterator funcIter = program.getFunctionManager().getFunctions(start, true);
					List<FunctionsContract.LoopRecord> rows = new ArrayList<>();
					int seen = 0;
					while (funcIter.hasNext() && rows.size() < limit) {
						Function func = funcIter.next();
						long funcEntry = func.getEntryPoint().getOffset();
						if (Long.compareUnsigned(funcEntry, startOff) < 0) { continue; }
						if (Long.compareUnsigned(funcEntry, endOff) > 0) { break; }
						if (func.isExternal()) { continue; }

						List<FunctionsContract.LoopRecord> funcLoops =
							extractLoops(func, funcEntry, blockModel, decompiler);
						for (FunctionsContract.LoopRecord loop : funcLoops) {
							if (seen++ < pOffset) { continue; }
							rows.add(loop);
							if (rows.size() >= limit) { break; }
						}
					}
					return new FunctionsContract.ListLoopsResponse(rows);
				}
			}
			catch (Exception e) {
				return new FunctionsContract.ListLoopsResponse(List.of());
			}
		}
	}

	// ---- Stack frames (decompiler-free; from Function.getStackFrame()) ----
	//
	// This never touches DecompInterface. It reads the listing-layer StackFrame
	// (Function.getStackFrame()) and its embedded stack Variables directly, so it
	// is cheap and safe to run over an entire program. var_id is computed with the
	// same FunctionSupport.canonicalLocalId used by the rename write path, so ids
	// round-trip.

	@Override
	public FunctionsContract.ListFunctionFramesResponse listFunctionFrames(
			FunctionsContract.ListFunctionFramesRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = requireProgram();
			try {
				long defaultStart = programMinOffset(program);
				long startOff = request != null ? request.rangeStart() : defaultStart;
				long endOff = request != null ? request.rangeEnd() : -1L;
				if (startOff == 0) { startOff = defaultStart; }
				int pOffset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 4096;

				String spName = "";
				try {
					if (program.getCompilerSpec() != null
							&& program.getCompilerSpec().getStackPointer() != null) {
						spName = program.getCompilerSpec().getStackPointer().getName();
					}
				}
				catch (Exception ignore) {
					spName = "";
				}

				Address start = toAddress(program, startOff);
				FunctionIterator funcIter = program.getFunctionManager().getFunctions(start, true);
				List<FunctionsContract.FunctionFrameRecord> rows = new ArrayList<>();
				int seen = 0;
				while (funcIter.hasNext() && rows.size() < limit) {
					Function func = funcIter.next();
					long funcEntry = func.getEntryPoint().getOffset();
					if (Long.compareUnsigned(funcEntry, startOff) < 0) { continue; }
					// INCLUSIVE upper bound: clients issue [addr, addr] point
					// windows (the contract of every other range RPC — an
					// exclusive bound here was the inclusive-range-end defect class).
					// The -1L "no bound" sentinel needs no special case: it is
					// unsigned all-ones, so compareUnsigned(entry, -1L) is never
					// > 0. (A signed endOff >= 0 pre-check wrongly disabled the
					// bound for ends in [2^63, 2^64-2].)
					if (Long.compareUnsigned(funcEntry, endOff) > 0) { break; }
					if (func.isExternal()) { continue; }

					// Skip frame-less functions BEFORE the pagination counter so
					// they do not inflate `seen` — otherwise pages come back
					// short and the client's paginator reads that as
					// end-of-data.
					StackFrame frame = func.getStackFrame();
					if (frame == null) { continue; }
					if (seen++ < pOffset) { continue; }

					List<FunctionsContract.StackVariableRecord> vars = new ArrayList<>();
					Variable[] stackVars = frame.getStackVariables();
					if (stackVars != null) {
						for (Variable v : stackVars) {
							if (v == null) { continue; }
							boolean isParam = v instanceof Parameter;
							String varId = FunctionSupport.canonicalLocalId(func, v);
							String dataType = v.getDataType() != null
								? v.getDataType().getName() : "";
							String sourceType = v.getSource() != null
								? v.getSource().name() : "";
							vars.add(new FunctionsContract.StackVariableRecord(
								varId,
								v.getName() != null ? v.getName() : "",
								dataType,
								v.getStackOffset(),
								// getLength() is -1 for unsized variables, which
								// would wrap to uint32 4294967295 on the wire.
								Math.max(0, v.getLength()),
								isParam,
								v.getFirstUseOffset(),
								sourceType));
						}
					}

					rows.add(new FunctionsContract.FunctionFrameRecord(
						funcEntry,
						frame.getFrameSize(),
						frame.getLocalSize(),
						frame.getParameterSize(),
						frame.getParameterOffset(),
						frame.getReturnAddressOffset(),
						frame.growsNegative(),
						spName,
						vars));
				}
				return new FunctionsContract.ListFunctionFramesResponse(rows);
			}
			catch (SessionRpcException e) {
				throw e;
			}
			catch (Exception e) {
				// A mid-scan failure must surface as an RPC error (success=false),
				// never as an empty success page — the client's paginator reads an
				// empty page as end-of-data.
				String message = e.getMessage();
				if (message == null || message.isBlank()) {
					message = e.toString();
				}
				throw new SessionRpcException("internal_error",
					"listFunctionFrames failed: " + message);
			}
		}
	}

	// ---- Private: dominator tree computation ----

	private List<FunctionsContract.DominatorRecord> buildDominatorRecords(
			Function func, SimpleBlockModel blockModel, boolean reversed)
			throws CancelledException {
		long funcEntry = func.getEntryPoint().getOffset();
		AddressSetView body = func.getBody();

		List<Long> blockAddrs = new ArrayList<>();
		CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(body, TaskMonitor.DUMMY);
		while (blockIter.hasNext()) {
			blockAddrs.add(blockIter.next().getMinAddress().getOffset());
		}
		if (blockAddrs.isEmpty()) {
			return List.of();
		}

		JungDirectedGraph<Long, DefaultGEdge<Long>> graph = new JungDirectedGraph<>();
		for (Long addr : blockAddrs) {
			graph.addVertex(addr);
		}

		blockIter = blockModel.getCodeBlocksContaining(body, TaskMonitor.DUMMY);
		while (blockIter.hasNext()) {
			CodeBlock block = blockIter.next();
			long srcAddr = block.getMinAddress().getOffset();
			CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
			while (destIter.hasNext()) {
				CodeBlockReference ref = destIter.next();
				CodeBlock destBlock = ref.getDestinationBlock();
				if (destBlock == null) { continue; }
				long dstAddr = destBlock.getMinAddress().getOffset();
				if (!graph.containsVertex(dstAddr)) { continue; }
				if (reversed) {
					graph.addEdge(new DefaultGEdge<>(dstAddr, srcAddr));
				} else {
					graph.addEdge(new DefaultGEdge<>(srcAddr, dstAddr));
				}
			}
		}

		GDirectedGraph<Long, GEdge<Long>> domTree =
			GraphAlgorithms.findDominanceTree(graph, TaskMonitor.DUMMY);
		if (domTree == null) {
			return List.of();
		}

		// Ghidra's GDirectedGraph.getInEdges/getOutEdges return NULL (not an empty
		// collection) for a vertex with no incident edges. Treat null as empty.
		Map<Long, Long> idomMap = new HashMap<>();
		for (Long vertex : domTree.getVertices()) {
			Collection<GEdge<Long>> inEdges = domTree.getInEdges(vertex);
			if (inEdges == null) {
				continue;
			}
			for (GEdge<Long> edge : inEdges) {
				idomMap.put(vertex, edge.getStart());
			}
		}

		long rootAddr = reversed ? findExitBlock(blockAddrs, graph) : funcEntry;
		Map<Long, Integer> depthMap = new HashMap<>();
		Queue<Long> queue = new LinkedList<>();
		depthMap.put(rootAddr, 0);
		queue.add(rootAddr);
		while (!queue.isEmpty()) {
			Long current = queue.poll();
			int depth = depthMap.get(current);
			Collection<GEdge<Long>> outEdges = domTree.getOutEdges(current);
			if (outEdges == null) {
				continue;
			}
			for (GEdge<Long> edge : outEdges) {
				Long child = edge.getEnd();
				if (!depthMap.containsKey(child)) {
					depthMap.put(child, depth + 1);
					queue.add(child);
				}
			}
		}

		List<FunctionsContract.DominatorRecord> rows = new ArrayList<>();
		for (Long addr : blockAddrs) {
			long idom = idomMap.getOrDefault(addr, addr);
			int depth = depthMap.getOrDefault(addr, 0);
			boolean isRoot = (addr == rootAddr);
			rows.add(new FunctionsContract.DominatorRecord(funcEntry, addr, idom, depth, isRoot));
		}
		return rows;
	}

	// For post-dominators the CFG is reversed (edge dst->src), so the exit block
	// is the reversed graph's SOURCE — the vertex with no INCOMING edges. That is
	// exactly the node GraphAlgorithms.findDominanceTree roots the tree at
	// (ChkDominanceAlgorithm -> getSources, unifySources), so the depth BFS below
	// must be seeded there. Testing out-edges instead would return the original
	// ENTRY (a leaf of the post-dominator tree), inverting depth and is_entry.
	private long findExitBlock(List<Long> blockAddrs,
			JungDirectedGraph<Long, DefaultGEdge<Long>> graph) {
		for (Long addr : blockAddrs) {
			var inEdges = graph.getInEdges(addr);
			if (inEdges == null || inEdges.isEmpty()) {
				return addr;
			}
		}
		return blockAddrs.get(blockAddrs.size() - 1);
	}

	// ---- Private: loop extraction from decompiler structured blocks ----

	// Recover structured loops (while/do-while/infinite) for a single function.
	//
	// The decompiler's HighFunction.getBasicBlocks() are DATA-FLOW blocks whose
	// getParent() chain does NOT reach the structured control tree (WHILEDO/DOWHILE/
	// INFLOOP) — walking those parents yields nothing, which is why loops were empty.
	// The structured tree is produced only by DecompInterface.structureGraph(), fed a
	// BlockGraph built from the function's CFG (BlockCopy vertices + internal edges).
	// This mirrors Ghidra's own DecompilerNestedLayout.
	private List<FunctionsContract.LoopRecord> extractLoops(
			Function func, long funcEntry, SimpleBlockModel blockModel, DecompInterface decompiler) {
		List<FunctionsContract.LoopRecord> loops = new ArrayList<>();
		try {
			AddressSetView body = func.getBody();
			CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(body, TaskMonitor.DUMMY);

			BlockGraph ingraph = new BlockGraph();
			Map<Address, PcodeBlock> blockByStart = new HashMap<>();
			List<CodeBlock> codeBlocks = new ArrayList<>();
			while (blockIter.hasNext()) {
				CodeBlock codeBlock = blockIter.next();
				Address startAddr = codeBlock.getMinAddress();
				if (blockByStart.containsKey(startAddr)) {
					continue;
				}
				PcodeBlock pcodeBlock = new BlockCopy(startAddr, startAddr);
				blockByStart.put(startAddr, pcodeBlock);
				ingraph.addBlock(pcodeBlock);
				codeBlocks.add(codeBlock);
			}
			if (ingraph.getSize() == 0) {
				return loops;
			}

			for (CodeBlock codeBlock : codeBlocks) {
				PcodeBlock srcPcode = blockByStart.get(codeBlock.getMinAddress());
				if (srcPcode == null) {
					continue;
				}
				CodeBlockReferenceIterator destIter = codeBlock.getDestinations(TaskMonitor.DUMMY);
				while (destIter.hasNext()) {
					CodeBlockReference ref = destIter.next();
					// Only keep control flow internal to the function; drop call edges.
					if (ref.getFlowType() != null && ref.getFlowType().isCall()) {
						continue;
					}
					CodeBlock destBlock = ref.getDestinationBlock();
					if (destBlock == null) {
						continue;
					}
					PcodeBlock dstPcode = blockByStart.get(destBlock.getMinAddress());
					if (dstPcode == null) {
						continue;
					}
					ingraph.addEdge(srcPcode, dstPcode);
				}
			}
			ingraph.setIndices();

			BlockGraph outgraph = decompiler.structureGraph(ingraph, 0, TaskMonitor.DUMMY);
			if (outgraph == null) {
				return loops;
			}
			List<PcodeBlock> topBlocks = new ArrayList<>();
			for (int i = 0; i < outgraph.getSize(); i++) {
				topBlocks.add(outgraph.getBlock(i));
			}
			collectLoopBlocks(funcEntry, topBlocks, loops, 0);
		}
		catch (Exception e) {
			// Structuring can fail for pathological CFGs; treat as no loops.
			return loops;
		}
		return loops;
	}

	private void collectLoopBlocks(long funcEntry, List<PcodeBlock> blocks,
			List<FunctionsContract.LoopRecord> loops, int nestingDepth) {
		for (PcodeBlock block : blocks) {
			int blockType = block.getType();
			String loopKind = null;
			switch (blockType) {
				case PcodeBlock.WHILEDO: loopKind = "while_do"; break;
				case PcodeBlock.DOWHILE: loopKind = "do_while"; break;
				case PcodeBlock.INFLOOP: loopKind = "infinite"; break;
			}
			if (loopKind != null) {
				long headerAddr = 0L;
				long backEdgeAddr = 0L;
				int innerBlockCount = 0;
				if (block instanceof BlockGraph bg) {
					innerBlockCount = bg.getSize();
					if (innerBlockCount > 0) {
						PcodeBlock first = bg.getBlock(0);
						if (first != null && first.getStart() != null) {
							headerAddr = first.getStart().getOffset();
						}
						PcodeBlock last = bg.getBlock(innerBlockCount - 1);
						if (last != null && last.getStart() != null) {
							backEdgeAddr = last.getStart().getOffset();
						}
					}
				} else if (block.getStart() != null) {
					headerAddr = block.getStart().getOffset();
				}
				loops.add(new FunctionsContract.LoopRecord(
					funcEntry, headerAddr, backEdgeAddr, loopKind,
					Math.max(innerBlockCount, 1), nestingDepth + 1));
			}
			if (block instanceof BlockGraph bg) {
				List<PcodeBlock> subBlocks = new ArrayList<>();
				for (int i = 0; i < bg.getSize(); i++) {
					subBlocks.add(bg.getBlock(i));
				}
				collectLoopBlocks(funcEntry, subBlocks, loops,
					loopKind != null ? nestingDepth + 1 : nestingDepth);
			}
		}
	}
}
