// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import libghidra.host.contract.DecompilerContract;

public final class DecompilerRuntime extends RuntimeSupport implements DecompilerOperations {

	public DecompilerRuntime(HostState state) {
		super(state);
	}

	@Override
	public DecompilerContract.DecompileFunctionResponse decompileFunction(
			DecompilerContract.DecompileFunctionRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new DecompilerContract.DecompileFunctionResponse(null);
			}
			try {
				Address address = toAddress(program, request.address());
				Function function = program.getFunctionManager().getFunctionContaining(address);
				if (function == null) {
					return new DecompilerContract.DecompileFunctionResponse(null);
				}

				int timeoutSeconds = DecompilerSupport.normalizeDecompileTimeoutSeconds(request.timeoutMs());
				try (DecompilerLease lease = state.leaseDecompiler(program)) {
					return new DecompilerContract.DecompileFunctionResponse(
						DecompilerSupport.toDecompileRecord(function, lease.get(), timeoutSeconds));
				}
			}
			catch (IllegalArgumentException e) {
				return new DecompilerContract.DecompileFunctionResponse(null);
			}
		}
	}

	@Override
	public DecompilerContract.GetPcodeResponse getPcode(
			DecompilerContract.GetPcodeRequest request) {
		try (LockScope ignored = readLock()) {
			Program program = currentProgram();
			if (program == null || request == null) {
				return new DecompilerContract.GetPcodeResponse(null);
			}
			try {
				Address address = toAddress(program, request.address());
				Function function = program.getFunctionManager().getFunctionContaining(address);
				if (function == null) {
					return new DecompilerContract.GetPcodeResponse(null);
				}
				int timeoutSeconds = DecompilerSupport.normalizeDecompileTimeoutSeconds(request.timeoutMs());
				if (request.maturity() == DecompilerContract.PcodeMaturity.RAW) {
					return new DecompilerContract.GetPcodeResponse(
						DecompilerSupport.toPcodeRecord(function, null, timeoutSeconds,
							request.maturity()));
				}
				try (DecompilerLease lease = state.leaseDecompiler(program)) {
					return new DecompilerContract.GetPcodeResponse(
						DecompilerSupport.toPcodeRecord(function, lease.get(), timeoutSeconds,
							request.maturity()));
				}
			}
			catch (IllegalArgumentException e) {
				return new DecompilerContract.GetPcodeResponse(null);
			}
		}
	}

	@Override
	public DecompilerContract.ListDecompilationsResponse listDecompilations(
			DecompilerContract.ListDecompilationsRequest request) {
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
					return new DecompilerContract.ListDecompilationsResponse(List.of());
				}

				int offset = request != null ? Math.max(0, request.offset()) : 0;
				int limit = request != null && request.limit() > 0 ? request.limit() : 128;
				int timeoutSeconds = DecompilerSupport.normalizeDecompileTimeoutSeconds(
					request != null ? request.timeoutMs() : 0);

				FunctionManager functionManager = program.getFunctionManager();
				Address start = toAddress(program, startOffset);
				FunctionIterator it = functionManager.getFunctions(start, true);
				List<DecompilerContract.DecompileRecord> rows = new ArrayList<>();
				int seen = 0;

				try (DecompilerLease lease = state.leaseDecompiler(program)) {
					DecompInterface decompiler = lease.get();
					while (it.hasNext()) {
						Function function = it.next();
						if (function == null) {
							continue;
						}
						long address = function.getEntryPoint().getOffset();
						if (Long.compareUnsigned(address, startOffset) < 0) {
							continue;
						}
						// INCLUSIVE upper bound, aligned with every other range
						// RPC (FunctionsRuntime et al.). The -1L "no bound"
						// sentinel needs no special case: compareUnsigned
						// against unsigned all-ones is never > 0.
						if (Long.compareUnsigned(address, endOffset) > 0) {
							break;
						}
						if (seen++ < offset) {
							continue;
						}
						rows.add(DecompilerSupport.toDecompileRecord(function, decompiler, timeoutSeconds));
						if (rows.size() >= limit) {
							break;
						}
					}
				}
				return new DecompilerContract.ListDecompilationsResponse(rows);
			}
			catch (IllegalArgumentException e) {
				return new DecompilerContract.ListDecompilationsResponse(List.of());
			}
		}
	}
}
