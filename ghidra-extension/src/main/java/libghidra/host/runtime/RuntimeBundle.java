// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

public final class RuntimeBundle {

	private final HostState state;
	private final HealthRuntime health;
	private final SessionRuntime session;
	private final MemoryRuntime memory;
	private final FunctionsRuntime functions;
	private final SymbolsRuntime symbols;
	private final XrefsRuntime xrefs;
	private final TypesRuntime types;
	private final DecompilerRuntime decompiler;
	private final ListingRuntime listing;
	private final AnalysisRuntime analysis;

	public RuntimeBundle(String initialHostMode) {
		this(createState(initialHostMode), initialHostMode);
	}

	private RuntimeBundle(HostState state, String initialHostMode) {
		this(state, createSession(state, initialHostMode));
	}

	public RuntimeBundle(HostState state, SessionRuntime session) {
		this.state = state;
		this.session = session;
		health = new HealthRuntime(state);
		memory = new MemoryRuntime(state);
		functions = new FunctionsRuntime(state);
		symbols = new SymbolsRuntime(state);
		xrefs = new XrefsRuntime(state);
		types = new TypesRuntime(state);
		decompiler = new DecompilerRuntime(state);
		listing = new ListingRuntime(state);
		// With a PluginTool, AutoAnalysisManager runs analysis as a tool background task and
		// returns at once, so a job's completion would not be observable: GUI hosts do not
		// start analysis over RPC.
		analysis = new AnalysisRuntime(state, !"gui".equals(state.getHostMode()));
	}

	public HostState state() {
		return state;
	}

	public HealthRuntime health() {
		return health;
	}

	public SessionRuntime session() {
		return session;
	}

	public MemoryRuntime memory() {
		return memory;
	}

	public FunctionsRuntime functions() {
		return functions;
	}

	public SymbolsRuntime symbols() {
		return symbols;
	}

	public XrefsRuntime xrefs() {
		return xrefs;
	}

	public TypesRuntime types() {
		return types;
	}

	public DecompilerRuntime decompiler() {
		return decompiler;
	}

	public ListingRuntime listing() {
		return listing;
	}

	public AnalysisRuntime analysis() {
		return analysis;
	}

	private static HostState createState(String initialHostMode) {
		return new HostState(initialHostMode);
	}

	private static SessionRuntime createSession(HostState state, String initialHostMode) {
		return "gui".equalsIgnoreCase(initialHostMode)
				? SessionRuntime.forAttachedGui(state)
				: SessionRuntime.forFixedHeadless(state);
	}
}
