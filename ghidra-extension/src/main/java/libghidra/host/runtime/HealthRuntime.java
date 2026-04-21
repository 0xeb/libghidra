package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;

import libghidra.host.contract.HealthContract;

public final class HealthRuntime extends RuntimeSupport implements HealthOperations {

	public HealthRuntime(HostState state) {
		super(state);
	}

	@Override
	public HealthContract.HealthStatusResponse getHealthStatus(
			HealthContract.HealthStatusRequest request) {
		List<String> warnings = new ArrayList<>();
		boolean ok = currentProgram() != null;
		if (!ok) {
			warnings.add("no active program bound");
		}
		else {
			warnings.add("shared state: clients on this endpoint share the active program");
		}
		return new HealthContract.HealthStatusResponse(
			ok,
			"libghidra-host",
			"0.1.0-dev",
			hostMode(),
			revision(),
			warnings);
	}

	@Override
	public HealthContract.CapabilityResponse getCapabilities(
			HealthContract.CapabilityRequest request) {
		try (LockScope ignored = readLock()) {
			List<HealthContract.Capability> capabilities = new ArrayList<>();
			boolean ready = currentProgram() != null;
			String programState = ready ? "ready" : "degraded";
			capabilities.add(new HealthContract.Capability(
				"health.status",
				"ready",
				"Service liveness and revision"));
			capabilities.add(new HealthContract.Capability(
				"host.shared_state",
				"ready",
				"All clients on this endpoint share one bound program"));
			capabilities.add(new HealthContract.Capability(
				"program.open",
				programState,
				ready
					? "Returns metadata for the shared active program"
					: "Requires an active program in GUI/headless host"));
			capabilities.add(new HealthContract.Capability(
				"program.save",
				programState,
				"Persists current program when save is available"));
			capabilities.add(new HealthContract.Capability(
				"program.discard",
				programState,
				"Rewinds undo stack for the current active program"));
			capabilities.add(new HealthContract.Capability(
				"memory.read_bytes",
				programState,
				"Reads raw bytes from mapped program memory"));
			capabilities.add(new HealthContract.Capability(
				"memory.write_bytes",
				programState,
				"Writes raw bytes via transaction"));
			capabilities.add(new HealthContract.Capability(
				"functions.list",
				programState,
				"Enumerates functions in a requested address range"));
			capabilities.add(new HealthContract.Capability(
				"functions.get",
				programState,
				"Looks up a function by address"));
			capabilities.add(new HealthContract.Capability(
				"functions.rename",
				programState,
				"Renames the function containing a target address"));
			capabilities.add(new HealthContract.Capability(
				"symbols.list",
				programState,
				"Enumerates symbols in a requested address range"));
			capabilities.add(new HealthContract.Capability(
				"symbols.get",
				programState,
				"Looks up the primary symbol at an address"));
			capabilities.add(new HealthContract.Capability(
				"symbols.rename",
				programState,
				"Renames the primary symbol at a target address"));
			capabilities.add(new HealthContract.Capability(
				"symbols.delete",
				programState,
				"Deletes symbols at a target address (optionally filtered by name)"));
			capabilities.add(new HealthContract.Capability(
				"xrefs.list",
				programState,
				"Enumerates references by source-address range"));
			capabilities.add(new HealthContract.Capability(
				"types.list",
				programState,
				"Enumerates data types from the active program data type manager"));
			capabilities.add(new HealthContract.Capability(
				"types.get",
				programState,
				"Looks up a data type by path or name"));
			capabilities.add(new HealthContract.Capability(
				"signatures.get",
				programState,
				"Returns function signature metadata at an address"));
			capabilities.add(new HealthContract.Capability(
				"signatures.list",
				programState,
				"Enumerates function signatures in an address range"));
			capabilities.add(new HealthContract.Capability(
				"types.signature.set",
				programState,
				"Updates a function signature by prototype text"));
			capabilities.add(new HealthContract.Capability(
				"types.param.rename",
				programState,
				"Renames a function parameter by ordinal"));
			capabilities.add(new HealthContract.Capability(
				"types.param.set_type",
				programState,
				"Updates a function parameter data type by ordinal"));
			capabilities.add(new HealthContract.Capability(
				"types.local.rename",
				programState,
				"Renames a function local or parameter using local_id"));
			capabilities.add(new HealthContract.Capability(
				"types.local.set_type",
				programState,
				"Updates a function local or parameter type using local_id"));
			capabilities.add(new HealthContract.Capability(
				"types.data.apply",
				programState,
				"Applies a data type to a data item at an address"));
			capabilities.add(new HealthContract.Capability(
				"types.authoring",
				programState,
				"Creates, deletes, and renames struct, union, enum, and typedef types"));
			capabilities.add(new HealthContract.Capability(
				"types.aliases",
				programState,
				"Creates, deletes, and retargets aliases"));
			capabilities.add(new HealthContract.Capability(
				"types.enum_members",
				programState,
				"Adds, renames, updates, and deletes enum members"));
			capabilities.add(new HealthContract.Capability(
				"types.members",
				programState,
				"Adds, renames, retypes, and deletes composite members"));
			capabilities.add(new HealthContract.Capability(
				"decompiler.function",
				programState,
				"Returns pseudocode for the function containing a target address"));
			capabilities.add(new HealthContract.Capability(
				"decompiler.functions",
				programState,
				"Enumerates pseudocode for functions in an address range"));
			capabilities.add(new HealthContract.Capability(
				"listing.instructions",
				programState,
				"Instruction lookup and listing by address range"));
			capabilities.add(new HealthContract.Capability(
				"listing.comments",
				programState,
				"Comment read, set, and delete surfaces"));
			capabilities.add(new HealthContract.Capability(
				"listing.data.rename",
				programState,
				"Renames or creates a label for a data item address"));
			capabilities.add(new HealthContract.Capability(
				"listing.data.delete",
				programState,
				"Deletes an existing data item by clearing its code units"));
			capabilities.add(new HealthContract.Capability(
				"listing.bookmarks",
				programState,
				"Lists, adds, and deletes bookmarks in address ranges"));
			capabilities.add(new HealthContract.Capability(
				"listing.breakpoints",
				programState,
				"Bookmark-backed live breakpoint CRUD and edit surfaces"));
			return new HealthContract.CapabilityResponse(capabilities);
		}
	}
}
