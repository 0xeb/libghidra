package libghidra.host.runtime;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import libghidra.host.contract.SessionContract;

public final class SessionRuntime extends RuntimeSupport implements SessionOperations {

	private enum ControlMode {
		ATTACHED_GUI,
		FIXED_HEADLESS,
		MANAGED_HEADLESS
	}

	private final ControlMode controlMode;
	private final ProjectData projectData;
	private final Object programConsumer;
	private final TaskMonitor taskMonitor;
	private final String managedProjectPath;
	private final String managedProjectName;
	private final Map<String, DomainFile> knownProgramFiles = new HashMap<>();

	private SessionRuntime(
			HostState state,
			ControlMode controlMode,
			ProjectData projectData,
			Object programConsumer,
			TaskMonitor taskMonitor,
			String managedProjectPath,
			String managedProjectName) {
		super(state);
		this.controlMode = controlMode;
		this.projectData = projectData;
		this.programConsumer = programConsumer;
		this.taskMonitor = taskMonitor != null ? taskMonitor : TaskMonitor.DUMMY;
		this.managedProjectPath = ManagedProgramSupport.normalizeProjectPath(managedProjectPath);
		this.managedProjectName = managedProjectName != null ? managedProjectName : "";
	}

	public static SessionRuntime forAttachedGui(HostState state) {
		return new SessionRuntime(state, ControlMode.ATTACHED_GUI, null, null, TaskMonitor.DUMMY, "", "");
	}

	public static SessionRuntime forFixedHeadless(HostState state) {
		return new SessionRuntime(state, ControlMode.FIXED_HEADLESS, null, null, TaskMonitor.DUMMY, "", "");
	}

	public static SessionRuntime forManagedHeadless(
			HostState state,
			ProjectData projectData,
			Object programConsumer,
			TaskMonitor taskMonitor,
			String managedProjectPath,
			String managedProjectName) {
		return new SessionRuntime(
			state,
			ControlMode.MANAGED_HEADLESS,
			projectData,
			programConsumer,
			taskMonitor,
			managedProjectPath,
			managedProjectName);
	}

	public void bindProgram(Program program, String mode) {
		state.bindProgram(program, mode);
	}

	public void bindProgram(Program program, String mode, String programPath) {
		String normalizedPath = ManagedProgramSupport.normalizeProgramPath(programPath);
		if (controlMode == ControlMode.MANAGED_HEADLESS &&
			!normalizedPath.isBlank() &&
			program != null &&
			program.getDomainFile() != null) {
			knownProgramFiles.put(normalizedPath, program.getDomainFile());
		}
		state.bindProgram(program, mode, programPath);
	}

	public void unbindProgram(Program program) {
		state.unbindProgram(program);
	}

	public boolean tryBeginUnbindProgram(Program program, long timeoutMillis)
			throws InterruptedException {
		return state.tryBeginUnbindProgram(program, timeoutMillis);
	}

	public void releaseOwnedProgram() {
		try (LockScope ignored = writeLock()) {
			releaseOwnedProgramLocked();
		}
	}

	@Override
	public SessionContract.OpenProgramResponse openProgram(SessionContract.OpenProgramRequest request) {
		try (LockScope ignored = writeLock()) {
			return switch (controlMode) {
				case ATTACHED_GUI -> openAttachedGui(request);
				case FIXED_HEADLESS -> openFixedProgram();
				case MANAGED_HEADLESS -> openManagedHeadless(request);
			};
		}
	}

	@Override
	public SessionContract.CloseProgramResponse closeProgram(SessionContract.CloseProgramRequest request) {
		try (LockScope ignored = writeLock()) {
			Program program = currentProgram();
			if (program == null) {
				return new SessionContract.CloseProgramResponse(false);
			}
			SessionContract.ShutdownPolicy policy = request != null
					? request.shutdownPolicy()
					: SessionContract.ShutdownPolicy.UNSPECIFIED;
			return switch (controlMode) {
				case ATTACHED_GUI ->
					throw new SessionRpcException(
						"NOT_SUPPORTED",
						"close_program() is not supported for an attached GUI host");
				case FIXED_HEADLESS -> {
					boolean ok = applyShutdownPolicyLocked(policy);
					if (ok) {
						bumpRevision();
					}
					yield new SessionContract.CloseProgramResponse(ok);
				}
				case MANAGED_HEADLESS -> new SessionContract.CloseProgramResponse(
					closeManagedProgramLocked(policy));
			};
		}
	}

	@Override
	public SessionContract.SaveProgramResponse saveProgram(SessionContract.SaveProgramRequest request) {
		try (LockScope ignored = writeLock()) {
			return new SessionContract.SaveProgramResponse(saveProgramLocked(false));
		}
	}

	@Override
	public SessionContract.DiscardProgramResponse discardProgram(
			SessionContract.DiscardProgramRequest request) {
		try (LockScope ignored = writeLock()) {
			return new SessionContract.DiscardProgramResponse(discardProgramLocked());
		}
	}

	@Override
	public SessionContract.GetRevisionResponse getRevision(SessionContract.GetRevisionRequest request) {
		return new SessionContract.GetRevisionResponse(revision());
	}

	@Override
	public SessionContract.ShutdownResponse shutdown(SessionContract.ShutdownRequest request) {
		try (LockScope ignored = writeLock()) {
			SessionContract.ShutdownPolicy policy = request != null
					? request.shutdownPolicy()
					: SessionContract.ShutdownPolicy.UNSPECIFIED;
			boolean ok = applyShutdownPolicyLocked(policy);
			if (ok) {
				bumpRevision();
			}
			return new SessionContract.ShutdownResponse(ok);
		}
	}

	private SessionContract.OpenProgramResponse openAttachedGui(SessionContract.OpenProgramRequest request) {
		Program program = currentProgram();
		if (program == null) {
			return emptyProgram();
		}
		if (request == null || request.programPath() == null || request.programPath().isBlank()) {
			return describeCurrentProgram(program);
		}
		if (matchesCurrentProgram(program, request.programPath())) {
			return describeCurrentProgram(program);
		}
		throw new SessionRpcException(
			"NOT_SUPPORTED",
			"open_program() cannot switch the active program for an attached GUI host");
	}

	private SessionContract.OpenProgramResponse openFixedProgram() {
		Program program = currentProgram();
		if (program == null) {
			return emptyProgram();
		}
		return describeCurrentProgram(program);
	}

	private SessionContract.OpenProgramResponse openManagedHeadless(
			SessionContract.OpenProgramRequest request) {
		if (!matchesManagedProject(request)) {
			throw new SessionRpcException(
				"NOT_SUPPORTED",
				"managed headless hosts only operate on their configured project");
		}
		String requestedProgramPath = request != null
				? ManagedProgramSupport.normalizeProgramPath(request.programPath())
				: "";
		Program current = currentProgram();
		if (requestedProgramPath.isBlank()) {
			return current != null ? describeCurrentProgram(current) : emptyProgram();
		}
		if (current != null) {
			if (currentProgramPath().equals(requestedProgramPath)) {
				throw new SessionRpcException(
					"conflict",
					"program is already open on this host: " + requestedProgramPath);
			}
			throw new SessionRpcException(
				"conflict",
				"close the current program before opening another one on this host");
		}
		try {
			DomainFile file = projectData != null ? projectData.getFile(requestedProgramPath) : null;
			if (file == null) {
				file = knownProgramFiles.get(requestedProgramPath);
			}
			if (file == null) {
				throw new IllegalArgumentException("program not found in project: " + requestedProgramPath);
			}
			Program opened = ManagedProgramSupport.openDomainFile(
				file,
				programConsumer,
				taskMonitor,
				request != null && request.readOnly());
			bindProgram(opened, "headless", requestedProgramPath);
			return describeCurrentProgram(opened);
		}
		catch (IllegalArgumentException e) {
			throw new SessionRpcException("not_found", e.getMessage());
		}
		catch (Exception e) {
			String message = e.getMessage();
			throw new SessionRpcException(
				"internal_error",
				message != null && !message.isBlank() ? message : e.toString());
		}
	}

	private boolean closeManagedProgramLocked(SessionContract.ShutdownPolicy policy) {
		Program program = currentProgram();
		if (program == null) {
			return false;
		}
		boolean ok = applyShutdownPolicyLocked(policy);
		if (!ok) {
			return false;
		}
		releaseOwnedProgramLocked();
		bumpRevision();
		return true;
	}

	private void releaseOwnedProgramLocked() {
		if (controlMode != ControlMode.MANAGED_HEADLESS) {
			return;
		}
		Program program = currentProgram();
		if (program == null) {
			return;
		}
		unbindProgram(program);
		try {
			program.release(programConsumer);
		}
		catch (RuntimeException e) {
			Msg.warn(this, "program release failed: " + e.getMessage(), e);
		}
	}

	private boolean matchesManagedProject(SessionContract.OpenProgramRequest request) {
		if (request == null) {
			return true;
		}
		if (request.projectName() != null && !request.projectName().isBlank() &&
			!request.projectName().equals(managedProjectName)) {
			return false;
		}
		if (request.projectPath() != null && !request.projectPath().isBlank()) {
			String normalizedRequest = ManagedProgramSupport.normalizeProjectPath(request.projectPath());
			if (!normalizedRequest.equals(managedProjectPath)) {
				return false;
			}
		}
		return true;
	}

	private boolean matchesCurrentProgram(Program program, String requestedProgramPath) {
		String normalizedRequested = ManagedProgramSupport.normalizeProgramPath(requestedProgramPath);
		if (normalizedRequested.isBlank()) {
			return true;
		}
		if (normalizedRequested.equals(currentProgramPath())) {
			return true;
		}
		int slash = normalizedRequested.lastIndexOf('/');
		String requestedName = slash >= 0 ? normalizedRequested.substring(slash + 1) : normalizedRequested;
		return program.getName().equalsIgnoreCase(requestedName);
	}

	private SessionContract.OpenProgramResponse emptyProgram() {
		return new SessionContract.OpenProgramResponse("", "", "", 0L);
	}

	private SessionContract.OpenProgramResponse describeCurrentProgram(Program program) {
		String name = program.getName();
		String languageId = program.getLanguageID().getIdAsString();
		String compiler = program.getCompilerSpec().getCompilerSpecID().toString();
		long imageBase = program.getImageBase().getOffset();
		return new SessionContract.OpenProgramResponse(name, languageId, compiler, imageBase);
	}

	private boolean applyShutdownPolicyLocked(SessionContract.ShutdownPolicy policy) {
		SessionContract.ShutdownPolicy resolved = policy != null
				? policy
				: SessionContract.ShutdownPolicy.UNSPECIFIED;
		switch (resolved) {
			case SAVE:
				return saveProgramLocked(true);
			case DISCARD:
				return discardProgramLocked();
			case NONE:
			case UNSPECIFIED:
			default:
				return true;
		}
	}

	private boolean saveProgramLocked(boolean allowDeferredHeadless) {
		Program program = currentProgram();
		if (program == null) {
			return false;
		}
		final boolean isHeadless = "headless".equals(hostMode());
		TransactionInfo txInfo = null;
		try {
			txInfo = program.getCurrentTransactionInfo();
		}
		catch (RuntimeException e) {
			Msg.warn(this, "transaction state check failed before save: " + e.getMessage());
		}
		if (txInfo != null) {
			Msg.info(
				this,
				"save blocked by active transaction '" + txInfo.getDescription() +
					"' (host_mode=" + hostMode() + ")");
			for (int i = 0; i < 50; i++) {
				try {
					Thread.sleep(100);
				}
				catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					break;
				}
				txInfo = null;
				try {
					txInfo = program.getCurrentTransactionInfo();
				}
				catch (RuntimeException e) {
					// ignore — retry
				}
				if (txInfo == null) {
					break;
				}
			}
			if (txInfo != null) {
				if (isHeadless && allowDeferredHeadless) {
					Msg.info(
						this,
						"deferring save until headless shutdown after active transaction '" +
							txInfo.getDescription() + "'");
					return true;
				}
				Msg.warn(this, "save timed out waiting for active transaction: " + txInfo.getDescription());
				return false;
			}
			Msg.info(this, "transaction cleared, proceeding with save");
		}
		boolean canSave = false;
		try {
			canSave = program.canSave();
		}
		catch (RuntimeException e) {
			Msg.warn(this, "canSave check failed; attempting save anyway: " + e.getMessage());
		}
		try {
			program.save("libghidra save", TaskMonitor.DUMMY);
			bumpRevision();
			return true;
		}
		catch (IOException | CancelledException e) {
			Msg.warn(this, "save failed (host_mode=" + hostMode() + ", canSave=" + canSave + "): " +
				e.getMessage());
			return false;
		}
		catch (RuntimeException e) {
			Msg.warn(this, "runtime save failure (host_mode=" + hostMode() + ", canSave=" + canSave + "): " +
				e.getMessage());
			return false;
		}
	}

	private boolean discardProgramLocked() {
		Program program = currentProgram();
		if (program == null) {
			return false;
		}
		try {
			int count = 0;
			while (program.canUndo()) {
				program.undo();
				count++;
				if (count > 10000) {
					break;
				}
			}
			bumpRevision();
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}
}
