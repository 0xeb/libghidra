package libghidra.host.runtime;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import generic.stl.Pair;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.base.project.GhidraProject;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.project.DefaultProjectManager;
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
	private final LibGhidraProjectManager projectManager;
	private Project project;
	private ProjectData projectData;
	private final Object programConsumer;
	private final TaskMonitor taskMonitor;
	private String managedProjectPath;
	private String managedProjectName;
	private final Map<String, DomainFile> knownProgramFiles = new HashMap<>();

	private SessionRuntime(
			HostState state,
			ControlMode controlMode,
			Project project,
			Object programConsumer,
			TaskMonitor taskMonitor,
			String managedProjectPath,
			String managedProjectName) {
		super(state);
		this.controlMode = controlMode;
		this.projectManager = new LibGhidraProjectManager();
		this.project = project;
		this.projectData = project != null ? project.getProjectData() : null;
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
			Project project,
			Object programConsumer,
			TaskMonitor taskMonitor,
			String managedProjectPath,
			String managedProjectName) {
		return new SessionRuntime(
			state,
			ControlMode.MANAGED_HEADLESS,
			project,
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
	public SessionContract.OpenProjectResponse openProject(SessionContract.OpenProjectRequest request) {
		try (LockScope ignored = writeLock()) {
			requireManagedProjectLifecycle("open_project()");
			SessionContract.OpenProjectRequest safeRequest = request != null
					? request
					: new SessionContract.OpenProjectRequest("", "", false, false);
			if (safeRequest.readOnly()) {
				throw new SessionRpcException(
					"NOT_SUPPORTED",
					"read-only project open is not supported by this host");
			}
			String projectPath = safeRequest.projectPath() != null ? safeRequest.projectPath().trim() : "";
			String projectName = safeRequest.projectName() != null ? safeRequest.projectName().trim() : "";
			if (projectPath.isBlank() || projectName.isBlank()) {
				throw new SessionRpcException(
					"invalid_argument",
					"project_path and project_name are required");
			}
			String normalizedPath = ManagedProgramSupport.normalizeProjectPath(projectPath);
			if (project != null && normalizedPath.equals(managedProjectPath) &&
				projectName.equals(managedProjectName)) {
				return new SessionContract.OpenProjectResponse(
					managedProjectPath,
					managedProjectName,
					false);
			}
			if (currentProgram() != null) {
				throw new SessionRpcException(
					"conflict",
					"close the current program before opening another project on this host");
			}
			closeProjectOnlyLocked();
			try {
				ProjectLocator locator = new ProjectLocator(projectPath, projectName);
				Project opened = safeRequest.create()
						? projectManager.createProject(locator, null, false)
						: projectManager.openProject(locator, false, false);
				if (opened == null) {
					throw new IOException("failed to open project: " + projectPath + "/" + projectName);
				}
				adoptProjectLocked(opened);
				return new SessionContract.OpenProjectResponse(
					managedProjectPath,
					managedProjectName,
					safeRequest.create());
			}
			catch (Exception e) {
				throw toSessionException("open_project", e);
			}
		}
	}

	@Override
	public SessionContract.CloseProjectResponse closeProject(SessionContract.CloseProjectRequest request) {
		try (LockScope ignored = writeLock()) {
			requireManagedProjectLifecycle("close_project()");
			SessionContract.ShutdownPolicy policy = request != null
					? request.shutdownPolicy()
					: SessionContract.ShutdownPolicy.UNSPECIFIED;
			if (currentProgram() != null && !closeManagedProgramLocked(policy)) {
				return new SessionContract.CloseProjectResponse(false);
			}
			boolean closed = closeProjectOnlyLocked();
			return new SessionContract.CloseProjectResponse(closed);
		}
	}

	@Override
	public SessionContract.ListProjectFilesResponse listProjectFiles(
			SessionContract.ListProjectFilesRequest request) {
		try (LockScope ignored = readLock()) {
			ProjectData data = requireProjectDataLocked();
			SessionContract.ListProjectFilesRequest safeRequest = request != null
					? request
					: new SessionContract.ListProjectFilesRequest(false, false);
			List<SessionContract.ProjectFile> files = new ArrayList<>();
			if (safeRequest.includeFolders() && !safeRequest.programsOnly()) {
				collectFolders(data.getRootFolder(), files);
			}
			for (DomainFile file : data) {
				SessionContract.ProjectFile mapped = toProjectFile(file);
				if (safeRequest.programsOnly() && !mapped.isProgram()) {
					continue;
				}
				files.add(mapped);
			}
			files.sort((a, b) -> a.path().compareToIgnoreCase(b.path()));
			return new SessionContract.ListProjectFilesResponse(files);
		}
	}

	@Override
	public SessionContract.ImportProgramResponse importProgram(
			SessionContract.ImportProgramRequest request) {
		try (LockScope ignored = writeLock()) {
			requireManagedProjectLifecycle("import_program()");
			Project targetProject = requireProjectLocked();
			SessionContract.ImportProgramRequest safeRequest = request != null
					? request
					: new SessionContract.ImportProgramRequest(
						"", "", "", false, false, "", "", "", List.of());
			String sourcePath = safeRequest.sourcePath() != null ? safeRequest.sourcePath().trim() : "";
			if (sourcePath.isBlank()) {
				throw new SessionRpcException("invalid_argument", "source_path is required");
			}
			File source = new File(sourcePath);
			if (!source.isFile()) {
				throw new SessionRpcException("not_found", "source binary not found: " + sourcePath);
			}
			String folderPath = normalizeProjectFolderPath(safeRequest.projectFolderPath());
			try {
				if (safeRequest.overwrite()) {
					deleteExistingImportTargetLocked(safeRequest, source, folderPath);
				}
				try (LoadResults<Program> results = buildProgramLoader(targetProject, safeRequest, source, folderPath)
					.load()) {
					List<String> paths = new ArrayList<>();
					for (Loaded<Program> loaded : results) {
						Program loadedProgram = loaded.getDomainObject(programConsumer);
						try {
							if (safeRequest.analyze()) {
								GhidraProject.analyze(loadedProgram);
							}
							DomainFile saved = loaded.save(taskMonitor);
							String path = ManagedProgramSupport.normalizeProgramPath(saved.getPathname());
							paths.add(path);
							knownProgramFiles.put(path, saved);
						}
						finally {
							loadedProgram.release(programConsumer);
						}
					}
					String primary = paths.isEmpty() ? "" : paths.get(0);
					return new SessionContract.ImportProgramResponse(paths, primary);
				}
			}
			catch (Exception e) {
				throw toSessionException("import_program", e);
			}
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
		return new SessionContract.GetRevisionResponse(
			programId(),
			modificationNumber(),
			currentProgramPath(),
			fileId(),
			fileVersion(),
			fileLastModifiedTime());
	}

	@Override
	public SessionContract.ShutdownResponse shutdown(SessionContract.ShutdownRequest request) {
		try (LockScope ignored = writeLock()) {
			SessionContract.ShutdownPolicy policy = request != null
					? request.shutdownPolicy()
					: SessionContract.ShutdownPolicy.UNSPECIFIED;
			boolean ok = applyShutdownPolicyLocked(policy);
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
		if (projectData == null) {
			throw new SessionRpcException("not_found", "no project is open on this host");
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
				return describeCurrentProgram(current);
			}
			throw new SessionRpcException(
				"conflict",
				"close the current program before opening another one on this host");
		}
		try {
			DomainFile file = projectData.getFile(requestedProgramPath);
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

	private void requireManagedProjectLifecycle(String operation) {
		if (controlMode != ControlMode.MANAGED_HEADLESS) {
			throw new SessionRpcException(
				"NOT_SUPPORTED",
				operation + " is only supported for managed headless hosts");
		}
	}

	private Project requireProjectLocked() {
		if (project == null || projectData == null) {
			throw new SessionRpcException("not_found", "no project is open on this host");
		}
		return project;
	}

	private ProjectData requireProjectDataLocked() {
		return requireProjectLocked().getProjectData();
	}

	private void adoptProjectLocked(Project opened) {
		project = opened;
		projectData = opened.getProjectData();
		ProjectLocator locator = projectData.getProjectLocator();
		managedProjectPath = locator != null
				? ManagedProgramSupport.normalizeProjectPath(locator.getLocation())
				: "";
		managedProjectName = locator != null ? locator.getName() : "";
		knownProgramFiles.clear();
	}

	private boolean closeProjectOnlyLocked() {
		if (project == null) {
			projectData = null;
			managedProjectPath = "";
			managedProjectName = "";
			knownProgramFiles.clear();
			return false;
		}
		try {
			project.close();
			project = null;
			projectData = null;
			managedProjectPath = "";
			managedProjectName = "";
			knownProgramFiles.clear();
			return true;
		}
		catch (RuntimeException e) {
			throw new SessionRpcException("internal_error", e.getMessage());
		}
	}

	private void collectFolders(DomainFolder folder, List<SessionContract.ProjectFile> out) {
		if (folder == null) {
			return;
		}
		if (!"/".equals(folder.getPathname())) {
			out.add(new SessionContract.ProjectFile(
				ManagedProgramSupport.normalizeProgramPath(folder.getPathname()),
				folder.getName(),
				folder.getParent() != null ? folder.getParent().getPathname() : "",
				"folder",
				"",
				true,
				false));
		}
		for (DomainFolder child : folder.getFolders()) {
			collectFolders(child, out);
		}
	}

	private SessionContract.ProjectFile toProjectFile(DomainFile file) {
		Class<?> clazz = file.getDomainObjectClass();
		boolean isProgram = clazz != null && Program.class.isAssignableFrom(clazz);
		String path = ManagedProgramSupport.normalizeProgramPath(file.getPathname());
		int slash = path.lastIndexOf('/');
		String folderPath = slash > 0 ? path.substring(0, slash) : "/";
		return new SessionContract.ProjectFile(
			path,
			file.getName(),
			folderPath,
			file.getContentType(),
			clazz != null ? clazz.getName() : "",
			false,
			isProgram);
	}

	private ProgramLoader.Builder buildProgramLoader(
			Project targetProject,
			SessionContract.ImportProgramRequest request,
			File source,
			String folderPath) throws Exception {
		ProgramLoader.Builder builder = ProgramLoader.builder()
			.source(source)
			.project(targetProject)
			.projectFolderPath(folderPath)
			.monitor(taskMonitor);
		if (request.programName() != null && !request.programName().isBlank()) {
			builder.name(request.programName().trim());
		}
		if (request.languageId() != null && !request.languageId().isBlank()) {
			builder.language(request.languageId().trim());
		}
		if (request.compilerSpecId() != null && !request.compilerSpecId().isBlank()) {
			builder.compiler(request.compilerSpecId().trim());
		}
		if (request.loaderClass() != null && !request.loaderClass().isBlank()) {
			applyLoaderClass(builder, request.loaderClass().trim());
		}
		List<Pair<String, String>> args = new ArrayList<>();
		if (request.loaderArgs() != null) {
			for (SessionContract.LoaderArg arg : request.loaderArgs()) {
				if (arg == null || arg.name() == null || arg.name().isBlank()) {
					continue;
				}
				args.add(new Pair<>(arg.name(), arg.value() != null ? arg.value() : ""));
			}
		}
		if (!args.isEmpty()) {
			builder.loaderArgs(args);
		}
		return builder;
	}

	private void applyLoaderClass(ProgramLoader.Builder builder, String loaderClass) throws Exception {
		try {
			builder.loaders(loaderClass);
		}
		catch (Exception e) {
			int dot = loaderClass.lastIndexOf('.');
			if (dot <= 0 || dot == loaderClass.length() - 1) {
				throw e;
			}
			builder.loaders(loaderClass.substring(dot + 1));
		}
	}

	private void deleteExistingImportTargetLocked(
			SessionContract.ImportProgramRequest request,
			File source,
			String folderPath) throws IOException {
		String name = request.programName() != null && !request.programName().isBlank()
				? request.programName().trim()
				: source.getName();
		String targetPath = ManagedProgramSupport.normalizeProgramPath(folderPath + "/" + name);
		if (targetPath.equals(currentProgramPath())) {
			throw new SessionRpcException(
				"conflict",
				"close the current program before overwriting it: " + targetPath);
		}
		DomainFile existing = projectData != null ? projectData.getFile(targetPath) : null;
		if (existing != null) {
			existing.delete();
			knownProgramFiles.remove(targetPath);
		}
	}

	private static String normalizeProjectFolderPath(String folderPath) {
		String normalized = ManagedProgramSupport.normalizeProgramPath(folderPath);
		if (normalized.isBlank()) {
			return "/";
		}
		while (normalized.length() > 1 && normalized.endsWith("/")) {
			normalized = normalized.substring(0, normalized.length() - 1);
		}
		return normalized;
	}

	private SessionRpcException toSessionException(String operation, Exception e) {
		if (e instanceof SessionRpcException session) {
			return session;
		}
		String message = e.getMessage();
		return new SessionRpcException(
			"internal_error",
			operation + " failed: " + (message != null && !message.isBlank() ? message : e.toString()));
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
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	private static final class LibGhidraProjectManager extends DefaultProjectManager {
	}
}
