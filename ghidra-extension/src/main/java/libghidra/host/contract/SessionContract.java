package libghidra.host.contract;

public final class SessionContract {

	private SessionContract() {
	}

	public enum ShutdownPolicy {
		UNSPECIFIED,
		SAVE,
		DISCARD,
		NONE
	}

	public record OpenProgramRequest(
		String projectPath,
		String projectName,
		String programPath,
		boolean analyze,
		boolean readOnly,
		String languageId,
		String compilerSpecId,
		String format,
		long baseAddress) {
	}

	public record OpenProgramResponse(
		String programName,
		String languageId,
		String compilerSpec,
		long imageBase,
		String md5,
		String sha256) {
	}

	public record OpenProjectRequest(
		String projectPath,
		String projectName,
		boolean create,
		boolean readOnly) {
	}

	public record OpenProjectResponse(
		String projectPath,
		String projectName,
		boolean created) {
	}

	public record CloseProjectRequest(ShutdownPolicy shutdownPolicy) {
	}

	public record CloseProjectResponse(boolean closed) {
	}

	public record ProjectFile(
		String path,
		String name,
		String folderPath,
		String contentType,
		String domainObjectClass,
		boolean isFolder,
		boolean isProgram) {
	}

	public record ListProjectFilesRequest(
		boolean includeFolders,
		boolean programsOnly) {
	}

	public record ListProjectFilesResponse(
		java.util.List<ProjectFile> files) {
	}

	public record LoaderArg(String name, String value) {
	}

	public record ImportProgramRequest(
		String sourcePath,
		String projectFolderPath,
		String programName,
		boolean overwrite,
		boolean analyze,
		String languageId,
		String compilerSpecId,
		String loaderClass,
		java.util.List<LoaderArg> loaderArgs) {
	}

	public record ImportProgramResponse(
		java.util.List<String> programPaths,
		String primaryProgramPath) {
	}

	public record CloseProgramRequest(
		ShutdownPolicy shutdownPolicy) {
	}

	public record CloseProgramResponse(boolean closed) {
	}

	public record SaveProgramRequest() {
	}

	public record SaveProgramResponse(boolean saved) {
	}

	public record DiscardProgramRequest() {
	}

	public record DiscardProgramResponse(boolean discarded) {
	}

	public record GetRevisionRequest() {
	}

	public record GetRevisionResponse(
		long programId,
		long modificationNumber,
		String programPath,
		String fileId,
		int fileVersion,
		long fileLastModifiedTime) {
	}

	public record ShutdownRequest(ShutdownPolicy shutdownPolicy) {
	}

	public record ShutdownResponse(boolean accepted) {
	}
}
