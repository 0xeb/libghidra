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
		long imageBase) {
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

	public record GetRevisionResponse(long revision) {
	}

	public record ShutdownRequest(ShutdownPolicy shutdownPolicy) {
	}

	public record ShutdownResponse(boolean accepted) {
	}
}
