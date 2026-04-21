package libghidra.host.runtime;

import libghidra.host.contract.SessionContract;

public interface SessionOperations {

	SessionContract.OpenProgramResponse openProgram(SessionContract.OpenProgramRequest request);

	SessionContract.CloseProgramResponse closeProgram(SessionContract.CloseProgramRequest request);

	SessionContract.SaveProgramResponse saveProgram(SessionContract.SaveProgramRequest request);

	SessionContract.DiscardProgramResponse discardProgram(SessionContract.DiscardProgramRequest request);

	SessionContract.GetRevisionResponse getRevision(SessionContract.GetRevisionRequest request);

	SessionContract.ShutdownResponse shutdown(SessionContract.ShutdownRequest request);
}
