package libghidra.host.runtime;

import libghidra.host.contract.SessionContract;

public interface SessionOperations {

	SessionContract.OpenProjectResponse openProject(SessionContract.OpenProjectRequest request);

	SessionContract.CloseProjectResponse closeProject(SessionContract.CloseProjectRequest request);

	SessionContract.ListProjectFilesResponse listProjectFiles(
		SessionContract.ListProjectFilesRequest request);

	SessionContract.ImportProgramResponse importProgram(SessionContract.ImportProgramRequest request);

	SessionContract.OpenProgramResponse openProgram(SessionContract.OpenProgramRequest request);

	SessionContract.CloseProgramResponse closeProgram(SessionContract.CloseProgramRequest request);

	SessionContract.SaveProgramResponse saveProgram(SessionContract.SaveProgramRequest request);

	SessionContract.DiscardProgramResponse discardProgram(SessionContract.DiscardProgramRequest request);

	SessionContract.GetRevisionResponse getRevision(SessionContract.GetRevisionRequest request);

	SessionContract.ShutdownResponse shutdown(SessionContract.ShutdownRequest request);
}
