// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import libghidra.host.contract.FunctionsContract;

public interface FunctionsOperations {

	FunctionsContract.GetFunctionResponse getFunction(FunctionsContract.GetFunctionRequest request);

	FunctionsContract.ListFunctionsResponse listFunctions(FunctionsContract.ListFunctionsRequest request);

	FunctionsContract.ListFunctionsResponse listLeafFunctions(
		FunctionsContract.ListFunctionsRequest request);

	FunctionsContract.RenameFunctionResponse renameFunction(
		FunctionsContract.RenameFunctionRequest request);

	FunctionsContract.ListBasicBlocksResponse listBasicBlocks(
		FunctionsContract.ListBasicBlocksRequest request);

	FunctionsContract.ListCFGEdgesResponse listCFGEdges(
		FunctionsContract.ListCFGEdgesRequest request);

	FunctionsContract.ListFunctionTagsResponse listFunctionTags(
		FunctionsContract.ListFunctionTagsRequest request);

	FunctionsContract.CreateFunctionTagResponse createFunctionTag(
		FunctionsContract.CreateFunctionTagRequest request);

	FunctionsContract.DeleteFunctionTagResponse deleteFunctionTag(
		FunctionsContract.DeleteFunctionTagRequest request);

	FunctionsContract.ListFunctionTagMappingsResponse listFunctionTagMappings(
		FunctionsContract.ListFunctionTagMappingsRequest request);

	FunctionsContract.TagFunctionResponse tagFunction(
		FunctionsContract.TagFunctionRequest request);

	FunctionsContract.UntagFunctionResponse untagFunction(
		FunctionsContract.UntagFunctionRequest request);

	FunctionsContract.ListSwitchTablesResponse listSwitchTables(
		FunctionsContract.ListSwitchTablesRequest request);

	FunctionsContract.ListDominatorsResponse listDominators(
		FunctionsContract.ListDominatorsRequest request);

	FunctionsContract.ListPostDominatorsResponse listPostDominators(
		FunctionsContract.ListPostDominatorsRequest request);

	FunctionsContract.ListLoopsResponse listLoops(
		FunctionsContract.ListLoopsRequest request);

	FunctionsContract.ListFunctionFramesResponse listFunctionFrames(
		FunctionsContract.ListFunctionFramesRequest request);
}
