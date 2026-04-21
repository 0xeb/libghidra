package libghidra.host.runtime;

import libghidra.host.contract.TypesContract;

public interface TypesOperations {

	TypesContract.GetTypeResponse getType(TypesContract.GetTypeRequest request);

	TypesContract.ListTypesResponse listTypes(TypesContract.ListTypesRequest request);

	TypesContract.ListTypeAliasesResponse listTypeAliases(
		TypesContract.ListTypeAliasesRequest request);

	TypesContract.ListTypeUnionsResponse listTypeUnions(
		TypesContract.ListTypeUnionsRequest request);

	TypesContract.ListTypeEnumsResponse listTypeEnums(TypesContract.ListTypeEnumsRequest request);

	TypesContract.ListTypeEnumMembersResponse listTypeEnumMembers(
		TypesContract.ListTypeEnumMembersRequest request);

	TypesContract.ListTypeMembersResponse listTypeMembers(
		TypesContract.ListTypeMembersRequest request);

	TypesContract.GetFunctionSignatureResponse getFunctionSignature(
		TypesContract.GetFunctionSignatureRequest request);

	TypesContract.ListFunctionSignaturesResponse listFunctionSignatures(
		TypesContract.ListFunctionSignaturesRequest request);

	TypesContract.SetFunctionSignatureResponse setFunctionSignature(
		TypesContract.SetFunctionSignatureRequest request);

	TypesContract.RenameFunctionParameterResponse renameFunctionParameter(
		TypesContract.RenameFunctionParameterRequest request);

	TypesContract.SetFunctionParameterTypeResponse setFunctionParameterType(
		TypesContract.SetFunctionParameterTypeRequest request);

	TypesContract.RenameFunctionLocalResponse renameFunctionLocal(
		TypesContract.RenameFunctionLocalRequest request);

	TypesContract.SetFunctionLocalTypeResponse setFunctionLocalType(
		TypesContract.SetFunctionLocalTypeRequest request);

	TypesContract.ApplyDataTypeResponse applyDataType(TypesContract.ApplyDataTypeRequest request);

	TypesContract.CreateTypeResponse createType(TypesContract.CreateTypeRequest request);

	TypesContract.DeleteTypeResponse deleteType(TypesContract.DeleteTypeRequest request);

	TypesContract.RenameTypeResponse renameType(TypesContract.RenameTypeRequest request);

	TypesContract.CreateTypeAliasResponse createTypeAlias(
		TypesContract.CreateTypeAliasRequest request);

	TypesContract.DeleteTypeAliasResponse deleteTypeAlias(
		TypesContract.DeleteTypeAliasRequest request);

	TypesContract.SetTypeAliasTargetResponse setTypeAliasTarget(
		TypesContract.SetTypeAliasTargetRequest request);

	TypesContract.CreateTypeEnumResponse createTypeEnum(
		TypesContract.CreateTypeEnumRequest request);

	TypesContract.DeleteTypeEnumResponse deleteTypeEnum(
		TypesContract.DeleteTypeEnumRequest request);

	TypesContract.AddTypeEnumMemberResponse addTypeEnumMember(
		TypesContract.AddTypeEnumMemberRequest request);

	TypesContract.DeleteTypeEnumMemberResponse deleteTypeEnumMember(
		TypesContract.DeleteTypeEnumMemberRequest request);

	TypesContract.RenameTypeEnumMemberResponse renameTypeEnumMember(
		TypesContract.RenameTypeEnumMemberRequest request);

	TypesContract.SetTypeEnumMemberValueResponse setTypeEnumMemberValue(
		TypesContract.SetTypeEnumMemberValueRequest request);

	TypesContract.AddTypeMemberResponse addTypeMember(TypesContract.AddTypeMemberRequest request);

	TypesContract.DeleteTypeMemberResponse deleteTypeMember(
		TypesContract.DeleteTypeMemberRequest request);

	TypesContract.RenameTypeMemberResponse renameTypeMember(
		TypesContract.RenameTypeMemberRequest request);

	TypesContract.SetTypeMemberTypeResponse setTypeMemberType(
		TypesContract.SetTypeMemberTypeRequest request);

	TypesContract.SetTypeMemberCommentResponse setTypeMemberComment(
		TypesContract.SetTypeMemberCommentRequest request);

	TypesContract.SetTypeEnumMemberCommentResponse setTypeEnumMemberComment(
		TypesContract.SetTypeEnumMemberCommentRequest request);

	TypesContract.ParseDeclarationsResponse parseDeclarations(
		TypesContract.ParseDeclarationsRequest request);
}
