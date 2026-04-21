package libghidra.host.service;

import libghidra.host.contract.TypesContract;
import libghidra.host.runtime.TypesOperations;

public final class TypesServiceHandler {

	private final TypesOperations runtime;

	public TypesServiceHandler(TypesOperations runtime) {
		this.runtime = runtime;
	}

	public TypesContract.GetTypeResponse getType(
			TypesContract.GetTypeRequest request) {
		if (request == null) {
			request = new TypesContract.GetTypeRequest(
				"");
		}
		return runtime.getType(request);
	}

	public TypesContract.ListTypesResponse listTypes(
			TypesContract.ListTypesRequest request) {
		if (request == null) {
			request = new TypesContract.ListTypesRequest(
				"",
				0,
				0);
		}
		return runtime.listTypes(request);
	}

	public TypesContract.ListTypeAliasesResponse listTypeAliases(
			TypesContract.ListTypeAliasesRequest request) {
		if (request == null) {
			request = new TypesContract.ListTypeAliasesRequest(
				"",
				0,
				0);
		}
		return runtime.listTypeAliases(request);
	}

	public TypesContract.ListTypeUnionsResponse listTypeUnions(
			TypesContract.ListTypeUnionsRequest request) {
		if (request == null) {
			request = new TypesContract.ListTypeUnionsRequest(
				"",
				0,
				0);
		}
		return runtime.listTypeUnions(request);
	}

	public TypesContract.ListTypeEnumsResponse listTypeEnums(
			TypesContract.ListTypeEnumsRequest request) {
		if (request == null) {
			request = new TypesContract.ListTypeEnumsRequest(
				"",
				0,
				0);
		}
		return runtime.listTypeEnums(request);
	}

	public TypesContract.ListTypeEnumMembersResponse listTypeEnumMembers(
			TypesContract.ListTypeEnumMembersRequest request) {
		if (request == null) {
			request = new TypesContract.ListTypeEnumMembersRequest(
				"",
				0,
				0);
		}
		return runtime.listTypeEnumMembers(request);
	}

	public TypesContract.ListTypeMembersResponse listTypeMembers(
			TypesContract.ListTypeMembersRequest request) {
		if (request == null) {
			request = new TypesContract.ListTypeMembersRequest(
				"",
				0,
				0);
		}
		return runtime.listTypeMembers(request);
	}

	public TypesContract.GetFunctionSignatureResponse getFunctionSignature(
			TypesContract.GetFunctionSignatureRequest request) {
		if (request == null) {
			request = new TypesContract.GetFunctionSignatureRequest(
				0L);
		}
		return runtime.getFunctionSignature(request);
	}

	public TypesContract.ListFunctionSignaturesResponse listFunctionSignatures(
			TypesContract.ListFunctionSignaturesRequest request) {
		if (request == null) {
			request = new TypesContract.ListFunctionSignaturesRequest(
				0L,
				0L,
				0,
				0);
		}
		return runtime.listFunctionSignatures(request);
	}

	public TypesContract.SetFunctionSignatureResponse setFunctionSignature(
			TypesContract.SetFunctionSignatureRequest request) {
		if (request == null) {
			request = new TypesContract.SetFunctionSignatureRequest(
				0L,
				"",
				"");
		}
		return runtime.setFunctionSignature(request);
	}

	public TypesContract.RenameFunctionParameterResponse renameFunctionParameter(
			TypesContract.RenameFunctionParameterRequest request) {
		if (request == null) {
			request = new TypesContract.RenameFunctionParameterRequest(
				0L,
				-1,
				"");
		}
		return runtime.renameFunctionParameter(request);
	}

	public TypesContract.SetFunctionParameterTypeResponse setFunctionParameterType(
			TypesContract.SetFunctionParameterTypeRequest request) {
		if (request == null) {
			request = new TypesContract.SetFunctionParameterTypeRequest(
				0L,
				-1,
				"");
		}
		return runtime.setFunctionParameterType(request);
	}

	public TypesContract.RenameFunctionLocalResponse renameFunctionLocal(
			TypesContract.RenameFunctionLocalRequest request) {
		if (request == null) {
			request = new TypesContract.RenameFunctionLocalRequest(
				0L,
				"",
				"");
		}
		return runtime.renameFunctionLocal(request);
	}

	public TypesContract.SetFunctionLocalTypeResponse setFunctionLocalType(
			TypesContract.SetFunctionLocalTypeRequest request) {
		if (request == null) {
			request = new TypesContract.SetFunctionLocalTypeRequest(
				0L,
				"",
				"");
		}
		return runtime.setFunctionLocalType(request);
	}

	public TypesContract.ApplyDataTypeResponse applyDataType(
			TypesContract.ApplyDataTypeRequest request) {
		if (request == null) {
			request = new TypesContract.ApplyDataTypeRequest(
				0L,
				"");
		}
		return runtime.applyDataType(request);
	}

	public TypesContract.CreateTypeResponse createType(
			TypesContract.CreateTypeRequest request) {
		if (request == null) {
			request = new TypesContract.CreateTypeRequest(
				"",
				"",
				0L);
		}
		return runtime.createType(request);
	}

	public TypesContract.DeleteTypeResponse deleteType(
			TypesContract.DeleteTypeRequest request) {
		if (request == null) {
			request = new TypesContract.DeleteTypeRequest(
				"");
		}
		return runtime.deleteType(request);
	}

	public TypesContract.RenameTypeResponse renameType(
			TypesContract.RenameTypeRequest request) {
		if (request == null) {
			request = new TypesContract.RenameTypeRequest(
				"",
				"");
		}
		return runtime.renameType(request);
	}

	public TypesContract.CreateTypeAliasResponse createTypeAlias(
			TypesContract.CreateTypeAliasRequest request) {
		if (request == null) {
			request = new TypesContract.CreateTypeAliasRequest(
				"",
				"");
		}
		return runtime.createTypeAlias(request);
	}

	public TypesContract.DeleteTypeAliasResponse deleteTypeAlias(
			TypesContract.DeleteTypeAliasRequest request) {
		if (request == null) {
			request = new TypesContract.DeleteTypeAliasRequest(
				"");
		}
		return runtime.deleteTypeAlias(request);
	}

	public TypesContract.SetTypeAliasTargetResponse setTypeAliasTarget(
			TypesContract.SetTypeAliasTargetRequest request) {
		if (request == null) {
			request = new TypesContract.SetTypeAliasTargetRequest(
				"",
				"");
		}
		return runtime.setTypeAliasTarget(request);
	}

	public TypesContract.CreateTypeEnumResponse createTypeEnum(
			TypesContract.CreateTypeEnumRequest request) {
		if (request == null) {
			request = new TypesContract.CreateTypeEnumRequest(
				"",
				0L,
				false);
		}
		return runtime.createTypeEnum(request);
	}

	public TypesContract.DeleteTypeEnumResponse deleteTypeEnum(
			TypesContract.DeleteTypeEnumRequest request) {
		if (request == null) {
			request = new TypesContract.DeleteTypeEnumRequest(
				"");
		}
		return runtime.deleteTypeEnum(request);
	}

	public TypesContract.AddTypeEnumMemberResponse addTypeEnumMember(
			TypesContract.AddTypeEnumMemberRequest request) {
		if (request == null) {
			request = new TypesContract.AddTypeEnumMemberRequest(
				"",
				"",
				0L);
		}
		return runtime.addTypeEnumMember(request);
	}

	public TypesContract.DeleteTypeEnumMemberResponse deleteTypeEnumMember(
			TypesContract.DeleteTypeEnumMemberRequest request) {
		if (request == null) {
			request = new TypesContract.DeleteTypeEnumMemberRequest(
				"",
				0L);
		}
		return runtime.deleteTypeEnumMember(request);
	}

	public TypesContract.RenameTypeEnumMemberResponse renameTypeEnumMember(
			TypesContract.RenameTypeEnumMemberRequest request) {
		if (request == null) {
			request = new TypesContract.RenameTypeEnumMemberRequest(
				"",
				0L,
				"");
		}
		return runtime.renameTypeEnumMember(request);
	}

	public TypesContract.SetTypeEnumMemberValueResponse setTypeEnumMemberValue(
			TypesContract.SetTypeEnumMemberValueRequest request) {
		if (request == null) {
			request = new TypesContract.SetTypeEnumMemberValueRequest(
				"",
				0L,
				0L);
		}
		return runtime.setTypeEnumMemberValue(request);
	}

	public TypesContract.AddTypeMemberResponse addTypeMember(
			TypesContract.AddTypeMemberRequest request) {
		if (request == null) {
			request = new TypesContract.AddTypeMemberRequest(
				"",
				"",
				"",
				0L);
		}
		return runtime.addTypeMember(request);
	}

	public TypesContract.DeleteTypeMemberResponse deleteTypeMember(
			TypesContract.DeleteTypeMemberRequest request) {
		if (request == null) {
			request = new TypesContract.DeleteTypeMemberRequest(
				"",
				0L);
		}
		return runtime.deleteTypeMember(request);
	}

	public TypesContract.RenameTypeMemberResponse renameTypeMember(
			TypesContract.RenameTypeMemberRequest request) {
		if (request == null) {
			request = new TypesContract.RenameTypeMemberRequest(
				"",
				0L,
				"");
		}
		return runtime.renameTypeMember(request);
	}

	public TypesContract.SetTypeMemberTypeResponse setTypeMemberType(
			TypesContract.SetTypeMemberTypeRequest request) {
		if (request == null) {
			request = new TypesContract.SetTypeMemberTypeRequest(
				"",
				0L,
				"");
		}
		return runtime.setTypeMemberType(request);
	}

	public TypesContract.SetTypeMemberCommentResponse setTypeMemberComment(
			TypesContract.SetTypeMemberCommentRequest request) {
		if (request == null) {
			request = new TypesContract.SetTypeMemberCommentRequest(
				"",
				0L,
				"");
		}
		return runtime.setTypeMemberComment(request);
	}

	public TypesContract.SetTypeEnumMemberCommentResponse setTypeEnumMemberComment(
			TypesContract.SetTypeEnumMemberCommentRequest request) {
		if (request == null) {
			request = new TypesContract.SetTypeEnumMemberCommentRequest(
				"",
				0L,
				"");
		}
		return runtime.setTypeEnumMemberComment(request);
	}

	public TypesContract.ParseDeclarationsResponse parseDeclarations(
			TypesContract.ParseDeclarationsRequest request) {
		if (request == null) {
			request = new TypesContract.ParseDeclarationsRequest(
				"");
		}
		return runtime.parseDeclarations(request);
	}
}
