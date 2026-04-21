package libghidra.host.contract;

import java.util.List;

public final class TypesContract {

	private TypesContract() {
	}

	public record TypeRecord(
		long typeId,
		String name,
		String pathName,
		String categoryPath,
		String displayName,
		String kind,
		int length,
		boolean isNotYetDefined,
		String sourceArchive,
		String universalId) {
	}

	public record ParameterRecord(
		int ordinal,
		String name,
		String dataType,
		String formalDataType,
		boolean isAutoParameter,
		boolean isForcedIndirect) {
	}

	public record FunctionSignatureRecord(
		long functionEntryAddress,
		String functionName,
		String prototype,
		String returnType,
		boolean hasVarArgs,
		String callingConvention,
		List<ParameterRecord> parameters) {
	}

	public record GetTypeRequest(
		String path) {
	}

	public record GetTypeResponse(TypeRecord type) {
	}

	public record ListTypesRequest(
		String query,
		int limit,
		int offset) {
	}

	public record ListTypesResponse(List<TypeRecord> types) {
	}

	public record TypeAliasRecord(
		long typeId,
		String pathName,
		String name,
		String targetType,
		String declaration) {
	}

	public record TypeUnionRecord(
		long typeId,
		String pathName,
		String name,
		long size,
		String declaration) {
	}

	public record TypeEnumRecord(
		long typeId,
		String pathName,
		String name,
		long width,
		boolean signed,
		String declaration) {
	}

	public record TypeEnumMemberRecord(
		long typeId,
		String typePathName,
		String typeName,
		long ordinal,
		String name,
		long value,
		String comment) {
	}

	public record TypeMemberRecord(
		long parentTypeId,
		String parentTypePathName,
		String parentTypeName,
		long ordinal,
		String name,
		String memberType,
		long offset,
		long size,
		String comment) {
	}

	public record ListTypeAliasesRequest(
		String query,
		int limit,
		int offset) {
	}

	public record ListTypeAliasesResponse(List<TypeAliasRecord> aliases) {
	}

	public record ListTypeUnionsRequest(
		String query,
		int limit,
		int offset) {
	}

	public record ListTypeUnionsResponse(List<TypeUnionRecord> unions) {
	}

	public record ListTypeEnumsRequest(
		String query,
		int limit,
		int offset) {
	}

	public record ListTypeEnumsResponse(List<TypeEnumRecord> enums) {
	}

	public record ListTypeEnumMembersRequest(
		String type,
		int limit,
		int offset) {
	}

	public record ListTypeEnumMembersResponse(List<TypeEnumMemberRecord> members) {
	}

	public record ListTypeMembersRequest(
		String type,
		int limit,
		int offset) {
	}

	public record ListTypeMembersResponse(List<TypeMemberRecord> members) {
	}

	public record GetFunctionSignatureRequest(
		long address) {
	}

	public record GetFunctionSignatureResponse(FunctionSignatureRecord signature) {
	}

	public record ListFunctionSignaturesRequest(
		long rangeStart,
		long rangeEnd,
		int limit,
		int offset) {
	}

	public record ListFunctionSignaturesResponse(List<FunctionSignatureRecord> signatures) {
	}

	public record SetFunctionSignatureRequest(
		long address,
		String prototype,
		String callingConvention) {
	}

	public record SetFunctionSignatureResponse(
		boolean updated,
		String functionName,
		String prototype,
		String errorCode,
		String errorMessage) {
	}

	public record RenameFunctionParameterRequest(
		long address,
		int ordinal,
		String newName) {
	}

	public record RenameFunctionParameterResponse(
		boolean updated,
		String name,
		String errorCode,
		String errorMessage) {
	}

	public record SetFunctionParameterTypeRequest(
		long address,
		int ordinal,
		String dataType) {
	}

	public record SetFunctionParameterTypeResponse(
		boolean updated,
		String dataType,
		String errorCode,
		String errorMessage) {
	}

	public record RenameFunctionLocalRequest(
		long address,
		String localId,
		String newName) {
	}

	public record RenameFunctionLocalResponse(
		boolean updated,
		String localId,
		String name,
		String errorCode,
		String errorMessage) {
	}

	public record SetFunctionLocalTypeRequest(
		long address,
		String localId,
		String dataType) {
	}

	public record SetFunctionLocalTypeResponse(
		boolean updated,
		String localId,
		String dataType,
		String errorCode,
		String errorMessage) {
	}

	public record ApplyDataTypeRequest(
		long address,
		String dataType) {
	}

	public record ApplyDataTypeResponse(
		boolean updated,
		String dataType) {
	}

	public record CreateTypeRequest(
		String name,
		String kind,
		long size) {
	}

	public record CreateTypeResponse(boolean updated) {
	}

	public record DeleteTypeRequest(
		String type) {
	}

	public record DeleteTypeResponse(boolean deleted) {
	}

	public record RenameTypeRequest(
		String type,
		String newName) {
	}

	public record RenameTypeResponse(
		boolean updated,
		String name) {
	}

	public record CreateTypeAliasRequest(
		String name,
		String targetType) {
	}

	public record CreateTypeAliasResponse(boolean updated) {
	}

	public record DeleteTypeAliasRequest(
		String type) {
	}

	public record DeleteTypeAliasResponse(boolean deleted) {
	}

	public record SetTypeAliasTargetRequest(
		String type,
		String targetType) {
	}

	public record SetTypeAliasTargetResponse(boolean updated) {
	}

	public record CreateTypeEnumRequest(
		String name,
		long width,
		boolean signed) {
	}

	public record CreateTypeEnumResponse(boolean updated) {
	}

	public record DeleteTypeEnumRequest(
		String type) {
	}

	public record DeleteTypeEnumResponse(boolean deleted) {
	}

	public record AddTypeEnumMemberRequest(
		String type,
		String name,
		long value) {
	}

	public record AddTypeEnumMemberResponse(boolean updated) {
	}

	public record DeleteTypeEnumMemberRequest(
		String type,
		long ordinal) {
	}

	public record DeleteTypeEnumMemberResponse(boolean deleted) {
	}

	public record RenameTypeEnumMemberRequest(
		String type,
		long ordinal,
		String newName) {
	}

	public record RenameTypeEnumMemberResponse(boolean updated) {
	}

	public record SetTypeEnumMemberValueRequest(
		String type,
		long ordinal,
		long value) {
	}

	public record SetTypeEnumMemberValueResponse(boolean updated) {
	}

	public record AddTypeMemberRequest(
		String type,
		String name,
		String memberType,
		long size) {
	}

	public record AddTypeMemberResponse(boolean updated) {
	}

	public record DeleteTypeMemberRequest(
		String type,
		long ordinal) {
	}

	public record DeleteTypeMemberResponse(boolean deleted) {
	}

	public record RenameTypeMemberRequest(
		String type,
		long ordinal,
		String newName) {
	}

	public record RenameTypeMemberResponse(boolean updated) {
	}

	public record SetTypeMemberTypeRequest(
		String type,
		long ordinal,
		String memberType) {
	}

	public record SetTypeMemberTypeResponse(boolean updated) {
	}

	public record SetTypeMemberCommentRequest(
		String type,
		long ordinal,
		String comment) {
	}

	public record SetTypeMemberCommentResponse(boolean updated) {
	}

	public record SetTypeEnumMemberCommentRequest(
		String type,
		long ordinal,
		String comment) {
	}

	public record SetTypeEnumMemberCommentResponse(boolean updated) {
	}

	public record ParseDeclarationsRequest(
		String sourceText) {
	}

	public record ParseDeclarationsResponse(
		int typesCreated,
		List<String> typeNames,
		List<String> errors) {
	}
}
