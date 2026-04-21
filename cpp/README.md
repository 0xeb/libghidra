# LocalClient API Reference

Reference for the libghidra C++ LocalClient in the `0.0.1` release -- an offline binary analysis engine embedding Ghidra's Sleigh decompiler. No Java, no network, no running Ghidra instance required.

## Overview

LocalClient implements the shared `IClient` surface backed by Ghidra's C++ decompiler engine, with unsupported live-Ghidra concepts returning `NOT_SUPPORTED`. It supports decompilation, function/symbol/type queries, memory read/write, instruction disassembly, comments, data items, cross-references, and basic block/CFG extraction.

All methods return `StatusOr<T>` -- check `.ok()`, then access `.value`.

## Quick Start

```cpp
#include "libghidra/ghidra.hpp"

auto client = ghidra::local({});

ghidra::OpenRequest req;
req.program_path = "/path/to/binary.exe";
auto r = client->OpenProgram(req);
if (!r.ok()) { /* handle error */ }

auto decomp = client->GetDecompilation(0x140001000, 30000);
if (decomp.ok() && decomp.value->decompilation)
    printf("%s\n", decomp.value->decompilation->pseudocode.c_str());
```

## Factory & Options

### `ghidra::local(opts)` / `CreateLocalClient(opts)`

```cpp
auto client = ghidra::local({
    .ghidra_root  = "",              // Ghidra source tree (empty = embedded specs)
    .state_path   = "state.xml",     // XML persistence (empty = disabled)
    .default_arch = "x86:LE:64:default",  // Sleigh ID (empty = auto-detect)
    .pool_size    = 4,               // Parallel decompiler slots (default: 1)
});
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ghidra_root` | `string` | `""` | Path to Ghidra source tree for `.sla`/`.pspec`/`.cspec` files. Empty uses embedded specs. |
| `state_path` | `string` | `""` | Path for auto-save/load of analysis state (XML). Empty disables persistence. |
| `default_arch` | `string` | `""` | Sleigh language ID hint (e.g. `"x86:LE:64:default"`). Empty auto-detects from binary format. |
| `pool_size` | `int` | `1` | Number of independent decompiler instances for parallel work. Each loads the binary separately. |

**Type aliases:**
- `ghidra::Client` = `IClient`
- `ghidra::LocalOptions` = `LocalClientOptions`
- `ghidra::OpenRequest` = `OpenProgramRequest`
- `ghidra::Result<T>` = `StatusOr<T>`

## Error Handling

Every method returns `StatusOr<T>`:

```cpp
auto result = client->ListFunctions(0, UINT64_MAX, 0, 0);
if (!result.ok()) {
    // result.status.code    -- error code (e.g. "NOT_SUPPORTED", "INVALID_ARGUMENT")
    // result.status.message -- human-readable description
    return;
}
// result.value is std::optional<T>, guaranteed non-empty when ok() is true
for (auto& f : result.value->functions) { ... }
```

Common error codes:
- `"NOT_SUPPORTED"` -- method not implemented by this backend
- `"INVALID_ARGUMENT"` -- bad parameters (e.g. unknown type name)
- `"NOT_FOUND"` -- entity not found at the given address/name

## Session

### OpenProgram

```cpp
StatusOr<OpenProgramResponse> OpenProgram(const OpenProgramRequest& request)
```

Opens a binary for analysis. Must be called before any query methods.

```cpp
ghidra::OpenRequest req;
req.program_path = "/path/to/binary.exe";
auto r = client->OpenProgram(req);
// r.value->program_name   -- detected program name
// r.value->language_id    -- Sleigh language (e.g. "x86:LE:64:default")
// r.value->compiler_spec  -- compiler spec (e.g. "windows")
// r.value->image_base     -- loaded image base address
```

| Field | Type | Description |
|-------|------|-------------|
| `program_path` | `string` | Path to binary file (required) |
| `project_path` | `string` | Unused by LocalClient |
| `project_name` | `string` | Unused by LocalClient |
| `analyze` | `bool` | Unused by LocalClient |
| `read_only` | `bool` | Unused by LocalClient |

### CloseProgram

```cpp
StatusOr<CloseProgramResponse> CloseProgram(ShutdownPolicy policy)
```

Closes the current program. Pass `ShutdownPolicy::kSave` to save state first, `kDiscard` to abandon changes.

### SaveProgram

```cpp
StatusOr<SaveProgramResponse> SaveProgram()
```

Saves analysis state to `state_path` (if configured). Includes renames, types, and other mutations.

### DiscardProgram

```cpp
StatusOr<DiscardProgramResponse> DiscardProgram()
```

Discards all unsaved mutations since last save.

### GetRevision

```cpp
StatusOr<RevisionResponse> GetRevision()
```

Returns current revision counter. Increments on each mutation (rename, type creation, etc.).

```cpp
auto rev = client->GetRevision();
uint64_t n = rev.value->revision;  // e.g. 0, 1, 2, ...
```

### GetStatus

```cpp
StatusOr<HealthStatus> GetStatus()
```

Returns backend status information.

```cpp
auto s = client->GetStatus();
// s.value->service_name     -- "libghidra-local"
// s.value->service_version  -- version string
// s.value->host_mode        -- "local"
// s.value->program_revision -- current revision
```

### GetCapabilities

```cpp
StatusOr<std::vector<Capability>> GetCapabilities()
```

Lists all capabilities with their support status (`"supported"`, `"not_supported"`).

```cpp
auto caps = client->GetCapabilities();
for (auto& c : *caps.value) {
    printf("%s: %s\n", c.id.c_str(), c.status.c_str());
    // c.note -- optional explanation
}
```

### Shutdown

```cpp
StatusOr<ShutdownResponse> Shutdown(ShutdownPolicy policy)
```

Shuts down the client. Equivalent to `CloseProgram` for the local backend.

## Decompiler

### GetDecompilation

```cpp
StatusOr<GetDecompilationResponse> GetDecompilation(uint64_t address, int timeout_ms)
```

Decompiles the function at `address`. This is a prerequisite for signature, xref, and basic block data.

```cpp
auto d = client->GetDecompilation(0x140001000, 30000);
if (d.ok() && d.value->decompilation) {
    auto& dec = *d.value->decompilation;
    // dec.pseudocode            -- C-like source
    // dec.function_name         -- function name
    // dec.prototype             -- function prototype
    // dec.function_entry_address
    // dec.completed             -- true if decompilation succeeded
    // dec.error_message         -- non-empty on failure
}
```

### ListDecompilations

```cpp
StatusOr<ListDecompilationsResponse> ListDecompilations(
    uint64_t range_start, uint64_t range_end, int limit, int offset, int timeout_ms)
```

Batch-decompiles all functions in the address range. Uses the decompiler pool for parallel execution when `pool_size > 1`.

```cpp
auto client = ghidra::local({.pool_size = 4});
// ... open program ...
auto ds = client->ListDecompilations(0, 0, 0, 0, 60000);
for (auto& d : ds.value->decompilations) {
    if (d.completed) printf("%s: %zu bytes\n", d.function_name.c_str(), d.pseudocode.size());
}
```

Pass `range_start = 0, range_end = 0` for all functions.

## Functions

### GetFunction

```cpp
StatusOr<GetFunctionResponse> GetFunction(uint64_t address)
```

Gets a single function by entry address.

```cpp
auto f = client->GetFunction(0x140001000);
if (f.ok() && f.value->function) {
    // f.value->function->name, entry_address, start_address, end_address, size
    // f.value->function->prototype, parameter_count, is_thunk, namespace_name
}
```

### ListFunctions

```cpp
StatusOr<ListFunctionsResponse> ListFunctions(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Lists functions in an address range. `limit=0` returns all. `range_start=0, range_end=UINT64_MAX` covers everything.

```cpp
auto funcs = client->ListFunctions(0, UINT64_MAX, 10, 0);
for (auto& f : funcs.value->functions) {
    printf("0x%llx  %s  (%u bytes)\n", f.entry_address, f.name.c_str(), (unsigned)f.size);
}
```

### RenameFunction

```cpp
StatusOr<RenameFunctionResponse> RenameFunction(uint64_t address, const string& new_name)
```

Renames the function at `address`. Increments revision.

### ListBasicBlocks

```cpp
StatusOr<ListBasicBlocksResponse> ListBasicBlocks(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Extracts basic blocks for functions in the range. Requires prior decompilation.

```cpp
auto blocks = client->ListBasicBlocks(func.start_address, func.end_address, 0, 0);
for (auto& b : blocks.value->blocks) {
    // b.function_entry, b.start_address, b.end_address, b.in_degree, b.out_degree
}
```

**Note:** Basic blocks do not survive `clearAnalysis()` -- they are extracted during decompilation.

### ListCFGEdges

```cpp
StatusOr<ListCFGEdgesResponse> ListCFGEdges(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Extracts control flow graph edges for functions in the range. Requires prior decompilation.

```cpp
auto edges = client->ListCFGEdges(func.start_address, func.end_address, 0, 0);
for (auto& e : edges.value->edges) {
    // e.function_entry, e.src_block_start, e.dst_block_start, e.edge_kind
}
```

## Memory

### ReadBytes

```cpp
StatusOr<ReadBytesResponse> ReadBytes(uint64_t address, uint32_t length)
```

Reads raw bytes from the program image. After `WriteBytes`, returns patched data from the CoW overlay.

```cpp
auto r = client->ReadBytes(0x140001000, 32);
for (auto b : r.value->data) printf("%02x ", b);
```

### WriteBytes

```cpp
StatusOr<WriteBytesResponse> WriteBytes(uint64_t address, const vector<uint8_t>& data)
```

Writes bytes via a Copy-on-Write overlay. The original binary is never modified; patches are layered on top. Installed lazily on first write.

```cpp
auto w = client->WriteBytes(0x140001000, {0x90, 0x90, 0x90, 0x90});
printf("Wrote %u bytes\n", w.value->bytes_written);
```

**Note:** Writes go through the primary decompiler slot only. Each pool slot would need its own overlay for thread safety.

### PatchBytesBatch

```cpp
StatusOr<PatchBytesBatchResponse> PatchBytesBatch(const vector<BytePatch>& patches)
```

Applies multiple patches atomically.

```cpp
libghidra::client::BytePatch p1{0x1000, {0x90, 0x90}};
libghidra::client::BytePatch p2{0x2000, {0xCC}};
auto r = client->PatchBytesBatch({p1, p2});
printf("Applied %u patches, %u bytes\n", r.value->patch_count, r.value->bytes_written);
```

### ListMemoryBlocks

```cpp
StatusOr<ListMemoryBlocksResponse> ListMemoryBlocks(int limit, int offset)
```

Lists memory blocks (segments) with permissions.

```cpp
auto blocks = client->ListMemoryBlocks(0, 0);
for (auto& b : blocks.value->blocks) {
    printf("%s  0x%llx-0x%llx  %c%c%c\n",
           b.name.c_str(), b.start_address, b.end_address,
           b.is_read ? 'R' : '-', b.is_write ? 'W' : '-', b.is_execute ? 'X' : '-');
}
```

## Symbols

### GetSymbol

```cpp
StatusOr<GetSymbolResponse> GetSymbol(uint64_t address)
```

Gets the primary symbol at an address.

```cpp
auto s = client->GetSymbol(0x140001000);
if (s.ok() && s.value->symbol) {
    // s.value->symbol->name, address, type, namespace_name, source
    // s.value->symbol->is_primary, is_external, is_dynamic, symbol_id
}
```

### ListSymbols

```cpp
StatusOr<ListSymbolsResponse> ListSymbols(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Lists symbols in an address range.

### RenameSymbol

```cpp
StatusOr<RenameSymbolResponse> RenameSymbol(uint64_t address, const string& new_name)
```

Renames the symbol at `address`. For function symbols, delegates to `RenameFunction`.

### DeleteSymbol

```cpp
StatusOr<DeleteSymbolResponse> DeleteSymbol(uint64_t address, const string& name_filter)
```

Deletes symbols at `address` matching `name_filter`.

## Types

### Querying Types

#### GetType

```cpp
StatusOr<GetTypeResponse> GetType(const string& path)
```

Gets a type by name or path (e.g. `"int"`, `"my_struct_t"`).

```cpp
auto t = client->GetType("int");
// t.value->type->name, kind, length, type_id, path_name, display_name
```

#### ListTypes

```cpp
StatusOr<ListTypesResponse> ListTypes(const string& query, int limit, int offset)
```

Lists all types. Pass empty `query` for no filter.

#### ListTypeAliases

```cpp
StatusOr<ListTypeAliasesResponse> ListTypeAliases(const string& query, int limit, int offset)
```

Lists typedef aliases. Each alias has `name`, `target_type`, `declaration`.

#### ListTypeEnums

```cpp
StatusOr<ListTypeEnumsResponse> ListTypeEnums(const string& query, int limit, int offset)
```

Lists enum types. Each has `name`, `width`, `is_signed`, `declaration`.

#### ListTypeUnions

```cpp
StatusOr<ListTypeUnionsResponse> ListTypeUnions(const string& query, int limit, int offset)
```

Lists union types. Each has `name`, `size`, `declaration`.

### Struct Operations

#### CreateType

```cpp
StatusOr<CreateTypeResponse> CreateType(const string& name, const string& kind, uint64_t size)
```

Creates a new type. `kind` is `"struct"` for structs.

```cpp
client->CreateType("packet_t", "struct", 16);
```

#### AddTypeMember

```cpp
StatusOr<AddTypeMemberResponse> AddTypeMember(
    const string& parent_type, const string& member_name,
    const string& member_type, uint64_t size)
```

Appends a field to a struct via read-modify-write internally.

```cpp
client->AddTypeMember("packet_t", "magic", "uint", 4);
client->AddTypeMember("packet_t", "flags", "byte", 1);
```

#### ListTypeMembers

```cpp
StatusOr<ListTypeMembersResponse> ListTypeMembers(
    const string& type_id_or_path, int limit, int offset)
```

Lists struct fields with `ordinal`, `name`, `member_type`, `offset`, `size`, `comment`.

#### RenameTypeMember

```cpp
StatusOr<RenameTypeMemberResponse> RenameTypeMember(
    const string& parent_type, uint64_t ordinal, const string& new_name)
```

Renames a struct field by ordinal (0-based).

#### SetTypeMemberType

```cpp
StatusOr<SetTypeMemberTypeResponse> SetTypeMemberType(
    const string& parent_type, uint64_t ordinal, const string& member_type)
```

Changes a struct field's type by ordinal.

#### SetTypeMemberComment

```cpp
StatusOr<SetTypeMemberCommentResponse> SetTypeMemberComment(
    const string& parent_type, uint64_t ordinal, const string& comment)
```

Sets a comment on a struct field.

#### DeleteTypeMember

```cpp
StatusOr<DeleteTypeMemberResponse> DeleteTypeMember(
    const string& parent_type, uint64_t ordinal)
```

Deletes a struct field by ordinal.

### Enum Operations

#### CreateTypeEnum

```cpp
StatusOr<CreateTypeEnumResponse> CreateTypeEnum(
    const string& name, uint64_t width, bool is_signed)
```

Creates an enum type.

```cpp
client->CreateTypeEnum("error_code_t", 4, false);  // 4-byte unsigned
```

#### AddTypeEnumMember

```cpp
StatusOr<AddTypeEnumMemberResponse> AddTypeEnumMember(
    const string& type, const string& name, int64_t value)
```

Adds a named value to an enum.

#### ListTypeEnumMembers

```cpp
StatusOr<ListTypeEnumMembersResponse> ListTypeEnumMembers(
    const string& type_id_or_path, int limit, int offset)
```

Lists enum values with `ordinal`, `name`, `value`, `comment`.

#### RenameTypeEnumMember

```cpp
StatusOr<RenameTypeEnumMemberResponse> RenameTypeEnumMember(
    const string& type, uint64_t ordinal, const string& new_name)
```

#### SetTypeEnumMemberValue

```cpp
StatusOr<SetTypeEnumMemberValueResponse> SetTypeEnumMemberValue(
    const string& type, uint64_t ordinal, int64_t value)
```

#### SetTypeEnumMemberComment

```cpp
StatusOr<SetTypeEnumMemberCommentResponse> SetTypeEnumMemberComment(
    const string& type, uint64_t ordinal, const string& comment)
```

#### DeleteTypeEnumMember

```cpp
StatusOr<DeleteTypeEnumMemberResponse> DeleteTypeEnumMember(
    const string& type, uint64_t ordinal)
```

#### DeleteTypeEnum

```cpp
StatusOr<DeleteTypeEnumResponse> DeleteTypeEnum(const string& type_id_or_path)
```

### Type Aliases

#### CreateTypeAlias

```cpp
StatusOr<CreateTypeAliasResponse> CreateTypeAlias(
    const string& name, const string& target_type)
```

Creates a typedef alias.

```cpp
client->CreateTypeAlias("DWORD", "uint");
```

#### SetTypeAliasTarget

```cpp
StatusOr<SetTypeAliasTargetResponse> SetTypeAliasTarget(
    const string& type_id_or_path, const string& target_type)
```

Retargets an existing alias.

#### DeleteTypeAlias

```cpp
StatusOr<DeleteTypeAliasResponse> DeleteTypeAlias(const string& type_id_or_path)
```

### Type Lifecycle

#### RenameType

```cpp
StatusOr<RenameTypeResponse> RenameType(
    const string& type_id_or_path, const string& new_name)
```

Renames any type in-place.

#### DeleteType

```cpp
StatusOr<DeleteTypeResponse> DeleteType(const string& type_id_or_path)
```

Deletes a type. Throws on core/built-in types.

## Function Signatures

### GetFunctionSignature

```cpp
StatusOr<GetFunctionSignatureResponse> GetFunctionSignature(uint64_t address)
```

Gets the full signature for a function. Requires prior decompilation.

```cpp
auto sig = client->GetFunctionSignature(addr);
if (sig.ok() && sig.value->signature) {
    auto& s = *sig.value->signature;
    // s.prototype, s.return_type, s.calling_convention, s.has_var_args
    for (auto& p : s.parameters) {
        // p.ordinal, p.name, p.data_type, p.is_auto_parameter
    }
}
```

### ListFunctionSignatures

```cpp
StatusOr<ListFunctionSignaturesResponse> ListFunctionSignatures(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Lists signatures for all functions in range. Requires prior decompilation.

### SetFunctionSignature

```cpp
StatusOr<SetFunctionSignatureResponse> SetFunctionSignature(
    uint64_t address, const string& prototype)
```

Sets a function's prototype string.

```cpp
client->SetFunctionSignature(0x1000, "int process_packet(int flags)");
```

### RenameFunctionParameter

```cpp
StatusOr<RenameFunctionParameterResponse> RenameFunctionParameter(
    uint64_t address, int ordinal, const string& new_name)
```

Renames a parameter by ordinal (0-based).

### SetFunctionParameterType

```cpp
StatusOr<SetFunctionParameterTypeResponse> SetFunctionParameterType(
    uint64_t address, int ordinal, const string& data_type)
```

Changes a parameter's type by ordinal.

### RenameFunctionLocal

```cpp
StatusOr<RenameFunctionLocalResponse> RenameFunctionLocal(
    uint64_t address, const string& local_id, const string& new_name)
```

Renames a local variable by its identifier.

### SetFunctionLocalType

```cpp
StatusOr<SetFunctionLocalTypeResponse> SetFunctionLocalType(
    uint64_t address, const string& local_id, const string& data_type)
```

Changes a local variable's type.

## Listing

### Instructions

#### GetInstruction

```cpp
StatusOr<GetInstructionResponse> GetInstruction(uint64_t address)
```

Gets a single instruction at an address.

```cpp
auto insn = client->GetInstruction(0x140001000);
if (insn.ok() && insn.value->instruction) {
    auto& i = *insn.value->instruction;
    // i.address, i.mnemonic, i.operand_text, i.disassembly, i.length
}
```

#### ListInstructions

```cpp
StatusOr<ListInstructionsResponse> ListInstructions(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Disassembles all instructions in an address range.

### Comments

#### SetComment

```cpp
StatusOr<SetCommentResponse> SetComment(uint64_t address, CommentKind kind, const string& text)
```

Sets a comment. `CommentKind` values: `kEol`, `kPre`, `kPost`, `kPlate`, `kRepeatable`.

#### GetComments

```cpp
StatusOr<GetCommentsResponse> GetComments(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Lists comments in an address range. Each has `address`, `kind`, `text`.

#### DeleteComment

```cpp
StatusOr<DeleteCommentResponse> DeleteComment(uint64_t address, CommentKind kind)
```

Deletes a specific comment at an address.

### Data Items

#### ApplyDataType

```cpp
StatusOr<ApplyDataTypeResponse> ApplyDataType(uint64_t address, const string& data_type)
```

Applies a data type at an address, creating a data item.

```cpp
client->ApplyDataType(0x140004000, "int");
```

#### ListDataItems

```cpp
StatusOr<ListDataItemsResponse> ListDataItems(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Lists defined data items. Each has `address`, `name`, `data_type`, `size`, `value_repr`.

#### RenameDataItem

```cpp
StatusOr<RenameDataItemResponse> RenameDataItem(uint64_t address, const string& new_name)
```

#### DeleteDataItem

```cpp
StatusOr<DeleteDataItemResponse> DeleteDataItem(uint64_t address)
```

### ListDefinedStrings

```cpp
StatusOr<ListDefinedStringsResponse> ListDefinedStrings(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Lists defined string data items. Each has `address`, `value`, `length`, `data_type`, `encoding`.

**Caveat:** The LocalClient does not have a string analysis pass, so this typically returns an empty list unless data items have been explicitly created with string types.

## Cross-References

### ListXrefs

```cpp
StatusOr<ListXrefsResponse> ListXrefs(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Extracts cross-references derived from pcode analysis. Includes both call and data references. Requires decompilation of the source functions (triggers automatically).

```cpp
auto xrefs = client->ListXrefs(0, UINT64_MAX, 0, 0);
for (auto& x : xrefs.value->xrefs) {
    // x.from_address, x.to_address, x.ref_type
    // x.is_flow, x.is_memory, x.is_external
}
```

Uses the decompiler pool for parallel extraction when `pool_size > 1`.

## Unsupported Methods

These methods return `NOT_SUPPORTED` on the LocalClient:

| Method | Reason |
|--------|--------|
| `ListSwitchTables` | Live/structural analysis surface not implemented locally |
| `ListDominators` | Live/structural analysis surface not implemented locally |
| `ListPostDominators` | Live/structural analysis surface not implemented locally |
| `ListLoops` | Live/structural analysis surface not implemented locally |
| `ListFunctionTags` | Ghidra database tag metadata is not modeled locally |
| `CreateFunctionTag` | Ghidra database tag metadata is not modeled locally |
| `DeleteFunctionTag` | Ghidra database tag metadata is not modeled locally |
| `ListFunctionTagMappings` | Ghidra database tag metadata is not modeled locally |
| `TagFunction` | Ghidra database tag metadata is not modeled locally |
| `UntagFunction` | Ghidra database tag metadata is not modeled locally |
| `ParseDeclarations` | Ghidra parser service is not embedded in the local backend |
| `ListBookmarks` | GUI-only concept, no engine backing |
| `AddBookmark` | GUI-only concept, no engine backing |
| `DeleteBookmark` | GUI-only concept, no engine backing |
| `ListBreakpoints` | Debugger concept, no engine backing |
| `AddBreakpoint` | Debugger concept, no engine backing |
| `SetBreakpointEnabled` | Debugger concept, no engine backing |
| `SetBreakpointKind` | Debugger concept, no engine backing |
| `SetBreakpointSize` | Debugger concept, no engine backing |
| `SetBreakpointCondition` | Debugger concept, no engine backing |
| `SetBreakpointGroup` | Debugger concept, no engine backing |
| `DeleteBreakpoint` | Debugger concept, no engine backing |

## Appendix

### Complete Method Table

| Area | Method | Supported |
|--------|--------|-----------|
| **Session** | `OpenProgram` | Yes |
| | `CloseProgram` | Yes |
| | `SaveProgram` | Yes |
| | `DiscardProgram` | Yes |
| | `GetRevision` | Yes |
| | `GetStatus` | Yes |
| | `GetCapabilities` | Yes |
| | `Shutdown` | Yes |
| **Decompiler** | `GetDecompilation` | Yes |
| | `ListDecompilations` | Yes (parallel) |
| **Functions** | `GetFunction` | Yes |
| | `ListFunctions` | Yes |
| | `RenameFunction` | Yes |
| | `ListBasicBlocks` | Yes |
| | `ListCFGEdges` | Yes |
| | `ListSwitchTables` | No |
| | `ListDominators` | No |
| | `ListPostDominators` | No |
| | `ListLoops` | No |
| | `ListFunctionTags` | No |
| | `CreateFunctionTag` | No |
| | `DeleteFunctionTag` | No |
| | `ListFunctionTagMappings` | No |
| | `TagFunction` | No |
| | `UntagFunction` | No |
| **Memory** | `ReadBytes` | Yes |
| | `WriteBytes` | Yes (CoW overlay) |
| | `PatchBytesBatch` | Yes (CoW overlay) |
| | `ListMemoryBlocks` | Yes |
| **Symbols** | `GetSymbol` | Yes |
| | `ListSymbols` | Yes |
| | `RenameSymbol` | Partial (function symbols only) |
| | `DeleteSymbol` | Yes |
| **Types** | `GetType` | Yes |
| | `ListTypes` | Yes |
| | `CreateType` | Partial (struct creation) |
| | `DeleteType` | Yes |
| | `RenameType` | Yes |
| | `ListTypeAliases` | Yes |
| | `CreateTypeAlias` | Yes |
| | `SetTypeAliasTarget` | Yes |
| | `DeleteTypeAlias` | Yes |
| | `ListTypeEnums` | Yes |
| | `CreateTypeEnum` | Yes |
| | `DeleteTypeEnum` | Yes |
| | `ListTypeEnumMembers` | Yes |
| | `AddTypeEnumMember` | Yes |
| | `RenameTypeEnumMember` | Yes |
| | `SetTypeEnumMemberValue` | Yes |
| | `SetTypeEnumMemberComment` | Yes |
| | `ParseDeclarations` | No |
| | `DeleteTypeEnumMember` | Yes |
| | `ListTypeMembers` | Yes |
| | `AddTypeMember` | Yes |
| | `RenameTypeMember` | Yes |
| | `SetTypeMemberType` | Yes |
| | `SetTypeMemberComment` | Yes |
| | `DeleteTypeMember` | Yes |
| | `ListTypeUnions` | Yes |
| **Signatures** | `GetFunctionSignature` | Yes |
| | `ListFunctionSignatures` | Yes |
| | `SetFunctionSignature` | Yes |
| | `RenameFunctionParameter` | Yes |
| | `SetFunctionParameterType` | Yes |
| | `RenameFunctionLocal` | Yes |
| | `SetFunctionLocalType` | Yes |
| | `ApplyDataType` | Yes |
| **Listing** | `GetInstruction` | Yes |
| | `ListInstructions` | Yes |
| | `GetComments` | Yes |
| | `SetComment` | Yes |
| | `DeleteComment` | Yes |
| | `ListDataItems` | Yes |
| | `RenameDataItem` | Yes |
| | `DeleteDataItem` | Yes |
| | `ListDefinedStrings` | Yes |
| **Xrefs** | `ListXrefs` | Yes (parallel) |
| **Bookmarks** | `ListBookmarks` | No |
| | `AddBookmark` | No |
| | `DeleteBookmark` | No |
| **Breakpoints** | `ListBreakpoints` | No |
| | `AddBreakpoint` | No |
| | `SetBreakpointEnabled` | No |
| | `SetBreakpointKind` | No |
| | `SetBreakpointSize` | No |
| | `SetBreakpointCondition` | No |
| | `SetBreakpointGroup` | No |
| | `DeleteBreakpoint` | No |

### Pagination Conventions

All `List*` methods accept `limit` and `offset`:
- `limit = 0` -- return all results (no cap)
- `offset = 0` -- start from the beginning

Range parameters (`range_start`, `range_end`) filter by address:
- `range_start = 0, range_end = UINT64_MAX` -- entire address space
- `range_start = 0, range_end = 0` -- also means "all" for some methods (ListDecompilations)

### Architecture String Format

Sleigh language IDs follow the pattern: `<processor>:<endian>:<size>:<variant>`

Examples:
- `x86:LE:64:default` -- x86-64, little-endian
- `x86:LE:32:default` -- x86-32, little-endian
- `ARM:LE:32:v8` -- ARM 32-bit, little-endian, ARMv8
- `AARCH64:LE:64:v8A` -- AArch64
- `MIPS:BE:32:default` -- MIPS 32-bit, big-endian
- `RISCV:LE:64:default` -- RISC-V 64-bit

When `default_arch` is empty, the backend auto-detects from the binary's format headers (PE, ELF, Mach-O).
