# Python Client API Reference

Comprehensive reference for the `libghidra` Python package — a typed HTTP client for Ghidra program databases via the LibGhidraHost RPC layer.

## Quick Start

```python
import libghidra as ghidra

client = ghidra.connect("http://127.0.0.1:18080")
status = client.get_status()
print(f"{status.service_name} v{status.service_version}")

funcs = client.list_functions(limit=10)
for f in funcs.functions:
    print(f"0x{f.entry_address:x}  {f.name}")

dec = client.get_decompilation(funcs.functions[0].entry_address)
print(dec.decompilation.pseudocode)
```

## Installation

```bash
pip install -e libghidra/python          # sync only
pip install -e "libghidra/python[async]"  # sync + async (adds aiohttp)
```

Requires Python 3.12+ and a running LibGhidraHost instance.

## Factory & Options

### `ghidra.connect(url) -> GhidraClient`

Create a client with default options.

```python
client = ghidra.connect("http://127.0.0.1:18080")
```

### `ClientOptions`

```python
from libghidra import ClientOptions

opts = ClientOptions(
    base_url="http://127.0.0.1:18080",
    auth_token="",              # Bearer token for authenticated hosts
    connect_timeout=3.0,        # seconds
    read_timeout=15.0,          # seconds
    max_retries=0,              # 0 = no retry
    initial_backoff=0.1,        # seconds, doubled each retry
    max_backoff=5.0,            # seconds
    jitter=True,                # randomize backoff
)
client = ghidra.GhidraClient(opts)
```

## Error Handling

All methods raise `GhidraError` on failure.

```python
from libghidra import GhidraError, ErrorCode

try:
    client.get_function(0xdeadbeef)
except GhidraError as e:
    print(e.code)     # ErrorCode.NOT_FOUND
    print(e.message)  # human-readable message
    if e.code.is_retryable():
        # CONNECTION_FAILED, TIMEOUT, TOO_MANY_REQUESTS,
        # INTERNAL_ERROR, BAD_GATEWAY, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT
        ...
```

### ErrorCode values

`CONNECTION_FAILED`, `TIMEOUT`, `TRANSPORT_ERROR`, `BAD_REQUEST`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `TOO_MANY_REQUESTS`, `INTERNAL_ERROR`, `BAD_GATEWAY`, `SERVICE_UNAVAILABLE`, `GATEWAY_TIMEOUT`, `HTTP_ERROR`, `ENCODE_ERROR`, `PARSE_ERROR`, `API_ERROR`, `NOT_SUPPORTED`, `CONFIG_ERROR`, `OTHER`.

---

## Health (2 methods)

### `get_status() -> HealthStatus`

Check host health and program state.

```python
status = client.get_status()
print(f"{status.service_name} v{status.service_version}")
print(f"Mode: {status.host_mode}, revision: {status.program_revision}")
```

**Returns:** `HealthStatus` with fields `ok: bool`, `service_name: str`, `service_version: str`, `host_mode: str`, `program_revision: int`, `warnings: list[str]`.

### `get_capabilities() -> list[Capability]`

List backend capabilities and their support status.

```python
caps = client.get_capabilities()
for c in caps:
    print(f"{c.id}: {c.status}")
```

**Returns:** list of `Capability` with fields `id: str`, `status: str`, `note: str`.

---

## Session (6 methods)

### `open_program(request) -> OpenProgramResponse`

Open a program in the host.

```python
resp = client.open_program(ghidra.OpenRequest(
    project_path="C:/ghidra_projects",
    program_path="binary.exe",
    analyze=True,
))
print(f"Opened: {resp.program_name} (base=0x{resp.image_base:x})")
```

**Parameters:** `request: OpenProgramRequest` with fields `project_path`, `project_name`, `program_path`, `analyze`, `read_only`.

**Returns:** `OpenProgramResponse` with fields `program_name: str`, `language_id: str`, `compiler_spec: str`, `image_base: int`.

### `close_program(policy=ShutdownPolicy.UNSPECIFIED) -> CloseProgramResponse`

Close the current program.

```python
resp = client.close_program(ghidra.ShutdownPolicy.SAVE)
```

**Returns:** `CloseProgramResponse` with `closed: bool`.

### `save_program() -> SaveProgramResponse`

Save the current program to disk.

```python
resp = client.save_program()
assert resp.saved
```

### `discard_program() -> DiscardProgramResponse`

Discard unsaved changes.

```python
resp = client.discard_program()
assert resp.discarded
```

### `get_revision() -> RevisionResponse`

Get the current program revision number. Increments on each mutation.

```python
rev = client.get_revision()
print(f"Revision: {rev.revision}")
```

### `shutdown(policy=ShutdownPolicy.UNSPECIFIED) -> ShutdownResponse`

Shut down the LibGhidraHost process.

```python
resp = client.shutdown(ghidra.ShutdownPolicy.SAVE)
```

**Returns:** `ShutdownResponse` with `accepted: bool`.

---

## Decompiler (2 methods)

### `get_decompilation(address, timeout_ms=0) -> GetDecompilationResponse`

Decompile the function at `address`.

```python
resp = client.get_decompilation(0x140001000, timeout_ms=30000)
if resp.decompilation and resp.decompilation.completed:
    print(resp.decompilation.pseudocode)
```

**Returns:** `GetDecompilationResponse` with `decompilation: DecompilationRecord | None`. Fields: `function_entry_address: int`, `function_name: str`, `prototype: str`, `pseudocode: str`, `completed: bool`, `is_fallback: bool`, `error_message: str`.

### `list_decompilations(range_start=0, range_end=0, limit=0, offset=0, timeout_ms=0) -> ListDecompilationsResponse`

Batch-decompile functions in an address range.

```python
resp = client.list_decompilations(limit=50, timeout_ms=60000)
for d in resp.decompilations:
    print(f"{d.function_name}: {'OK' if d.completed else 'FAIL'}")
```

---

## Functions (5 methods)

### `get_function(address) -> GetFunctionResponse`

Get a function by its entry address.

```python
resp = client.get_function(0x140001000)
if resp.function:
    print(f"{resp.function.name} ({resp.function.size} bytes)")
```

**Returns:** `GetFunctionResponse` with `function: FunctionRecord | None`. Fields: `entry_address: int`, `name: str`, `start_address: int`, `end_address: int`, `size: int`, `namespace_name: str`, `prototype: str`, `is_thunk: bool`, `parameter_count: int`.

### `list_functions(range_start=0, range_end=0, limit=0, offset=0) -> ListFunctionsResponse`

List functions, optionally filtered by address range.

```python
funcs = client.list_functions(limit=20)
for f in funcs.functions:
    print(f"0x{f.entry_address:x}  {f.name}")
```

### `rename_function(address, new_name) -> RenameFunctionResponse`

Rename a function.

```python
resp = client.rename_function(0x140001000, "initialize_app")
print(f"Renamed: {resp.name}")
```

**Returns:** `RenameFunctionResponse` with `renamed: bool`, `name: str`.

### `list_basic_blocks(range_start=0, range_end=0, limit=0, offset=0) -> ListBasicBlocksResponse`

List basic blocks for functions in a range.

```python
blocks = client.list_basic_blocks(
    range_start=func.start_address,
    range_end=func.end_address,
)
for b in blocks.blocks:
    print(f"  0x{b.start_address:x}-0x{b.end_address:x}  in={b.in_degree} out={b.out_degree}")
```

**Returns:** list of `BasicBlockRecord` with fields `function_entry: int`, `start_address: int`, `end_address: int`, `in_degree: int`, `out_degree: int`.

### `list_cfg_edges(range_start=0, range_end=0, limit=0, offset=0) -> ListCFGEdgesResponse`

List control-flow graph edges for functions in a range.

```python
edges = client.list_cfg_edges(
    range_start=func.start_address,
    range_end=func.end_address,
)
for e in edges.edges:
    print(f"  0x{e.src_block_start:x} -> 0x{e.dst_block_start:x}  ({e.edge_kind})")
```

**Returns:** list of `CFGEdgeRecord` with fields `function_entry: int`, `src_block_start: int`, `dst_block_start: int`, `edge_kind: str`.

---

## Memory (4 methods)

### `read_bytes(address, length) -> ReadBytesResponse`

Read raw bytes from program memory.

```python
resp = client.read_bytes(0x140000000, 64)
print(resp.data.hex())
```

**Returns:** `ReadBytesResponse` with `data: bytes`.

### `write_bytes(address, data) -> WriteBytesResponse`

Write bytes to program memory.

```python
resp = client.write_bytes(0x140000000, b"\x90\x90\x90\x90")
print(f"Wrote {resp.bytes_written} bytes")
```

### `patch_bytes_batch(patches) -> PatchBytesBatchResponse`

Apply multiple byte patches atomically.

```python
from libghidra.models import BytePatch

resp = client.patch_bytes_batch([
    BytePatch(address=0x140001000, data=b"\xcc"),
    BytePatch(address=0x140001010, data=b"\x90\x90"),
])
print(f"{resp.patch_count} patches, {resp.bytes_written} bytes")
```

### `list_memory_blocks(limit=0, offset=0) -> ListMemoryBlocksResponse`

List memory blocks (segments) in the program.

```python
blocks = client.list_memory_blocks()
for b in blocks.blocks:
    perms = ("r" if b.is_read else "-") + ("w" if b.is_write else "-") + ("x" if b.is_execute else "-")
    print(f"  {b.name}  0x{b.start_address:x}  {perms}  {b.size} bytes")
```

**Returns:** list of `MemoryBlockRecord` with fields `name: str`, `start_address: int`, `end_address: int`, `size: int`, `is_read: bool`, `is_write: bool`, `is_execute: bool`, `is_volatile: bool`, `is_initialized: bool`, `source_name: str`, `comment: str`.

---

## Symbols (4 methods)

### `get_symbol(address) -> GetSymbolResponse`

Get the primary symbol at an address.

```python
resp = client.get_symbol(0x140001000)
if resp.symbol:
    print(f"{resp.symbol.name} ({resp.symbol.type})")
```

**Returns:** `GetSymbolResponse` with `symbol: SymbolRecord | None`. Fields: `symbol_id: int`, `address: int`, `name: str`, `full_name: str`, `type: str`, `namespace_name: str`, `source: str`, `is_primary: bool`, `is_external: bool`, `is_dynamic: bool`.

### `list_symbols(range_start=0, range_end=0, limit=0, offset=0) -> ListSymbolsResponse`

List symbols, optionally filtered by address range.

```python
syms = client.list_symbols(limit=20)
for s in syms.symbols:
    print(f"0x{s.address:x}  {s.name}  ({s.type})")
```

### `rename_symbol(address, new_name) -> RenameSymbolResponse`

Rename a symbol at the given address.

```python
resp = client.rename_symbol(0x140001000, "my_func")
print(f"Renamed to: {resp.name}")
```

### `delete_symbol(address, name_filter="") -> DeleteSymbolResponse`

Delete symbols at an address. Use `name_filter` to target a specific name.

```python
resp = client.delete_symbol(0x140001000, name_filter="old_label")
print(f"Deleted {resp.deleted_count} symbols")
```

---

## Types (31 methods)

### Query methods (7)

#### `get_type(path) -> GetTypeResponse`

Get a type by path name (e.g. `/int`, `/my_struct_t`).

```python
resp = client.get_type("/int")
if resp.type:
    print(f"{resp.type.name}: {resp.type.kind}, {resp.type.length} bytes")
```

**Returns:** `TypeRecord` with fields `type_id: int`, `name: str`, `path_name: str`, `category_path: str`, `display_name: str`, `kind: str`, `length: int`, `is_not_yet_defined: bool`, `source_archive: str`, `universal_id: str`.

#### `list_types(query="", limit=0, offset=0) -> ListTypesResponse`

List types, optionally filtered by name query.

```python
types = client.list_types(query="struct", limit=10)
```

#### `list_type_aliases(query="", limit=0, offset=0) -> ListTypeAliasesResponse`

List typedef aliases.

```python
aliases = client.list_type_aliases(limit=10)
for a in aliases.aliases:
    print(f"{a.name} -> {a.target_type}")
```

**Returns:** list of `TypeAliasRecord` with fields `type_id: int`, `path_name: str`, `name: str`, `target_type: str`, `declaration: str`.

#### `list_type_unions(query="", limit=0, offset=0) -> ListTypeUnionsResponse`

List union types.

**Returns:** list of `TypeUnionRecord` with fields `type_id: int`, `path_name: str`, `name: str`, `size: int`, `declaration: str`.

#### `list_type_enums(query="", limit=0, offset=0) -> ListTypeEnumsResponse`

List enum types.

**Returns:** list of `TypeEnumRecord` with fields `type_id: int`, `path_name: str`, `name: str`, `width: int`, `is_signed: bool`, `declaration: str`.

#### `list_type_enum_members(type_id_or_path, limit=0, offset=0) -> ListTypeEnumMembersResponse`

List members of an enum type.

```python
members = client.list_type_enum_members("error_code_t")
for m in members.members:
    print(f"  {m.name} = {m.value}")
```

**Returns:** list of `TypeEnumMemberRecord` with fields `type_id: int`, `type_path_name: str`, `type_name: str`, `ordinal: int`, `name: str`, `value: int`.

#### `list_type_members(type_id_or_path, limit=0, offset=0) -> ListTypeMembersResponse`

List fields of a struct type.

```python
members = client.list_type_members("context_t")
for m in members.members:
    print(f"  [{m.ordinal}] {m.member_type} {m.name} @ offset {m.offset}")
```

**Returns:** list of `TypeMemberRecord` with fields `parent_type_id: int`, `parent_type_path_name: str`, `parent_type_name: str`, `ordinal: int`, `name: str`, `member_type: str`, `offset: int`, `size: int`.

### Struct CRUD (5)

#### `create_type(name, kind, size) -> CreateTypeResponse`

Create a new composite type.

```python
client.create_type("my_struct_t", "struct", 32)
```

#### `delete_type(type_id_or_path) -> DeleteTypeResponse`

```python
client.delete_type("my_struct_t")
```

#### `rename_type(type_id_or_path, new_name) -> RenameTypeResponse`

```python
client.rename_type("my_struct_t", "context_t")
```

#### `add_type_member(parent_type_id_or_path, member_name, member_type, size) -> AddTypeMemberResponse`

Append a field to a struct.

```python
client.add_type_member("context_t", "flags", "int", 4)
```

#### `delete_type_member(parent_type_id_or_path, ordinal) -> DeleteTypeMemberResponse`

```python
client.delete_type_member("context_t", 0)
```

### Struct member mutation (2)

#### `rename_type_member(parent_type_id_or_path, ordinal, new_name) -> RenameTypeMemberResponse`

```python
client.rename_type_member("context_t", 0, "state_flags")
```

#### `set_type_member_type(parent_type_id_or_path, ordinal, member_type) -> SetTypeMemberTypeResponse`

```python
client.set_type_member_type("context_t", 0, "uint")
```

### Alias CRUD (3)

#### `create_type_alias(name, target_type) -> CreateTypeAliasResponse`

```python
client.create_type_alias("HANDLE", "void *")
```

#### `delete_type_alias(type_id_or_path) -> DeleteTypeAliasResponse`

```python
client.delete_type_alias("HANDLE")
```

#### `set_type_alias_target(type_id_or_path, target_type) -> SetTypeAliasTargetResponse`

```python
client.set_type_alias_target("HANDLE", "long")
```

### Enum CRUD (6)

#### `create_type_enum(name, width, is_signed=False) -> CreateTypeEnumResponse`

```python
client.create_type_enum("error_code_t", width=4)
```

#### `delete_type_enum(type_id_or_path) -> DeleteTypeEnumResponse`

```python
client.delete_type_enum("error_code_t")
```

#### `add_type_enum_member(type_id_or_path, name, value) -> AddTypeEnumMemberResponse`

```python
client.add_type_enum_member("error_code_t", "ERR_NONE", 0)
```

#### `delete_type_enum_member(type_id_or_path, ordinal) -> DeleteTypeEnumMemberResponse`

```python
client.delete_type_enum_member("error_code_t", 2)
```

#### `rename_type_enum_member(type_id_or_path, ordinal, new_name) -> RenameTypeEnumMemberResponse`

```python
client.rename_type_enum_member("error_code_t", 0, "SUCCESS")
```

#### `set_type_enum_member_value(type_id_or_path, ordinal, value) -> SetTypeEnumMemberValueResponse`

```python
client.set_type_enum_member_value("error_code_t", 1, 0xFF)
```

### Signatures (8)

#### `get_function_signature(address) -> GetFunctionSignatureResponse`

Get the full function signature including parameters.

```python
resp = client.get_function_signature(0x140001000)
if resp.signature:
    sig = resp.signature
    print(f"Prototype: {sig.prototype}")
    print(f"Return: {sig.return_type}, Convention: {sig.calling_convention}")
    for p in sig.parameters:
        print(f"  param[{p.ordinal}]: {p.data_type} {p.name}")
```

**Returns:** `FunctionSignatureRecord` with fields `function_entry_address: int`, `function_name: str`, `prototype: str`, `return_type: str`, `has_var_args: bool`, `calling_convention: str`, `parameters: list[ParameterRecord]`. Each `ParameterRecord` has `ordinal: int`, `name: str`, `data_type: str`, `formal_data_type: str`, `is_auto_parameter: bool`, `is_forced_indirect: bool`.

#### `list_function_signatures(range_start=0, range_end=0, limit=0, offset=0) -> ListFunctionSignaturesResponse`

List signatures for functions in a range.

```python
sigs = client.list_function_signatures(limit=10)
```

#### `set_function_signature(address, prototype) -> SetFunctionSignatureResponse`

Override a function's prototype string.

```python
resp = client.set_function_signature(0x140001000, "int main(int argc, char **argv)")
print(f"Updated: {resp.prototype}")
```

#### `rename_function_parameter(address, ordinal, new_name) -> RenameFunctionParameterResponse`

```python
client.rename_function_parameter(0x140001000, 0, "count")
```

#### `set_function_parameter_type(address, ordinal, data_type) -> SetFunctionParameterTypeResponse`

```python
client.set_function_parameter_type(0x140001000, 0, "size_t")
```

#### `rename_function_local(address, local_id, new_name) -> RenameFunctionLocalResponse`

Rename a local variable in a decompiled function.

```python
client.rename_function_local(0x140001000, "local_10", "buffer")
```

#### `set_function_local_type(address, local_id, data_type) -> SetFunctionLocalTypeResponse`

Change the type of a local variable.

```python
client.set_function_local_type(0x140001000, "local_10", "char *")
```

#### `apply_data_type(address, data_type) -> ApplyDataTypeResponse`

Apply a data type at a memory address.

```python
resp = client.apply_data_type(0x140010000, "dword")
```

---

## Listing (20 methods)

### Instructions (2)

#### `get_instruction(address) -> GetInstructionResponse`

Get the instruction at an address.

```python
resp = client.get_instruction(0x140001000)
if resp.instruction:
    i = resp.instruction
    print(f"0x{i.address:x}  {i.disassembly}  ({i.length} bytes)")
```

**Returns:** `InstructionRecord` with fields `address: int`, `mnemonic: str`, `operand_text: str`, `disassembly: str`, `length: int`.

#### `list_instructions(range_start=0, range_end=0, limit=0, offset=0) -> ListInstructionsResponse`

List instructions in an address range.

```python
instrs = client.list_instructions(
    range_start=func.start_address,
    range_end=func.end_address,
    limit=20,
)
```

### Comments (3)

#### `set_comment(address, kind, text) -> SetCommentResponse`

Set a comment at an address.

```python
client.set_comment(0x140001000, ghidra.CommentKind.EOL, "entry point")
client.set_comment(0x140001000, ghidra.CommentKind.PLATE, "Main function")
```

**CommentKind values:** `EOL` (end of line), `PRE` (before), `POST` (after), `PLATE` (function header), `REPEATABLE`.

#### `get_comments(range_start=0, range_end=0, limit=0, offset=0) -> GetCommentsResponse`

Get comments in an address range.

```python
comments = client.get_comments(
    range_start=0x140001000,
    range_end=0x140002000,
)
for c in comments.comments:
    print(f"0x{c.address:x}  [{c.kind.name}]  {c.text}")
```

#### `delete_comment(address, kind) -> DeleteCommentResponse`

Delete a specific comment kind at an address.

```python
client.delete_comment(0x140001000, ghidra.CommentKind.EOL)
```

### Data Items (3)

#### `list_data_items(range_start=0, range_end=0, limit=0, offset=0) -> ListDataItemsResponse`

List defined data items.

```python
items = client.list_data_items(limit=20)
for d in items.data_items:
    print(f"0x{d.address:x}  {d.name}  {d.data_type}  ({d.size} bytes)")
```

**Returns:** list of `DataItemRecord` with fields `address: int`, `end_address: int`, `name: str`, `data_type: str`, `size: int`, `value_repr: str`.

#### `rename_data_item(address, new_name) -> RenameDataItemResponse`

```python
resp = client.rename_data_item(0x140010000, "g_config")
```

#### `delete_data_item(address) -> DeleteDataItemResponse`

```python
client.delete_data_item(0x140010000)
```

### Bookmarks (3)

#### `list_bookmarks(range_start=0, range_end=0, limit=0, offset=0, type_filter="", category_filter="") -> ListBookmarksResponse`

```python
marks = client.list_bookmarks(limit=10)
for b in marks.bookmarks:
    print(f"0x{b.address:x}  [{b.type}] {b.category}: {b.comment}")
```

**Returns:** list of `BookmarkRecord` with fields `address: int`, `type: str`, `category: str`, `comment: str`.

#### `add_bookmark(address, type, category="", comment="") -> AddBookmarkResponse`

```python
client.add_bookmark(0x140001000, "Note", "Analysis", "Check this function")
```

#### `delete_bookmark(address, type, category="") -> DeleteBookmarkResponse`

```python
client.delete_bookmark(0x140001000, "Note", "Analysis")
```

### Breakpoints (8)

#### `list_breakpoints(range_start=0, range_end=0, limit=0, offset=0, kind_filter="", group_filter="") -> ListBreakpointsResponse`

**Returns:** list of `BreakpointRecord` with fields `address: int`, `enabled: bool`, `kind: str`, `size: int`, `condition: str`, `group: str`.

#### `add_breakpoint(address, kind="SW_EXECUTE", size=1, enabled=True, condition="", group="") -> AddBreakpointResponse`

#### `set_breakpoint_enabled(address, enabled) -> SetBreakpointEnabledResponse`

#### `set_breakpoint_kind(address, kind) -> SetBreakpointKindResponse`

#### `set_breakpoint_size(address, size) -> SetBreakpointSizeResponse`

#### `set_breakpoint_condition(address, condition) -> SetBreakpointConditionResponse`

#### `set_breakpoint_group(address, group) -> SetBreakpointGroupResponse`

#### `delete_breakpoint(address) -> DeleteBreakpointResponse`

### Strings (1)

#### `list_defined_strings(range_start=0, range_end=0, limit=0, offset=0) -> ListDefinedStringsResponse`

List defined string data in the program.

```python
strings = client.list_defined_strings(limit=20)
for s in strings.strings:
    print(f"0x{s.address:x}  {s.value!r}  ({s.data_type})")
```

**Returns:** list of `DefinedStringRecord` with fields `address: int`, `value: str`, `length: int`, `data_type: str`, `encoding: str`.

---

## Cross-References (1 method)

### `list_xrefs(range_start=0, range_end=0, limit=0, offset=0) -> ListXrefsResponse`

List cross-references (calls, data refs) in a range.

```python
xrefs = client.list_xrefs(limit=20)
for x in xrefs.xrefs:
    print(f"0x{x.from_address:x} -> 0x{x.to_address:x}  {x.ref_type}")
```

**Returns:** list of `XrefRecord` with fields `from_address: int`, `to_address: int`, `operand_index: int`, `ref_type: str`, `is_primary: bool`, `source: str`, `symbol_id: int`, `is_external: bool`, `is_memory: bool`, `is_flow: bool`.

---

## Async Client

The `AsyncGhidraClient` mirrors the sync API surface with async counterparts. Requires `aiohttp` (`pip install -e ".[async]"`).

```python
import asyncio
from libghidra.async_client import AsyncGhidraClient
from libghidra import ConnectOptions

async def main():
    async with AsyncGhidraClient(ConnectOptions()) as client:
        status = await client.get_status()
        print(f"{status.service_name} v{status.service_version}")

        funcs = await client.list_functions(limit=5)
        for f in funcs.functions:
            print(f"  0x{f.entry_address:x}  {f.name}")

        if funcs.functions:
            dec = await client.get_decompilation(funcs.functions[0].entry_address)
            if dec.decompilation:
                print(dec.decompilation.pseudocode)

asyncio.run(main())
```

The async client supports context manager (`async with`) for automatic cleanup. You can also create it directly and call `await client.close()` when done.

Every method has the same name and signature as the sync client, but returns an awaitable.

---

## Appendix

### Type aliases

The package exports short aliases for common record types:

| Alias | Full Type |
|-------|-----------|
| `Function` | `FunctionRecord` |
| `Symbol` | `SymbolRecord` |
| `Decompilation` | `DecompilationRecord` |
| `Instruction` | `InstructionRecord` |
| `Xref` | `XrefRecord` |
| `Type` | `TypeRecord` |
| `Comment` | `CommentRecord` |
| `MemoryBlock` | `MemoryBlockRecord` |
| `BasicBlock` | `BasicBlockRecord` |
| `CFGEdge` | `CFGEdgeRecord` |
| `DataItem` | `DataItemRecord` |
| `Bookmark` | `BookmarkRecord` |
| `Breakpoint` | `BreakpointRecord` |
| `Parameter` | `ParameterRecord` |
| `Signature` | `FunctionSignatureRecord` |
| `DefinedString` | `DefinedStringRecord` |
| `TypeMember` | `TypeMemberRecord` |
| `TypeEnum` | `TypeEnumRecord` |
| `TypeEnumMember` | `TypeEnumMemberRecord` |
| `TypeAlias` | `TypeAliasRecord` |
| `TypeUnion` | `TypeUnionRecord` |
| `OpenRequest` | `OpenProgramRequest` |

### Pagination

List methods accept `limit` and `offset` parameters for pagination. When `limit=0`, the server returns all items (server-side default). Typical usage:

```python
# First page
page1 = client.list_functions(limit=100, offset=0)

# Next page
page2 = client.list_functions(limit=100, offset=100)
```

### ShutdownPolicy

| Value | Effect |
|-------|--------|
| `UNSPECIFIED` | Server decides |
| `SAVE` | Save before closing |
| `DISCARD` | Discard unsaved changes |
| `NONE` | Close without saving |
