# Rust Client API Reference

Comprehensive reference for the `libghidra-client` Rust crate -- a synchronous HTTP client for Ghidra program databases via the LibGhidraHost RPC layer.

Comprehensive method coverage across 9 service areas, plus auto-pagination helpers.

## Quick Start

```rust
use libghidra as ghidra;

fn main() -> Result<(), ghidra::Error> {
    let client = ghidra::connect("http://127.0.0.1:18080");

    let status = client.get_status()?;
    println!("{} v{}", status.service_name, status.service_version);

    let funcs = client.list_functions(0, u64::MAX, 10, 0)?;
    for f in &funcs.functions {
        println!("0x{:x}  {}", f.entry_address, f.name);
    }

    if let Some(f) = funcs.functions.first() {
        let dec = client.get_decompilation(f.entry_address, 30000)?;
        if let Some(d) = &dec.decompilation {
            println!("{}", d.pseudocode);
        }
    }
    Ok(())
}
```

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
libghidra-client = { path = "../libghidra/rust" }
```

Requires a running LibGhidraHost instance.

## Factory & Options

### `ghidra::connect(url) -> GhidraClient`

Create a client with default options.

```rust
let client = ghidra::connect("http://127.0.0.1:18080");
```

### `ClientOptions`

```rust
use libghidra::{ClientOptions, GhidraClient};
use std::time::Duration;

let client = GhidraClient::new(ClientOptions {
    base_url: "http://127.0.0.1:18080".into(),
    auth_token: String::new(),
    connect_timeout: Duration::from_secs(3),
    read_timeout: Duration::from_secs(15),
    max_retries: 0,
    initial_backoff: Duration::from_millis(100),
    max_backoff: Duration::from_secs(5),
    jitter: true,
});
```

## Error Handling

All methods return `Result<T, ghidra::Error>`.

```rust
use libghidra::{Error, ErrorCode};

match client.get_function(0xdeadbeef) {
    Ok(resp) => { /* ... */ }
    Err(e) => {
        eprintln!("Code: {:?}, Message: {}", e.code, e);
        if e.code.is_retryable() {
            // retry logic
        }
    }
}
```

### ErrorCode variants

`ConnectionFailed`, `Timeout`, `TransportError`, `BadRequest`, `Unauthorized`, `Forbidden`, `NotFound`, `Conflict`, `TooManyRequests`, `InternalError`, `BadGateway`, `ServiceUnavailable`, `GatewayTimeout`, `HttpError`, `EncodeError`, `ParseError`, `ApiError`, `NotSupported`, `ConfigError`, `Other`.

---

## Health (2 methods)

### `fn get_status(&self) -> Result<HealthStatus>`

Check host health and program state.

```rust
let status = client.get_status()?;
println!("{} v{} (mode: {})", status.service_name, status.service_version, status.host_mode);
```

**Returns:** `HealthStatus { ok, service_name, service_version, host_mode, program_revision, warnings }`.

### `fn get_capabilities(&self) -> Result<Vec<Capability>>`

List backend capabilities.

```rust
let caps = client.get_capabilities()?;
for c in &caps {
    println!("{}: {}", c.id, c.status);
}
```

---

## Session (6 methods)

### `fn open_program(&self, request: &OpenProgramRequest) -> Result<OpenProgramResponse>`

```rust
let req = ghidra::OpenRequest {
    project_path: "/path/to/project".into(),
    program_path: "binary.exe".into(),
    analyze: true,
    ..Default::default()
};
let resp = client.open_program(&req)?;
println!("Opened: {} (base=0x{:x})", resp.program_name, resp.image_base);
```

**Returns:** `OpenProgramResponse { program_name, language_id, compiler_spec, image_base }`.

### `fn close_program(&self, policy: ShutdownPolicy) -> Result<CloseProgramResponse>`

```rust
client.close_program(ghidra::ShutdownPolicy::Save)?;
```

### `fn save_program(&self) -> Result<SaveProgramResponse>`

```rust
let resp = client.save_program()?;
assert!(resp.saved);
```

### `fn discard_program(&self) -> Result<DiscardProgramResponse>`

```rust
client.discard_program()?;
```

### `fn get_revision(&self) -> Result<RevisionResponse>`

```rust
let rev = client.get_revision()?;
println!("Revision: {}", rev.revision);
```

### `fn shutdown(&self, policy: ShutdownPolicy) -> Result<ShutdownResponse>`

```rust
client.shutdown(ghidra::ShutdownPolicy::Save)?;
```

---

## Decompiler (2 methods)

### `fn get_decompilation(&self, address: u64, timeout_ms: u32) -> Result<GetDecompilationResponse>`

```rust
let resp = client.get_decompilation(0x140001000, 30000)?;
if let Some(d) = &resp.decompilation {
    if d.completed {
        println!("{}", d.pseudocode);
    }
}
```

**Returns:** `GetDecompilationResponse { decompilation: Option<DecompilationRecord> }`. Record fields: `function_entry_address`, `function_name`, `prototype`, `pseudocode`, `completed`, `is_fallback`, `error_message`.

### `fn list_decompilations(&self, range_start: u64, range_end: u64, limit: i32, offset: i32, timeout_ms: u32) -> Result<ListDecompilationsResponse>`

```rust
let resp = client.list_decompilations(0, u64::MAX, 50, 0, 60000)?;
```

---

## Functions (5 methods)

### `fn get_function(&self, address: u64) -> Result<GetFunctionResponse>`

```rust
let resp = client.get_function(0x140001000)?;
if let Some(f) = &resp.function {
    println!("{} ({} bytes)", f.name, f.size);
}
```

**Returns:** `FunctionRecord { entry_address, name, start_address, end_address, size, namespace_name, prototype, is_thunk, parameter_count }`.

### `fn list_functions(&self, range_start: u64, range_end: u64, limit: i32, offset: i32) -> Result<ListFunctionsResponse>`

```rust
let funcs = client.list_functions(0, u64::MAX, 20, 0)?;
```

### `fn rename_function(&self, address: u64, new_name: &str) -> Result<RenameFunctionResponse>`

```rust
let resp = client.rename_function(0x140001000, "init_app")?;
println!("Renamed: {}", resp.name);
```

### `fn list_basic_blocks(&self, range_start: u64, range_end: u64, limit: i32, offset: i32) -> Result<ListBasicBlocksResponse>`

```rust
let blocks = client.list_basic_blocks(func.start_address, func.end_address, 100, 0)?;
for b in &blocks.blocks {
    println!("  0x{:x}-0x{:x}  in={} out={}", b.start_address, b.end_address, b.in_degree, b.out_degree);
}
```

**Returns:** `BasicBlockRecord { function_entry, start_address, end_address, in_degree, out_degree }`.

### `fn list_cfg_edges(&self, range_start: u64, range_end: u64, limit: i32, offset: i32) -> Result<ListCFGEdgesResponse>`

```rust
let edges = client.list_cfg_edges(func.start_address, func.end_address, 100, 0)?;
for e in &edges.edges {
    println!("  0x{:x} -> 0x{:x}  ({})", e.src_block_start, e.dst_block_start, e.edge_kind);
}
```

**Returns:** `CFGEdgeRecord { function_entry, src_block_start, dst_block_start, edge_kind }`.

---

## Memory (4 methods)

### `fn read_bytes(&self, address: u64, length: u32) -> Result<ReadBytesResponse>`

```rust
let resp = client.read_bytes(0x140000000, 64)?;
for (i, byte) in resp.data.iter().enumerate() {
    print!("{:02x} ", byte);
    if (i + 1) % 16 == 0 { println!(); }
}
```

### `fn write_bytes(&self, address: u64, data: &[u8]) -> Result<WriteBytesResponse>`

```rust
client.write_bytes(0x140000000, &[0x90, 0x90, 0x90, 0x90])?;
```

### `fn patch_bytes_batch(&self, patches: &[BytePatch]) -> Result<PatchBytesBatchResponse>`

```rust
let patches = vec![
    ghidra::BytePatch { address: 0x140001000, data: vec![0xcc] },
    ghidra::BytePatch { address: 0x140001010, data: vec![0x90, 0x90] },
];
let resp = client.patch_bytes_batch(&patches)?;
println!("{} patches, {} bytes", resp.patch_count, resp.bytes_written);
```

### `fn list_memory_blocks(&self, limit: i32, offset: i32) -> Result<ListMemoryBlocksResponse>`

```rust
let blocks = client.list_memory_blocks(100, 0)?;
for b in &blocks.blocks {
    let perms = format!("{}{}{}",
        if b.is_read { "r" } else { "-" },
        if b.is_write { "w" } else { "-" },
        if b.is_execute { "x" } else { "-" },
    );
    println!("  {}  0x{:x}  {}  {} bytes", b.name, b.start_address, perms, b.size);
}
```

**Returns:** `MemoryBlockRecord { name, start_address, end_address, size, is_read, is_write, is_execute, is_volatile, is_initialized, source_name, comment }`.

---

## Symbols (4 methods)

### `fn get_symbol(&self, address: u64) -> Result<GetSymbolResponse>`

```rust
let resp = client.get_symbol(0x140001000)?;
if let Some(s) = &resp.symbol {
    println!("{} ({})", s.name, s.r#type);
}
```

**Returns:** `SymbolRecord { symbol_id, address, name, full_name, r#type, namespace_name, source, is_primary, is_external, is_dynamic }`.

### `fn list_symbols(&self, range_start: u64, range_end: u64, limit: i32, offset: i32) -> Result<ListSymbolsResponse>`

```rust
let syms = client.list_symbols(0, u64::MAX, 20, 0)?;
```

### `fn rename_symbol(&self, address: u64, new_name: &str) -> Result<RenameSymbolResponse>`

```rust
client.rename_symbol(0x140001000, "my_func")?;
```

### `fn delete_symbol(&self, address: u64, name_filter: &str) -> Result<DeleteSymbolResponse>`

```rust
client.delete_symbol(0x140001000, "old_label")?;
```

---

## Types (31 methods)

### Query methods (7)

#### `fn get_type(&self, path: &str) -> Result<GetTypeResponse>`

```rust
let resp = client.get_type("/int")?;
if let Some(t) = &resp.r#type {
    println!("{}: {} ({} bytes)", t.name, t.kind, t.length);
}
```

**Returns:** `TypeRecord { type_id, name, path_name, category_path, display_name, kind, length, is_not_yet_defined, source_archive, universal_id }`.

#### `fn list_types(&self, query: &str, limit: i32, offset: i32) -> Result<ListTypesResponse>`

#### `fn list_type_aliases(&self, query: &str, limit: i32, offset: i32) -> Result<ListTypeAliasesResponse>`

**Returns:** `TypeAliasRecord { type_id, path_name, name, target_type, declaration }`.

#### `fn list_type_unions(&self, query: &str, limit: i32, offset: i32) -> Result<ListTypeUnionsResponse>`

**Returns:** `TypeUnionRecord { type_id, path_name, name, size, declaration }`.

#### `fn list_type_enums(&self, query: &str, limit: i32, offset: i32) -> Result<ListTypeEnumsResponse>`

**Returns:** `TypeEnumRecord { type_id, path_name, name, width, is_signed, declaration }`.

#### `fn list_type_enum_members(&self, type_id_or_path: &str, limit: i32, offset: i32) -> Result<ListTypeEnumMembersResponse>`

**Returns:** `TypeEnumMemberRecord { type_id, type_path_name, type_name, ordinal, name, value }`.

#### `fn list_type_members(&self, type_id_or_path: &str, limit: i32, offset: i32) -> Result<ListTypeMembersResponse>`

**Returns:** `TypeMemberRecord { parent_type_id, parent_type_path_name, parent_type_name, ordinal, name, member_type, offset, size }`.

### Struct CRUD (5)

#### `fn create_type(&self, name: &str, kind: &str, size: u64) -> Result<CreateTypeResponse>`

```rust
client.create_type("my_struct", "struct", 32)?;
```

#### `fn delete_type(&self, type_id_or_path: &str) -> Result<DeleteTypeResponse>`

#### `fn rename_type(&self, type_id_or_path: &str, new_name: &str) -> Result<RenameTypeResponse>`

#### `fn add_type_member(&self, parent: &str, name: &str, member_type: &str, size: u64) -> Result<AddTypeMemberResponse>`

```rust
client.add_type_member("my_struct", "flags", "int", 4)?;
```

#### `fn delete_type_member(&self, parent: &str, ordinal: u64) -> Result<DeleteTypeMemberResponse>`

### Struct member mutation (2)

#### `fn rename_type_member(&self, parent: &str, ordinal: u64, new_name: &str) -> Result<RenameTypeMemberResponse>`

#### `fn set_type_member_type(&self, parent: &str, ordinal: u64, member_type: &str) -> Result<SetTypeMemberTypeResponse>`

### Alias CRUD (3)

#### `fn create_type_alias(&self, name: &str, target_type: &str) -> Result<CreateTypeAliasResponse>`

```rust
client.create_type_alias("HANDLE", "void *")?;
```

#### `fn delete_type_alias(&self, type_id_or_path: &str) -> Result<DeleteTypeAliasResponse>`

#### `fn set_type_alias_target(&self, type_id_or_path: &str, target_type: &str) -> Result<SetTypeAliasTargetResponse>`

### Enum CRUD (6)

#### `fn create_type_enum(&self, name: &str, width: u64, is_signed: bool) -> Result<CreateTypeEnumResponse>`

```rust
client.create_type_enum("error_code", 4, false)?;
```

#### `fn delete_type_enum(&self, type_id_or_path: &str) -> Result<DeleteTypeEnumResponse>`

#### `fn add_type_enum_member(&self, type_id_or_path: &str, name: &str, value: i64) -> Result<AddTypeEnumMemberResponse>`

#### `fn delete_type_enum_member(&self, type_id_or_path: &str, ordinal: u64) -> Result<DeleteTypeEnumMemberResponse>`

#### `fn rename_type_enum_member(&self, type_id_or_path: &str, ordinal: u64, new_name: &str) -> Result<RenameTypeEnumMemberResponse>`

#### `fn set_type_enum_member_value(&self, type_id_or_path: &str, ordinal: u64, value: i64) -> Result<SetTypeEnumMemberValueResponse>`

### Signatures (8)

#### `fn get_function_signature(&self, address: u64) -> Result<GetFunctionSignatureResponse>`

```rust
let resp = client.get_function_signature(0x140001000)?;
if let Some(sig) = &resp.signature {
    println!("Prototype: {}", sig.prototype);
    println!("Return: {}, Convention: {}", sig.return_type, sig.calling_convention);
    for p in &sig.parameters {
        println!("  param[{}]: {} {}", p.ordinal, p.data_type, p.name);
    }
}
```

**Returns:** `FunctionSignatureRecord { function_entry_address, function_name, prototype, return_type, has_var_args, calling_convention, parameters }`. Each `ParameterRecord { ordinal, name, data_type, formal_data_type, is_auto_parameter, is_forced_indirect }`.

#### `fn list_function_signatures(&self, range_start: u64, range_end: u64, limit: i32, offset: i32) -> Result<ListFunctionSignaturesResponse>`

#### `fn set_function_signature(&self, address: u64, prototype: &str, calling_convention: &str) -> Result<SetFunctionSignatureResponse>`

```rust
client.set_function_signature(0x140001000, "int main(int argc, char **argv)", "")?;
```

#### `fn rename_function_parameter(&self, address: u64, ordinal: i32, new_name: &str) -> Result<RenameFunctionParameterResponse>`

#### `fn set_function_parameter_type(&self, address: u64, ordinal: i32, data_type: &str) -> Result<SetFunctionParameterTypeResponse>`

#### `fn rename_function_local(&self, address: u64, local_id: &str, new_name: &str) -> Result<RenameFunctionLocalResponse>`

#### `fn set_function_local_type(&self, address: u64, local_id: &str, data_type: &str) -> Result<SetFunctionLocalTypeResponse>`

#### `fn apply_data_type(&self, address: u64, data_type: &str) -> Result<ApplyDataTypeResponse>`

```rust
client.apply_data_type(0x140010000, "dword")?;
```

---

## Listing (20 methods)

### Instructions (2)

#### `fn get_instruction(&self, address: u64) -> Result<GetInstructionResponse>`

```rust
let resp = client.get_instruction(0x140001000)?;
if let Some(i) = &resp.instruction {
    println!("0x{:x}  {}  ({} bytes)", i.address, i.disassembly, i.length);
}
```

**Returns:** `InstructionRecord { address, mnemonic, operand_text, disassembly, length }`.

#### `fn list_instructions(&self, range_start: u64, range_end: u64, limit: i32, offset: i32) -> Result<ListInstructionsResponse>`

### Comments (3)

#### `fn set_comment(&self, address: u64, kind: CommentKind, text: &str) -> Result<SetCommentResponse>`

```rust
client.set_comment(0x140001000, ghidra::CommentKind::Eol, "entry point")?;
```

**CommentKind variants:** `Eol`, `Pre`, `Post`, `Plate`, `Repeatable`.

#### `fn get_comments(&self, range_start: u64, range_end: u64, limit: i32, offset: i32) -> Result<GetCommentsResponse>`

**Returns:** `CommentRecord { address, kind, text }`.

#### `fn delete_comment(&self, address: u64, kind: CommentKind) -> Result<DeleteCommentResponse>`

### Data Items (3)

#### `fn list_data_items(&self, range_start: u64, range_end: u64, limit: i32, offset: i32) -> Result<ListDataItemsResponse>`

**Returns:** `DataItemRecord { address, end_address, name, data_type, size, value_repr }`.

#### `fn rename_data_item(&self, address: u64, new_name: &str) -> Result<RenameDataItemResponse>`

#### `fn delete_data_item(&self, address: u64) -> Result<DeleteDataItemResponse>`

### Bookmarks (3)

#### `fn list_bookmarks(&self, range_start: u64, range_end: u64, limit: i32, offset: i32, type_filter: &str, category_filter: &str) -> Result<ListBookmarksResponse>`

**Returns:** `BookmarkRecord { address, r#type, category, comment }`.

#### `fn add_bookmark(&self, address: u64, r#type: &str, category: &str, comment: &str) -> Result<AddBookmarkResponse>`

#### `fn delete_bookmark(&self, address: u64, r#type: &str, category: &str) -> Result<DeleteBookmarkResponse>`

### Breakpoints (8)

#### `fn list_breakpoints(&self, range_start: u64, range_end: u64, limit: i32, offset: i32, kind_filter: &str, group_filter: &str) -> Result<ListBreakpointsResponse>`

**Returns:** `BreakpointRecord { address, enabled, kind, size, condition, group }`.

#### `fn add_breakpoint(&self, address: u64, kind: &str, size: u64, enabled: bool, condition: &str, group: &str) -> Result<AddBreakpointResponse>`

#### `fn set_breakpoint_enabled(&self, address: u64, enabled: bool) -> Result<SetBreakpointEnabledResponse>`

#### `fn set_breakpoint_kind(&self, address: u64, kind: &str) -> Result<SetBreakpointKindResponse>`

#### `fn set_breakpoint_size(&self, address: u64, size: u64) -> Result<SetBreakpointSizeResponse>`

#### `fn set_breakpoint_condition(&self, address: u64, condition: &str) -> Result<SetBreakpointConditionResponse>`

#### `fn set_breakpoint_group(&self, address: u64, group: &str) -> Result<SetBreakpointGroupResponse>`

#### `fn delete_breakpoint(&self, address: u64) -> Result<DeleteBreakpointResponse>`

### Strings (1)

#### `fn list_defined_strings(&self, range_start: u64, range_end: u64, limit: i32, offset: i32) -> Result<ListDefinedStringsResponse>`

**Returns:** `DefinedStringRecord { address, value, length, data_type, encoding }`.

---

## Cross-References (1 method)

### `fn list_xrefs(&self, range_start: u64, range_end: u64, limit: i32, offset: i32) -> Result<ListXrefsResponse>`

```rust
let xrefs = client.list_xrefs(0, u64::MAX, 20, 0)?;
for x in &xrefs.xrefs {
    println!("0x{:x} -> 0x{:x}  {}", x.from_address, x.to_address, x.ref_type);
}
```

**Returns:** `XrefRecord { from_address, to_address, operand_index, ref_type, is_primary, source, symbol_id, is_external, is_memory, is_flow }`.

---

## Pagination

The `paginate` module provides helpers for auto-fetching all pages from paginated list RPCs.

### `fetch_all(fetch_fn) -> Result<Vec<T>>`

Convenience function that drains all pages into a single `Vec`.

```rust
use ghidra::paginate::fetch_all;

let all_funcs = fetch_all(|limit, offset| {
    let resp = client.list_functions(0, u64::MAX, limit, offset)?;
    Ok(resp.functions)
})?;
println!("Total functions: {}", all_funcs.len());
```

### `Paginator<T, F>`

Lazy iterator that fetches pages on demand. Implements `Iterator<Item = Result<Vec<T>>>`.

```rust
use ghidra::paginate::Paginator;

// Default page size (100)
let pages: Result<Vec<Vec<_>>, _> = Paginator::new(|limit, offset| {
    let resp = client.list_symbols(0, u64::MAX, limit, offset)?;
    Ok(resp.symbols)
}).collect();

// Custom page size
let pages = Paginator::new(|limit, offset| {
    let resp = client.list_types("", limit, offset)?;
    Ok(resp.types)
}).page_size(25);

for page in pages {
    let items = page?;
    println!("Got {} types", items.len());
}
```

The closure receives `(limit: i32, offset: i32)` and should return `Result<Vec<T>>` from the list response. Iteration stops when a page returns fewer items than the page size.

---

## Appendix

### Type aliases

The crate exports short aliases for common types:

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
| `Client` | `GhidraClient` |
| `ConnectOptions` | `ClientOptions` |

### ShutdownPolicy

| Variant | Effect |
|---------|--------|
| `Unspecified` | Server decides |
| `Save` | Save before closing |
| `Discard` | Discard unsaved changes |
| `None` | Close without saving |
