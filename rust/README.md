# libghidra Rust Client

Synchronous Rust client for the libghidra typed RPC layer. Uses `ureq` for HTTP transport and `prost` for protobuf serialization — no async runtime required.

## Features

- Broad synchronous API coverage across the host service areas
- Synchronous HTTP transport via `POST /rpc` with binary protobuf envelopes
- Automatic retry with exponential backoff and jitter
- Typed model structs (not raw prost types) for all request/response types
- Session management (open/close/save/discard/shutdown)

## Quick Start

```rust
use libghidra as ghidra;

let client = ghidra::connect("http://127.0.0.1:18080");

let status = client.get_status()?;
println!("{} v{}", status.service_name, status.service_version);

let funcs = client.list_functions(0, u64::MAX, 10, 0)?;
for f in &funcs.functions {
    println!("0x{:x}  {}", f.entry_address, f.name);
}
```

## Selected Examples

See [`examples/`](examples/) for the full set of Rust examples.

| Example | Coverage |
|---------|----------|
| [`quickstart.rs`](examples/quickstart.rs) | Connect, list functions, decompile one |
| [`memory_ops.rs`](examples/memory_ops.rs) | Memory blocks, read/write/patch bytes |
| [`disassemble.rs`](examples/disassemble.rs) | Instructions and disassembly listing |
| [`comments.rs`](examples/comments.rs) | Comment CRUD (Eol, Pre, Post, Plate, Repeatable) |
| [`data_items.rs`](examples/data_items.rs) | Apply data types, rename/delete data items |
| [`symbols.rs`](examples/symbols.rs) | Symbol query, rename, delete |
| [`type_system.rs`](examples/type_system.rs) | Type overview: structs, aliases, enums, unions |
| [`struct_builder.rs`](examples/struct_builder.rs) | Struct member add/rename/retype/delete |
| [`enum_builder.rs`](examples/enum_builder.rs) | Enum member add/rename/revalue/delete |
| [`function_signatures.rs`](examples/function_signatures.rs) | Signatures, parameter mutation, prototype override |
| [`cfg_analysis.rs`](examples/cfg_analysis.rs) | Basic blocks and CFG edges |
| [`decompile_tokens.rs`](examples/decompile_tokens.rs) | Pseudocode token records and local metadata |
| [`end_to_end.rs`](examples/end_to_end.rs) | Launch headless Ghidra, analyze, enumerate functions/blocks/decompilation, save, shutdown |
| [`function_tags.rs`](examples/function_tags.rs) | Function tag CRUD and mappings |
| [`parse_declarations.rs`](examples/parse_declarations.rs) | Parse C declarations into data types |
| [`session_lifecycle.rs`](examples/session_lifecycle.rs) | Status, capabilities, revision, save/discard |
| [`structural_analysis.rs`](examples/structural_analysis.rs) | Switch tables, dominators, post-dominators, and loops |
| [`pagination.rs`](examples/pagination.rs) | `fetch_all` and `Paginator` with custom page size |

For the full method-by-method reference, see the [API Reference](docs/api_reference.md).

## Pagination

The `paginate` module provides auto-pagination helpers:

```rust
use ghidra::paginate::fetch_all;

let all_funcs = fetch_all(|limit, offset| {
    let resp = client.list_functions(0, u64::MAX, limit, offset)?;
    Ok(resp.functions)
})?;
```

See [`examples/pagination.rs`](examples/pagination.rs) for `Paginator` with custom page sizes.

## API Surface

| Area | Methods |
|------|---------|
| Health | `get_status`, `get_capabilities` |
| Session | `open_program`, `close_program`, `save_program`, `discard_program`, `get_revision`, `shutdown` |
| Memory | `read_bytes`, `write_bytes`, `patch_bytes_batch`, `list_memory_blocks` |
| Functions | Functions, CFG, structural analysis, and function tags |
| Symbols | `get_symbol`, `list_symbols`, `rename_symbol`, `delete_symbol` |
| Xrefs | `list_xrefs` |
| Types | Type queries and mutations, function signatures, locals/parameters, data type application, and declaration parsing |
| Decompiler | `get_decompilation`, `list_decompilations` |
| Listing | 20 methods for instructions, comments, data items, bookmarks, breakpoints, strings |

## Architecture

```
ghidra::connect(url) -> Client (GhidraClient, sync, ureq)
    |
    +-- call_rpc<Req, Resp>(method, request) -> Result<Resp>
    |       |-- serialize RpcRequest envelope (prost)
    |       |-- POST /rpc with retry loop
    |       |-- deserialize RpcResponse, unpack Any payload
    |
    +-- models (clean Rust structs, not prost types)
    +-- convert (From<proto> for models)
    +-- error (ErrorCode enum with semantic codes)
```

## Protobuf Codegen

Protobuf stubs are auto-regenerated at build time via `build.rs` using prost-build. Set the `PROTOC` env var to point to a protoc binary to enable auto-regeneration. If protoc is not available, the build falls back to the pre-generated stubs in `generated/libghidra.rs`.

The C++ SDK in [`cpp/`](../cpp/) and the [proto contracts](../proto/) are the reference implementations.
