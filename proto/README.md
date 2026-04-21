# libghidra Proto Contracts

This directory is the source of truth for all external API contracts. The current
contracts define 88 typed domain RPCs across 9 service areas, plus one generic
transport RPC.

## Service Catalog

| Proto file | Service | RPCs | Description |
|-----------|---------|------|-------------|
| `health.proto` | HealthService | 2 | `GetStatus`, `GetCapabilities` |
| `session.proto` | SessionService | 6 | Shared active-program control: `OpenProgram`, `CloseProgram`, `SaveProgram`, `DiscardProgram`, `GetRevision`, `Shutdown` |
| `memory.proto` | MemoryService | 4 | `ReadBytes`, `WriteBytes`, `PatchBytesBatch`, `ListMemoryBlocks` |
| `functions.proto` | FunctionsService | 15 | Functions, CFG, structural analysis, and function tags |
| `symbols.proto` | SymbolsService | 4 | `GetSymbol`, `ListSymbols`, `RenameSymbol`, `DeleteSymbol` |
| `xrefs.proto` | XrefsService | 1 | `ListXrefs` |
| `types.proto` | TypesService | 34 | Types, aliases, enums, members, function signatures, parameters, locals, data type application, declaration parsing |
| `decompiler.proto` | DecompilerService | 2 | `DecompileFunction`, `ListDecompilations` |
| `listing.proto` | ListingService | 20 | Instructions, comments, data items, bookmarks, breakpoints, defined strings |
| `common.proto` | — | 0 | Shared types: `ErrorDetail`, `Pagination`, `AddressRange`, `ShutdownPolicy` |
| `rpc.proto` | RpcService | 1 | Generic `Call` — `RpcRequest`/`RpcResponse` envelope |

**Total: 88 domain service RPCs + 1 transport RPC = 89 RPCs**

Client SDKs may expose convenience names that differ from the wire RPC name. For
example, the wire RPC is `DecompilerService/DecompileFunction`, while SDKs expose
helpers such as `get_decompilation` and `GetDecompilation`.

## Transport

Binary protobuf over HTTP — **not gRPC**.

- Endpoint: `POST /rpc`
- Request body: serialized `libghidra.RpcRequest` (contains method name + serialized inner request)
- Response body: serialized `libghidra.RpcResponse` (contains serialized inner response or error)
- Defined in `rpc.proto`

## Codegen

Pre-generated stubs are checked into the repository. **Hand-written code is never touched by regeneration** — generated files live in language-specific generated locations, with Python `_pb2.py` files checked into the package source tree.

| Language | Generated output | Tool |
|----------|-----------------|------|
| C++ | `cpp/generated/libghidra/*.pb.{h,cc}` | protoc `--cpp_out` |
| Java | `ghidra-extension/src/main/generated/` | protoc `--java_out` |
| Rust | `rust/generated/libghidra.rs` | prost-build (build.rs) |
| Python | `python/src/libghidra/*_pb2.py` | protoc `--python_out` |

### Regenerate all stubs (one command)

```bash
python proto/tools/regen.py --protoc /path/to/protoc
```

### Regenerate a single language

```bash
python proto/tools/regen.py --protoc /path/to/protoc --languages rust
python proto/tools/regen.py --protoc /path/to/protoc --languages cpp java
```

The script auto-detects proto files, calls protoc for C++/Java/Python, and runs the prost-build codegen crate for Rust. Set `PROTOC` env var to skip `--protoc` flag.

### Build-time auto-regeneration

Each language's build system can automatically regenerate stubs when `.proto` files change. All approaches fall back to pre-generated stubs when protoc is not available.

| Language | Mechanism | Trigger | Fallback |
|----------|-----------|---------|----------|
| C++ | CMake `add_custom_command` | Proto file newer than generated output | Uses checked-in `.pb.{h,cc}` files |
| Rust | `build.rs` with prost-build | `cargo build` (rerun-if-changed on proto dir) | Copies `generated/libghidra.rs` to `OUT_DIR` |
| Java | Gradle `generateProto` task | `compileJava` (inputs/outputs caching) | Uses checked-in Java stubs |
| Python | Manual only | — | Uses checked-in `*_pb2.py` files |

**C++**: The CMake build fetches protobuf v29.3 via FetchContent, which includes a `protoc` target. When proto files change, `add_custom_command` re-runs protoc automatically. If the `protoc` target is not available (pre-built protobuf package), the command is skipped.

**Rust**: The `build.rs` script attempts prost-build (which uses protoc). Set `PROTOC` env var to point to a protoc binary. If protoc is not available or compilation fails, it copies `generated/libghidra.rs` into `OUT_DIR`.

**Java**: The `generateProto` Gradle task finds protoc via `-PPROTOC` property, `PROTOC` env var, or `PATH`. If protoc is not found, a warning is logged and pre-generated stubs are used.

**Python**: No build step — continue using `regen.py` for manual regeneration.

## Rules

- `proto3` only.
- Package namespace: `libghidra`.
- RPC requests use typed protobuf messages only.
- The API is intentionally evolving and may introduce breaking changes.
