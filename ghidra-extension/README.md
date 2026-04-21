# LibGhidraHost

Ghidra extension that exposes a typed protobuf RPC API over HTTP, enabling external tools to interact with Ghidra program databases.

This folder contains the complete Java host implementation for libghidra. It builds and installs the `LibGhidraHost` Ghidra extension, which serves binary protobuf RPCs over `POST /rpc`.

## End-user quick start

Prerequisites:
- Ghidra 12.0.4+
- JDK 21
- Gradle, or the local Ghidra source-tree wrapper (`ghidra/gradlew.bat`)
- `protoc` is optional; pre-generated Java stubs are already included

1. Install the extension with:
   `gradle installExtension -PGHIDRA_INSTALL_DIR=/path/to/ghidra_dist`
2. Make sure `/path/to/ghidra_dist` is the Ghidra distribution root containing `support/buildExtension.gradle`.
3. If you do not have a standalone Gradle install, you can also run:
   `C:\path\to\ghidra\gradlew.bat -p libghidra\ghidra-extension installExtension -PGHIDRA_INSTALL_DIR=C:\path\to\ghidra_dist`
4. Launch Ghidra from that distribution and open a program.
5. Go to `File > Configure` and enable `LibGhidraHost` if needed.
6. Start the server from `Tools > libghidra Host > Start Server...`.
7. Verify the server with `Tools > libghidra Host > Status`.

By default, the host binds to `127.0.0.1:18080`.

## Responsibilities

- Host typed API operations defined in `libghidra/proto`
- Attach to the active Ghidra GUI program without changing the user's visible program
- Own open/save/close lifecycle for managed headless sessions

## Architecture

```
Proto contracts (libghidra)
    ↓
Contract records (Java mirrors of proto messages)
    ↓
Service handlers (typed Java implementations per service area)
    ↓
RpcDispatcher (routes RpcRequest.method → handler)
    ↓
libghidra HTTP server (POST /rpc endpoint)
    ↓
GUI plugin / headless host entrypoint
```

## Components

- **Contract mirrors** — `src/main/java/libghidra/host/contract`
- **Runtime layer** — `RuntimeBundle`, `HostState`, and the domain runtimes (`SessionRuntime`, `MemoryRuntime`, `TypesRuntime`, ...)
- **Service handlers** — typed handlers for health, session, memory, functions, symbols, xrefs, types, decompiler, and listing services
- **HTTP host** — `LibGhidraHttpServer` with protobuf RPC endpoint (`POST /rpc`)
- **Entry points** — `LibGhidraHostPlugin` (GUI), `LibGhidraHeadlessServer.java` (headless script), and `LibGhidraHeadlessHost` (headless host)
- **RPC services** via `RpcDispatcher`:
  - Health / session lifecycle
  - Memory / functions / symbols / xrefs
  - Decompiler / listing
  - Full types surface

## Service Handlers

- `HealthServiceHandler`, `SessionServiceHandler`
- `MemoryServiceHandler`, `FunctionsServiceHandler`
- `SymbolsServiceHandler`, `XrefsServiceHandler`
- `TypesServiceHandler`, `DecompilerServiceHandler`
- `ListingServiceHandler`

## Runtime Map

- `RuntimeBundle`: composition root used by the GUI plugin and the headless host.
- `HostState`: shared bound-program state, host mode, revision, and read/write locking.
- `HealthRuntime`: liveness and capability reporting.
- `SessionRuntime`: bind/unbind, open/save/discard/close/shutdown behavior. GUI hosts are attached to the active program and do not switch or close the visible UI program; managed headless hosts can open, save, close, and reopen programs within their configured project.
- `MemoryRuntime`: raw byte reads, writes, batch patching, and memory block listing.
- `FunctionsRuntime`: function lookup, listing, renaming, CFG queries, and tag operations.
- `SymbolsRuntime`: symbol lookup, listing, renaming, and deletion.
- `XrefsRuntime`: cross-reference enumeration.
- `TypesRuntime`: type catalog, function signatures, locals/params, and type authoring flows.
- `DecompilerRuntime`: decompilation queries and decompiler-backed local metadata.
- `ListingRuntime`: instructions, comments, data items, bookmarks, breakpoints, and strings.
- `RuntimeSupport`, `RuntimeMappers`, `DataTypeSupport`, `DecompilerSupport`, `FunctionPrototypeSupport`, `FunctionVariableMutationSupport`, and `ManagedProgramSupport`: shared helpers kept out of the domain files.

## Transport

- **Endpoint:** `POST /rpc`
- **Format:** Binary protobuf (`libghidra.RpcRequest` / `libghidra.RpcResponse`)
- **No gRPC** — plain HTTP with protobuf serialization
