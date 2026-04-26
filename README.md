# libghidra

Typed API for Ghidra program databases. Query functions, types, memory, decompiler output, and more from C++, Python, or Rust -- without touching Java.

Current release: `0.0.1` alpha. The API is usable, but still evolving.

## Get Running

### Quickstart

If you are evaluating this release, the shortest successful path is:

1. Install the `LibGhidraHost` extension into a Ghidra 12.0.4+ distribution.
2. Start Ghidra, open a program, and start `Tools > libghidra Host > Start Server...`.
3. Verify connectivity with the Python client first.
4. Then layer the C++/Rust SDKs or your own tooling on top of the same host URL.

This path exercises the current release focus: live typed access, decompiler-backed reads,
and structured annotation writes.

### Prerequisites

- [Ghidra](https://ghidra-sre.org/) distribution (12.0.4+)
- JDK 21 (e.g. [Eclipse Adoptium](https://adoptium.net/)) for building the Java extension
- [Gradle](https://gradle.org/) for building the Java extension
  - no standalone Gradle wrapper is checked into `libghidra/ghidra-extension`
  - if you have the local Ghidra source tree, you can also drive the extension build with `ghidra/gradlew.bat`
- `protoc` is optional for normal extension builds; pre-generated Java protobuf stubs are included in-tree
- C++20 compiler (Visual Studio 2022, GCC 12+, or Clang 15+) -- only if using the C++ SDK
- CMake 3.20+ -- only if using the C++ SDK

### 1. Install the libghidra host extension

This installs the Ghidra plugin that serves the typed libghidra RPC API over HTTP:

`GHIDRA_INSTALL_DIR` must point at the Ghidra distribution root, the directory that contains `support/buildExtension.gradle`.
For example, if you unpack Ghidra under `C:\ghidra_dist\ghidra_12.1_DEV`, use that full inner path as the install dir.

Normal extension builds do not require `protoc`; if it is missing, the build uses the shipped generated stubs.

```bash
cd ghidra-extension
gradle installExtension -PGHIDRA_INSTALL_DIR=/path/to/ghidra_dist
```

If you already have the local Ghidra source tree checked out, this wrapper-based variant works too:

```bat
C:\path\to\ghidra\gradlew.bat -p libghidra\ghidra-extension installExtension -PGHIDRA_INSTALL_DIR=C:\ghidra_dist\ghidra_12.1_DEV
```

After install, the extension is unpacked under:

```text
/path/to/ghidra_dist/Ghidra/Extensions/LibGhidraHost
```

### 2. Start the API server

**Option A -- From the Ghidra GUI:**
Start Ghidra from the same distribution you installed into and open a program. Then:

1. Go to `File > Configure` and enable `LibGhidraHost` if it is not already enabled.
2. Use `Tools > libghidra Host > Start Server...`, then accept the default URL or enter a full `http://host:port` URL or plain `host:port`.
3. Optionally check `Tools > libghidra Host > Status` to confirm the bound URL and active program.

By default, the start dialog is prefilled with `http://127.0.0.1:18080`.

To override the GUI bind/port, launch Ghidra with JVM properties via Ghidra's launcher environment variables:

```bat
set GHIDRA_GUI_JAVA_OPTIONS=-Dlibghidra.host.bind=127.0.0.1 -Dlibghidra.host.port=19090
C:\ghidra_dist\ghidra_12.1_DEV\ghidraRun.bat
```

**Option B -- Headless (no GUI):**
```bash
/path/to/ghidra_dist/support/analyzeHeadless \
  ./myproject MyProject -import target.exe \
  -postScript LibGhidraHeadlessServer.java port=18080
```

The headless command must also use the Ghidra distribution root that contains `support/analyzeHeadless`.

### 3. Query the API

**Python** (easiest):

Pre-built wheels (Python 3.12+) are attached to every [release](https://github.com/0xeb/libghidra/releases). Each native wheel bundles both the HTTP/RPC client and the offline local backend — Ghidra's Sleigh decompiler engine is compiled in and Sleigh processor specs are embedded, so no Ghidra install or Java is needed at runtime.

```bash
# Linux x86_64 (RHEL 8+, Ubuntu 20.04+, Debian 11+, Fedora 29+)
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.1-rc8/libghidra-0.0.1-cp312-abi3-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl

# Linux aarch64 (Raspberry Pi 4/5 on 64-bit OS, Ubuntu aarch64, Debian arm64)
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.1-rc8/libghidra-0.0.1-cp312-abi3-manylinux_2_26_aarch64.manylinux_2_28_aarch64.whl

# macOS Apple Silicon (M1/M2/M3/M4)
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.1-rc8/libghidra-0.0.1-cp312-abi3-macosx_15_0_arm64.whl

# Windows x64
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.1-rc8/libghidra-0.0.1-cp312-abi3-win_amd64.whl
```

No wheel for your platform (Intel Mac, Windows on Arm, etc.)? Use the pure-Python fallback `libghidra-0.0.1-py3-none-any.whl` inside `libghidra-python-v0.0.1-rc8.zip` on the release page — it gives you the HTTP/RPC client only; the local offline backend is unavailable.

For contributor / editable installs from a clone:

```bash
pip install -e python                       # HTTP/RPC client only
pip install -e "python[async]"              # adds aiohttp for AsyncGhidraClient
pip install -e "python[cli]"                # adds pefile/capstone for CLI offline helpers
pip install -e "python[local]"              # adds local ELF/PE/Mach-O detection helpers
```

Building the offline local backend from source additionally needs CMake 3.24+, a C++20 compiler, and a local Ghidra source tree — see [Building the C++ SDK](#building-the-c-sdk).

Install `libghidra[local]` when using the native local backend from Python.
`LocalClient` auto-detects ELF, PE, Mach-O, and raw data inputs and passes the
matching Ghidra `language_id` to the backend. Advanced users can still pass an
explicit `language_id` on `OpenProgramRequest`.

```python
import libghidra as ghidra

client = ghidra.connect("http://127.0.0.1:18080")
status = client.get_status()
print(f"Connected: {status.service_name}")

funcs = client.list_functions()
for f in funcs.functions[:10]:
    print(f"  0x{f.entry_address:x}  {f.name}")
```

The Python package also installs a `libghidra` command for quick status checks,
function listing, decompilation, and small offline binary helpers:

```bash
libghidra status --url http://127.0.0.1:18080
libghidra functions --url http://127.0.0.1:18080 --limit 20
libghidra decompile --url http://127.0.0.1:18080 0x140001000
```

**C++:**
```cpp
#include "libghidra/ghidra.hpp"

auto client = ghidra::connect("http://127.0.0.1:18080");
auto funcs = client->ListFunctions(/*min_addr=*/0, /*max_addr=*/UINT64_MAX,
                                   /*limit=*/10, /*offset=*/0);
if (funcs.ok())
    for (auto& f : funcs.value->functions)
        printf("0x%llx  %s\n", f.entry_address, f.name.c_str());
```

**Rust:**
```rust
use libghidra as ghidra;

let client = ghidra::connect("http://127.0.0.1:18080");
let funcs = client.list_functions(0, u64::MAX, 10, 0)?;
for f in &funcs.functions {
    println!("0x{:x}  {}", f.entry_address, f.name);
}
```

## Building the C++ SDK

```bash
cmake -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

On Windows, prefer the Visual Studio generator. MinGW may work for the HTTP
client, but the local/offline backend is validated with MSVC.

This builds `libghidra_client` (HTTP client). The offline local backend is
opt-in because it also needs a local Ghidra source checkout.

To also build the offline local backend:

```bash
cmake -B build -G "Visual Studio 17 2022" \
  -DLIBGHIDRA_WITH_LOCAL=ON \
  -DGHIDRA_SOURCE_DIR=/path/to/ghidra-source
cmake --build build --config Release
```

### CMake targets

| Target | Alias | What |
|--------|-------|------|
| `libghidra_client` | `libghidra::client` | IClient + HTTP backend + protobuf stubs |
| `libghidra_local` | `libghidra::local` | Adds offline decompiler backend (no Java needed at runtime) |

```cmake
target_link_libraries(app PRIVATE libghidra::client)  # HTTP only
target_link_libraries(app PRIVATE libghidra::local)   # HTTP + offline
```

Installed-package consumption is supported too:

```cmake
find_package(libghidra CONFIG REQUIRED)
target_link_libraries(app PRIVATE libghidra::client)
```

An install exports `libghidra::client` and `libghidra::local`, plus the generated
`libghidra/*.h` protobuf headers used by the current public C++ API.

Dependencies (auto-fetched via FetchContent): protobuf v29.3, cpp-httplib v0.16.3.

## Offline / Local Backend

The local backend embeds Ghidra's Sleigh decompiler engine directly -- no Java, no network, no running Ghidra instance. Processor specs are embedded at build time; at runtime it's fully self-contained.

```cpp
#include "libghidra/ghidra.hpp"

ghidra::LocalOptions opts;
opts.pool_size = 4;  // parallel decompilation (default: 1)
auto client = ghidra::local(opts);

ghidra::OpenRequest req;
req.program_path = "/path/to/binary.exe";
req.language_id = "x86:LE:64:default";  // optional; Python LocalClient can auto-detect
client->OpenProgram(req);

auto decomp = client->GetDecompilation(0x140001000, 30000);
if (decomp.ok())
    printf("%s\n", decomp.value->decompilation->pseudocode.c_str());
```

See [`cpp/examples/`](cpp/examples/) for complete examples covering HTTP, headless, and local backends (memory, disassembly, comments, data items, symbols, types, structs, enums, signatures, CFG, session management, parallel headless analysis, and a complete headless cookbook).

For the full method-by-method reference, see the [C++ LocalClient API Reference](cpp/README.md).

## Architecture

```
IClient (composite interface, 88 domain methods)
  |-- HttpClient   --> POST /rpc (protobuf) --> libghidra host (Java, live Ghidra)
  |-- LocalClient  --> standalone C++ decompiler engine (offline, no Java)
```

Two backends, one interface. Every call returns `StatusOr<T>` -- check `.ok()`, then use `.value`.

| | **Remote** (HttpClient) | **Local** (LocalClient) |
|---|---|---|
| Runtime | Ghidra JVM + extension | None |
| Capabilities | Live host API (read + write) | Offline subset: decompiler, functions, symbols, types, memory, listing, xrefs |
| Use case | GUI automation, live analysis, writes | Offline batch decompilation, CI, tooling |

## Directory Structure

```
libghidra/
  proto/                  Protobuf service contracts (source of truth)
  cpp/                    C++ SDK (two CMake targets from one directory)
    include/libghidra/    Public headers
    src/                  HTTP + local backend + decompiler engine
    generated/            Pre-generated protobuf stubs
    examples/             Complete examples (HTTP + local)
  python/                 Python SDK
  rust/                   Rust SDK
  ghidra-extension/       Java extension project (installed as `LibGhidraHost`)
```

## SDK Status

| SDK | Status | Notes |
|-----|--------|-------|
| **C++ (HttpClient)** | Available | Broad live-host API coverage |
| **C++ (LocalClient)** | Available | Offline subset; see [cpp/](cpp/) for supported and unsupported methods |
| **Python** | Available | Sync + async HTTP, typed models, and CLI tooling. See [python/](python/) and [API Reference](python/docs/api_reference.md) |
| **Rust** | Available | Sync HTTP client, typed models, and pagination helpers. See [rust/](rust/) and [API Reference](rust/docs/api_reference.md) |

## Known Limitations

- Method names and data models may still change before a compatibility promise.
- The current public C++ API still exposes generated protobuf headers under `libghidra/*`.
- Structured local-variable mutation is supported, but callers should use the canonical `local_id`
  returned by the API instead of guessing display-style names.
- The primary validation path is the live host plus headless integration coverage; more expansive
  clean-room packaging and installer coverage is still release hardening work.

### Local backend (`LocalClient`) caveats

- **Enumeration methods are out of scope in local mode.** `IClient` is the shared API across
  two backends. `HttpClient` talks to a running Ghidra instance whose analysis pass populates a
  full function/xref/string database — `list_functions()`, `list_basic_blocks(addr)`,
  `list_cfg_edges(addr)`, `list_xrefs(start, end)`, and `list_defined_strings()` work as you
  would expect there. `LocalClient` wraps the standalone C++ decompiler engine, which does not
  run an analysis pass; those same enumeration methods always return empty by design. Local
  mode is for **address-driven** queries — `get_decompilation(addr)`,
  `list_instructions(start, end)`, `read_bytes(addr, n)`, `rename_function(addr, name)`, and
  the rest of the per-address API work as documented. If you need enumeration of everything in
  the analyzed program, route through `HttpClient` against a Ghidra host.
- **No macOS x86_64 / Windows arm64 wheel** in the matrix — both fell out due to GitHub Actions
  runner availability (macos-13 saturation) and `actions/setup-python` not yet shipping arm64
  Python for `windows-11-arm`. Both gaps will be revisited; in the meantime users on those
  platforms can `pip install` the pure-Python wheel from the release ZIP for the HTTP client.
- **After upgrading the wheel, clear the spec cache once.** The native module decompresses
  Ghidra's Sleigh data into `~/.ghidracpp/cache/sleigh/<key>/` on first use; the key is now a
  content hash of the embedded specs (rc8+), so an upgrade picks up new data automatically.
  Older rc wheels (rc1–rc7) hashed the host process binary's mtime instead and could leave a
  stale cache. If you upgraded from one of those, run `rm -rf ~/.ghidracpp` once.

## Proto Contracts

Typed RPCs across 9 domain service areas, defined in [`proto/libghidra/`](proto/libghidra/). The current contracts define 88 domain RPCs plus one transport RPC. Transport is binary protobuf over `POST /rpc` (not gRPC). See [proto/README.md](proto/README.md).

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
