# libghidra

Typed API for Ghidra program databases. Query functions, types, memory, decompiler output, and more from C++, Python, or Rust -- without touching Java.

Current release: `0.0.7` alpha. The API is usable, but still evolving.

Two backends behind one interface:

| | **Remote** (`HttpClient`) | **Local** (`LocalClient`) |
|---|---|---|
| Runtime | Ghidra JVM + host extension | none -- Sleigh engine is compiled in |
| Capabilities | full live host API (read + write) | offline subset: decompiler, functions, symbols, types, memory, listing, xrefs |
| Use case | GUI automation, live analysis, writes | offline batch decompilation, CI, tooling |

Every call returns `StatusOr<T>` -- check `.ok()`, then use `.value`.

## Install with an AI agent (recommended)

The fastest way to stand up libghidra end-to-end is to point an AI
coding agent (Claude Code, Cursor, Codex, Aider, etc.) at the bundled
installer prompt:

> [`install-prompt.md`](install-prompt.md)

It is a self-contained runbook with explicit verification gates at
every step -- preflight checks, Ghidra install, host extension install,
Python wheel install, and a first live decompilation. Hand it to your
agent and let it drive the install; intervene only if a gate reports a
failure.

If you would rather drive the install yourself, see **Get Running** below.

## Get Running

Shortest successful path: install the extension, start the server, verify with
Python, then layer the C++/Rust SDKs on the same host URL.

### Prerequisites

- [Ghidra](https://ghidra-sre.org/) distribution (12.0.4+)
- JDK 21 (e.g. [Eclipse Adoptium](https://adoptium.net/)) and [Gradle](https://gradle.org/), for building the Java extension
  - no Gradle wrapper is checked into `ghidra-extension`; with a local Ghidra source tree you can use `ghidra/gradlew.bat` instead
  - `protoc` is optional -- pre-generated Java protobuf stubs ship in-tree
- C++20 compiler (Visual Studio 2022, GCC 12+, Clang 15+) and CMake 3.26+ -- only for the C++ SDK

### 1. Install the host extension

`GHIDRA_INSTALL_DIR` must be the Ghidra distribution **root** -- the directory
containing `support/buildExtension.gradle`. If you unpacked Ghidra under
`C:\ghidra_dist\ghidra_12.1_DEV`, that full inner path is the install dir.

```bash
cd ghidra-extension
gradle installExtension -PGHIDRA_INSTALL_DIR=/path/to/ghidra_dist
```

With a local Ghidra source tree, the wrapper variant works too:

```bat
C:\path\to\ghidra\gradlew.bat -p libghidra\ghidra-extension installExtension -PGHIDRA_INSTALL_DIR=C:\ghidra_dist\ghidra_12.1_DEV
```

The extension unpacks to `/path/to/ghidra_dist/Ghidra/Extensions/LibGhidraHost`.

### 2. Start the API server

**Option A -- Ghidra GUI.** Start Ghidra from the distribution you installed
into and open a program, then:

1. `File > Configure` -- enable `LibGhidraHost` if it is not already.
2. `Tools > libghidra Host > Start Server...` -- accept the default URL, or enter `http://host:port` or plain `host:port`.
3. `Tools > libghidra Host > Status` confirms the bound URL and active program.

The dialog is prefilled with `http://127.0.0.1:18080`. To override the bind/port
at launch:

```bat
set GHIDRA_GUI_JAVA_OPTIONS=-Dlibghidra.host.bind=127.0.0.1 -Dlibghidra.host.port=19090
C:\ghidra_dist\ghidra_12.1_DEV\ghidraRun.bat
```

**Option B -- Headless, no GUI.** Use the same distribution root (the one
containing `support/analyzeHeadless`):

```bash
/path/to/ghidra_dist/support/analyzeHeadless \
  ./myproject MyProject \
  -scriptPath /path/to/ghidra_dist/Ghidra/Extensions/LibGhidraHost/ghidra_scripts \
  -postScript LibGhidraHeadlessServer.java port=18080 shutdown=save
```

The host starts without importing a binary; clients drive project operations
explicitly (`import_program`, `open_program`, queries, `close_program`,
shutdown). See [Working with projects](#working-with-projects).

### 3. First query

```python
import libghidra as ghidra

client = ghidra.connect("http://127.0.0.1:18080")
print(f"Connected: {client.get_status().service_name}")

for f in client.list_functions().functions[:10]:
    print(f"  0x{f.entry_address:x}  {f.name}")
```

```cpp
#include "libghidra/ghidra.hpp"

auto client = ghidra::connect("http://127.0.0.1:18080");
auto funcs = client->ListFunctions(/*min_addr=*/0, /*max_addr=*/UINT64_MAX,
                                   /*limit=*/10, /*offset=*/0);
if (funcs.ok())
    for (auto& f : funcs.value->functions)
        printf("0x%llx  %s\n", f.entry_address, f.name.c_str());
```

```rust
use libghidra as ghidra;

let client = ghidra::connect("http://127.0.0.1:18080");
for f in &client.list_functions(0, u64::MAX, 10, 0)?.functions {
    println!("0x{:x}  {}", f.entry_address, f.name);
}
# Ok::<(), libghidra::Error>(())
```

## Installing the SDKs

### Python

Pre-built wheels (Python 3.12+) are attached to every
[release](https://github.com/0xeb/libghidra/releases). Each native wheel bundles
**both** backends: the HTTP/RPC client and the offline local backend, with
Ghidra's Sleigh engine compiled in and processor specs embedded -- no Ghidra
install and no Java at runtime.

```bash
# Linux x86_64 (RHEL 8+, Ubuntu 20.04+, Debian 11+, Fedora 29+)
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.7/libghidra-0.0.7-cp312-abi3-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl

# Linux aarch64 (Raspberry Pi 4/5 on 64-bit OS, Ubuntu/Debian arm64)
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.7/libghidra-0.0.7-cp312-abi3-manylinux_2_26_aarch64.manylinux_2_28_aarch64.whl

# macOS Apple Silicon (M1/M2/M3/M4)
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.7/libghidra-0.0.7-cp312-abi3-macosx_26_0_arm64.whl

# Windows x64
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.7/libghidra-0.0.7-cp312-abi3-win_amd64.whl
```

Inspecting an executable **file** offline (rather than a live program) also
needs the format-detection dependencies, packaged as the `local` extra.
`LocalClient` then auto-detects ELF, PE, Mach-O and raw inputs and picks the
matching Ghidra `language_id`; you can still pass one explicitly on
`OpenProgramRequest`.

```bash
pip install "libghidra[local] @ https://github.com/0xeb/libghidra/releases/download/v0.0.7/libghidra-0.0.7-cp312-abi3-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"
```

No wheel for your platform (Intel Mac, Windows on Arm)? The pure-Python
fallback `libghidra-0.0.7-py3-none-any.whl` inside `libghidra-python-v0.0.7.zip`
on the release page gives you the HTTP/RPC client only -- no local backend.

From a clone, for contributors:

```bash
pip install -e python                       # HTTP/RPC client only
pip install -e "python[async]"              # + aiohttp for AsyncGhidraClient
pip install -e "python[cli]"                # + pefile/capstone for CLI offline helpers
pip install -e "python[local]"              # + local ELF/PE/Mach-O detection
```

The package also installs a `libghidra` command:

```bash
libghidra status    --url http://127.0.0.1:18080
libghidra functions --url http://127.0.0.1:18080 --limit 20
libghidra decompile --url http://127.0.0.1:18080 --require-exact 0x140001000
```

`--require-exact` exits nonzero rather than accepting incomplete or synthetic
fallback pseudocode. JSON output always carries `completed`, `is_fallback`, and
a normalized `status`.

### Rust

Like the Python wheel, the crate ships both backends -- and is **distributed
from GitHub Releases, not crates.io**:

```toml
[dependencies]
# Live (HTTP) only -- pure Rust, no system deps
libghidra = { git = "https://github.com/0xeb/libghidra" }

# Live + offline (cxx -> C++ engine, prebuilt archive needed)
libghidra = { git = "https://github.com/0xeb/libghidra", features = ["local"] }
```

```bash
cargo binstall libghidra   # or grab a prebuilt local archive from Releases
```

Offline use needs no Ghidra install at runtime:

```rust
use libghidra as ghidra;

# #[cfg(feature = "local")] {
let local = ghidra::local()?;
let _ = libghidra::format_detect::detect_and_open(&local, "/usr/bin/ls", None)?;
let dec = local.get_decompilation(0xa000, 30_000)?;
println!("{}", dec.decompilation.unwrap().pseudocode);
# }
# Ok::<(), libghidra::Error>(())
```

See [`rust/README.md`](rust/README.md) for the full story.

### C++

See [Building the C++ SDK](#building-the-c-sdk).

## Working with projects

A Ghidra project may hold many programs, but a libghidra host intentionally has
**one active `Program`** at a time. List or import project contents, then switch
with an explicit close/open:

```python
import libghidra as ghidra

with ghidra.launch_headless_project(ghidra.HeadlessProjectOptions(
    ghidra_dir="C:/ghidra_dist/ghidra_12.1_DEV",
    project_dir="C:/work/projects",
    project_name="firmware",
    shutdown="save",
)) as host:
    loader = host.import_program(ghidra.ImportProgramRequest(
        source_path="C:/samples/loader.elf", overwrite=True, analyze=True))
    host.import_program(ghidra.ImportProgramRequest(
        source_path="C:/samples/payload.elf", overwrite=True, analyze=True))
    host.open_program(ghidra.OpenProgramRequest(
        project_path="C:/work/projects", project_name="firmware",
        program_path=loader.primary_program_path))

    for item in host.list_project_files(
            ghidra.ListProjectFilesRequest(programs_only=True)).files:
        print(item.path)

    host.close_program(ghidra.ShutdownPolicy.SAVE)
    host.open_program(ghidra.OpenProgramRequest(
        project_path="C:/work/projects", project_name="firmware",
        program_path="/payload.elf"))
```

`program_path` is a Ghidra domain path (`/payload.elf`,
`/firmware/payload.elf`) when `project_path` and `project_name` are set.
Program-scoped APIs -- functions, memory, types, decompiler, comments -- always
act on the active program only. Close with save to persist; a later GUI, Python,
C++, Rust, or ghidrasql session can reopen any saved program.

Runnable multi-program examples: `python/examples/multi_program_strings.py`,
`cpp/examples/multi_program_strings.cpp`, `rust/examples/multi_program_strings.rs`.

### Headless process ownership

`HeadlessClient` owns the entire process tree it launches. On Windows that tree
is assigned to a kill-on-close Job Object; on POSIX the launcher and JVM share a
dedicated process group, and a lifetime guardian closes that group if the C++
owner disappears without running destructors (including `SIGKILL`).

Generic headless launchers default to the no-action policy -- owning
applications select their own. `close()` requests the caller's policy before
escalating to a bounded force-kill. `detach()` is the explicit exception: it
disarms ownership and leaves the host running after the client exits, and the
caller then owns shutdown, project locks, and cleanup.

## Building the C++ SDK

```bash
cmake -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

On Windows prefer the Visual Studio generator; MinGW may work for the HTTP
client, but the local backend is validated with MSVC. This builds
`libghidra_client` (HTTP only) -- the offline backend is opt-in because it also
needs a Ghidra **source** checkout.

> **Which Ghidra source.** The local backend tracks Ghidra `master`, not a
> release branch. It requires source at or after **GP-7063** ("New detection of
> symbol conflicts"), which split `SymbolEntry` into `MapEntry` and
> `DynamicEntry`. That landed *after* the 12.1.3 release, so the 12.1.3 source
> tree (and anything older) fails to compile the local backend with errors about
> `MapEntry`. CI pins the exact commit it builds against; see
> `.github/workflows/ci.yml`. The HTTP client has no such requirement.

To also build the offline backend:

```bash
# 1) Apply libghidra's patches to Ghidra's C++ decompiler source. CI does this
#    before every release build. Skipping it leaves some local loads failing or
#    mis-detecting architecture metadata -- and one patch (rawloadimage) is what
#    stops a single short read from silently turning every later image read
#    into zeros.
cd /path/to/ghidra-source
for p in /path/to/libghidra/cpp/patches/*.patch; do patch -p1 < "$p"; done
cd -

# 2) Overlay compiled Sleigh .sla grammars from the matching Ghidra release ZIP.
#    The git tree ships only .slaspec (grammar source); without the compiled
#    .sla files the embedded-spec generator finds architecture metadata but the
#    decompiler has no grammar, so every disassembly returns halt_baddata().
#      cp -R ghidra_*_PUBLIC/Ghidra/Processors/*/data/languages/*.sla \
#            /path/to/ghidra-source/Ghidra/Processors/<proc>/data/languages/
#    (ci.yml's "Overlay compiled Sleigh .sla" step has the exact invocation.)

# 3) Configure + build.
cmake -B build -G "Visual Studio 17 2022" \
  -DLIBGHIDRA_WITH_LOCAL=ON \
  -DGHIDRA_SOURCE_DIR=/path/to/ghidra-source
cmake --build build --config Release
```

**Source builds only** -- `pip install` and `cargo binstall` users skip all of
this; published wheels and Rust archives are produced by CI with both steps
already applied.

If you re-source the same Ghidra tree after a `.sla` update, delete
`build/cpp/embedded_specs.{cpp,h}` first: `embed_specs.py`'s staleness check
trusts source mtimes, and cp/rsync preserve the release ZIP's timestamps, so a
re-overlay can look *older* than the cached output.

### CMake targets

| Target | Alias | What |
|--------|-------|------|
| `libghidra_client` | `libghidra::client` | IClient + HTTP backend + protobuf stubs |
| `libghidra_local` | `libghidra::local` | Adds the offline decompiler backend |

```cmake
target_link_libraries(app PRIVATE libghidra::client)  # HTTP only
target_link_libraries(app PRIVATE libghidra::local)   # HTTP + offline

# Installed-package consumption
find_package(libghidra CONFIG REQUIRED)
```

An install exports both targets plus the generated `libghidra/*.h` protobuf
headers used by the public C++ API; installed consumers must make a compatible
Protobuf package exporting `protobuf::libprotobuf` discoverable to CMake.

Dependencies (auto-fetched via FetchContent): protobuf v29.3, cpp-httplib v0.16.3.

## Offline / Local Backend

The local backend embeds Ghidra's Sleigh decompiler engine directly -- no Java,
no network, no running Ghidra. Processor specs are embedded at build time, so at
runtime it is fully self-contained.

```cpp
#include "libghidra/ghidra.hpp"

ghidra::LocalClientOptions opts;
opts.pool_size = 4;  // parallel decompilation (default: 1)
auto client = ghidra::local(opts);

ghidra::OpenProgramRequest req;
req.program_path = "/path/to/binary.exe";
req.language_id = "x86:LE:64:default";  // optional; Python auto-detects
client->OpenProgram(req);

auto decomp = client->GetDecompilation(0x140001000, 30000);
if (decomp.ok())
    printf("%s\n", decomp.value->decompilation->pseudocode.c_str());
```

[`cpp/examples/`](cpp/examples/) covers HTTP, headless, and local backends
(memory, disassembly, comments, data items, symbols, types, structs, enums,
signatures, CFG, session management, project import/switching, multi-program
string counting, parallel headless analysis, and a headless cookbook). Full
method-by-method reference: [C++ LocalClient API Reference](cpp/README.md).

## Reference

### Architecture

```
IClient (composite interface, 90 domain methods)
  |-- HttpClient   --> POST /rpc (protobuf) --> libghidra host (Java, live Ghidra)
  |-- LocalClient  --> standalone C++ decompiler engine (offline, no Java)
```

### Directory structure

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

### SDK status

| SDK | Status | Notes |
|-----|--------|-------|
| **C++ (HttpClient)** | Available | Broad live-host API coverage |
| **C++ (LocalClient)** | Available | Offline subset; see [cpp/](cpp/) for supported and unsupported methods |
| **Python** | Available | Sync + async HTTP, typed models, CLI. See [python/](python/) and [API Reference](python/docs/api_reference.md) |
| **Rust** | Available | Sync HTTP, typed models, pagination helpers. See [rust/](rust/) and [API Reference](rust/docs/api_reference.md) |

### Proto contracts

Typed RPCs across 9 domain service areas, defined in
[`proto/libghidra/`](proto/libghidra/): 90 domain RPCs plus one transport RPC.
Transport is binary protobuf over `POST /rpc` (not gRPC). See
[proto/README.md](proto/README.md).

Exact-from-function xref responses carry source and destination function
identity, so call-graph views stay bounded without an RPC per edge. The live
declaration parser also supplies exact signed/unsigned 8/16/32/64-bit `stdint`
typedef identities, despite intentionally not running a C preprocessor or
loading `<stdint.h>`.

## Known Limitations

- Method names and data models may still change before a compatibility promise.
- The public C++ API still exposes generated protobuf headers under `libghidra/*`.
- Structured local-variable mutation is supported, but use the canonical
  `local_id` returned by the API rather than guessing display-style names.
- Primary validation is the live host plus headless integration coverage;
  broader clean-room packaging and installer coverage is still hardening work.

**`LocalClient` caveats:**

- **Enumeration is out of scope in local mode.** `HttpClient` talks to a running
  Ghidra whose analysis pass populates a full function/xref/string database, so
  `list_functions()`, `list_basic_blocks(addr)`, `list_cfg_edges(addr)`,
  `list_xrefs(start, end)`, `list_xrefs_to_function(addr)` and
  `list_defined_strings()` behave as expected. `LocalClient` wraps the
  standalone decompiler engine, which runs no analysis pass -- those same
  methods always return empty **by design**. Local mode is **address-driven**:
  `get_decompilation(addr)`, `list_instructions(start, end)`,
  `read_bytes(addr, n)`, `rename_function(addr, name)` and the rest of the
  per-address API work as documented. For whole-program enumeration, route
  through `HttpClient`.
- **No macOS x86_64 / Windows arm64 wheel.** Both fell out of the matrix due to
  GitHub Actions runner availability (macos-13 saturation) and
  `actions/setup-python` not shipping arm64 Python for `windows-11-arm`. Both
  will be revisited; meanwhile use the pure-Python wheel for the HTTP client.
- **After upgrading the wheel, clear the spec cache once.** The native module
  decompresses Sleigh data into `~/.ghidracpp/cache/sleigh/<key>/` on first use.
  The key is a content hash of the embedded specs (rc8+), so upgrades pick up
  new data automatically; older rc wheels (rc1-rc7) hashed the host binary's
  mtime and could leave a stale cache. If you upgraded from one of those, run
  `rm -rf ~/.ghidracpp` once.

## License and Terms of Use

In short: you may read, build, evaluate, benchmark, package, and use unmodified libghidra, including commercially, if you preserve notices and follow the license terms. You may fork or patch it to prepare bug fixes, optimizations, features, tests, or documentation improvements for contribution back within the license's contribution-purpose rules.

You may not maintain a divergent private fork, port, rebrand, clone, API-compatible replacement, competing implementation, or use libghidra as AI input to recreate or improve a derivative implementation without prior written permission from Elias Bachaalany. Independent implementations that are not copied from, materially derived from, or substantially informed by libghidra in the license's defined sense are not prohibited.

Permission requests: open a GitHub issue at [0xeb/libghidra/issues](https://github.com/0xeb/libghidra/issues).

If libghidra materially informs a distributed project, preserve the human origin: credit libghidra and Elias Bachaalany visibly in your README/docs and in About/credits UI when applicable. The license includes an examples/FAQ section for common allowed and permission-required uses. Third-party dependencies (protobuf/gRPC, the upstream Ghidra engine, and their transitive dependencies) remain under their own licenses.

See the full [Human-Origin Source License v1.0](LICENSE).

Releases up to v0.0.3 remain under the MPL-2.0 they shipped with.
