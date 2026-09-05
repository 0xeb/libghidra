# libghidra Rust Client

Rust client for the Ghidra decompiler. Two backends, one crate, one
import:

- **`live`** *(default)* — HTTP/RPC client. Lights up when a Ghidra
  Desktop with the `LibGhidraHost` extension is reachable, or when you
  spawn a headless project session via `launch_headless_project`.
- **`local`** — offline backend. Links the C++ libghidra engine + its
  embedded Sleigh specs via a cxx FFI bridge. **No Ghidra install
  required at runtime.** Mirrors `python/src/libghidra/local.py`.

```toml
# Cargo.toml
[dependencies]
libghidra = { git = "https://github.com/0xeb/libghidra" }                                # live only
libghidra = { git = "https://github.com/0xeb/libghidra", features = ["local"] }          # live + local
libghidra = { git = "https://github.com/0xeb/libghidra", default-features = false, features = ["local"] }
                                                                                          # local only
```

The crate is **not published to crates.io** — same distribution model
as the Python wheel (which isn't on PyPI either). Pull from the GitHub
repo directly, or use `cargo binstall` against the [Releases page](https://github.com/0xeb/libghidra/releases)
for a prebuilt local-mode archive. The two distributions are kept
deliberately in sync method-for-method.

## Install

### Live (HTTP) backend — pure Rust, no system deps

```toml
[dependencies]
libghidra = { git = "https://github.com/0xeb/libghidra" }
```

That's it. Links against `ureq` + `prost`; builds in seconds.

### Local (offline) backend — needs the C++ engine

The `local` feature pulls in the cxx FFI bridge into
`libghidra::local_whole`. Two install paths:

1. **`cargo-binstall` (recommended)** — fetches a prebuilt archive for
   your target from the GitHub Release matching the crate version. No
   C++ build on your machine.
   ```
   cargo binstall libghidra
   ```
2. **Build from source** — if no prebuilt archive matches your
   target, point `build.rs` at a libghidra C++ SDK:
   ```
   # 1. Apply libghidra's patches to your Ghidra source tree. Skipping
   #    this is the #1 footgun: some local/offline loads will fail or
   #    mis-detect architecture metadata.
   cd <path/to/ghidra>
   for p in <path/to/libghidra>/cpp/patches/*.patch; do patch -p1 < "$p"; done

   # 2. Overlay compiled .sla Sleigh grammars from the matching Ghidra
   #    release ZIP into the source tree (the git tree only has .slaspec
   #    sources). Without .sla files the decompiler emits halt_baddata()
   #    for every function. See ci.yml's "Overlay compiled Sleigh .sla
   #    grammars" step for the exact rsync invocation.

   # 3. Build the SDK
   cd <path/to/libghidra>
   cmake -S cpp -B build -DLIBGHIDRA_WITH_LOCAL=ON \
                          -DGHIDRA_SOURCE_DIR=<path/to/ghidra>
   cmake --build build --config Release

   # 4. Stage the flat SDK layout expected by build.rs. Keep the vendored
   #    Protobuf/Abseil archives with the two libghidra archives so their
   #    versions cannot drift at link time.
   SDK_BUNDLE=$PWD/sdk-bundle
   mkdir -p "$SDK_BUNDLE/include" "$SDK_BUNDLE/lib"
   cp -R cpp/include/* "$SDK_BUNDLE/include/"
   find build -type f \( \
     -name 'liblibghidra_*.a' -o -name 'libghidra_*.lib' -o \
     -name 'liblibghidra_*.lib' -o -name 'libprotobuf.a' -o \
     -name 'libprotobuf.lib' -o -name 'libabsl_*.a' -o \
     -name 'absl_*.lib' -o -name 'libutf8_*.a' -o \
     -name 'utf8_*.lib' \
   \) -exec cp {} "$SDK_BUNDLE/lib/" \;

   # 5. Tell cargo where it lives
   export LIBGHIDRA_PREBUILT_DIR=$SDK_BUNDLE
   cargo build --features local
   ```

   The CI matrix (.github/workflows/ci.yml) does steps 1-3 automatically
   on every release build, which is why `cargo binstall libghidra` users
   never have to think about patches or .sla overlays. The full build
   docs live in the top-level [README's "Building the C++ SDK"](../README.md#building-the-c-sdk)
   section.

Supported targets for prebuilt archives (matches the Python wheel
matrix):

| Target triple                       | Linux x86_64 | Linux aarch64 | macOS arm64 | Windows x86_64 |
|-------------------------------------|:------------:|:-------------:|:-----------:|:--------------:|
| Prebuilt `cargo binstall` available |    ✅        |     ✅        |     ✅      |      ✅        |

Other targets (FreeBSD, illumos, etc.) work via the source path; expect
a multi-minute first compile.

#### Native dependencies for the `local` feature

Release prebuilt archives are self-contained: they carry the exact
Protobuf/Abseil/utf8 archives used to build `libghidra_client`, and Linux
archives also carry the matching static libbfd and its archive dependencies.
No Protobuf or binutils development package is needed to consume one.

A source build still needs the C++ prerequisites listed in the top-level
README. On Linux that includes the libbfd headers (`binutils-dev` on
Debian/Ubuntu, `binutils-devel` on Fedora/RHEL) at CMake build time. A custom
bundle must retain the fetched Protobuf/Abseil/utf8 archives as shown above;
otherwise the final Rust link is intentionally fail-closed instead of silently
mixing incompatible Protobuf versions. `LIBGHIDRA_LINK_LIBS` and
`LIBGHIDRA_LINK_DYLIBS` remain available for deliberately non-standard SDK
layouts.

## Quick start — live (HTTP)

```rust
use libghidra as ghidra;

let client = ghidra::connect("http://127.0.0.1:18080");

let status = client.get_status()?;
println!("{} v{}", status.service_name, status.service_version);

let funcs = client.list_functions(0, u64::MAX, 10, 0)?;
for f in &funcs.functions {
    println!("0x{:x}  {}", f.entry_address, f.name);
}
# Ok::<(), libghidra::Error>(())
```

### Project files and switching

Live/headless sessions can enumerate and import Ghidra project programs while
keeping one active program per host. Import and analyze with Ghidra, list
project programs, close the current program, then open the next Ghidra domain
path:

```rust
use libghidra::{
    ListProjectFilesRequest, OpenProgramRequest, ShutdownPolicy,
};

let files = client.list_project_files(ListProjectFilesRequest {
    programs_only: true,
    ..Default::default()
})?;
for file in &files.files {
    println!("{}", file.path);
}

client.close_program(ShutdownPolicy::Save)?;
client.open_program(OpenProgramRequest {
    project_path: "C:/work/projects".into(),
    project_name: "firmware".into(),
    program_path: "/payload.elf".into(),
    ..Default::default()
})?;
# Ok::<(), libghidra::Error>(())
```

Generic headless options default to no save/discard action. Call `close(true)`
or shut down with `ShutdownPolicy::Save` to persist the project explicitly.
Later Rust, Python, C++, GUI, or ghidrasql sessions can reopen the same project
and select saved programs by domain path. See
[`examples/multi_program_strings.rs`](examples/multi_program_strings.rs) for a
variadic live example that imports multiple binaries, counts strings, saves, and
shuts headless down.

## Quick start — local (offline)

```rust
# #[cfg(feature = "local")] {
use libghidra::format_detect::detect_and_open;
use libghidra::{local_with, LocalClientOptions};

// Auto-detect the Sleigh language ID from the binary headers.
let client = local_with(LocalClientOptions::auto())?;
let detected = detect_and_open(&client, "/usr/bin/ls", None)?;
println!("language = {}", detected.language_id);

let dec = client
    .get_decompilation(/*addr=*/0xa000, /*timeout_ms=*/30_000)?
    .decompilation
    .expect("no decompilation");
println!("{}", dec.pseudocode);
# }
# Ok::<(), libghidra::Error>(())
```

## Examples

See [`examples/`](examples/) for the full set.

| Example | Mode | Coverage |
|---------|------|----------|
| [`quickstart.rs`](examples/quickstart.rs) | live | Connect, list functions, decompile one |
| [`local_quickstart.rs`](examples/local_quickstart.rs) | local | Open a binary offline and decompile |
| [`format_detect.rs`](examples/format_detect.rs) | – | Identify Sleigh language ID without opening |
| [`explore_binary.rs`](examples/explore_binary.rs) | live | Memory blocks, functions, symbols, xrefs, strings |
| [`annotate_and_export.rs`](examples/annotate_and_export.rs) | live | Create types, rename functions, comments, batch decompile |
| [`memory_ops.rs`](examples/memory_ops.rs) | live | Memory blocks, read/write/patch bytes |
| [`disassemble.rs`](examples/disassemble.rs) | live | Instructions and disassembly listing |
| [`comments.rs`](examples/comments.rs) | live | Comment CRUD (Eol, Pre, Post, Plate, Repeatable) |
| [`data_items.rs`](examples/data_items.rs) | live | Apply data types, rename/delete data items |
| [`symbols.rs`](examples/symbols.rs) | live | Symbol query, rename, delete |
| [`type_system.rs`](examples/type_system.rs) | live | Type overview: structs, aliases, enums, unions |
| [`struct_builder.rs`](examples/struct_builder.rs) | live | Struct member add/rename/retype/delete |
| [`enum_builder.rs`](examples/enum_builder.rs) | live | Enum member add/rename/revalue/delete |
| [`function_signatures.rs`](examples/function_signatures.rs) | live | Signatures, parameter mutation, prototype override |
| [`cfg_analysis.rs`](examples/cfg_analysis.rs) | live | Basic blocks and CFG edges |
| [`decompile_tokens.rs`](examples/decompile_tokens.rs) | live | Pseudocode token records and local metadata |
| [`end_to_end.rs`](examples/end_to_end.rs) | live | Launch headless Ghidra, analyze, enumerate, save, shutdown |
| [`multi_program_strings.rs`](examples/multi_program_strings.rs) | live | Import/analyze multiple binaries, count strings per program, save project |
| [`function_tags.rs`](examples/function_tags.rs) | live | Function tag CRUD and mappings |
| [`parse_declarations.rs`](examples/parse_declarations.rs) | live | Parse C declarations into data types |
| [`session_lifecycle.rs`](examples/session_lifecycle.rs) | live | Status, capabilities, revision, save/discard |
| [`structural_analysis.rs`](examples/structural_analysis.rs) | live | Switch tables, dominators, post-dominators, loops |
| [`pagination.rs`](examples/pagination.rs) | live | `fetch_all` and `Paginator` with custom page size |

For the full method-by-method reference, see the [API Reference](docs/api_reference.md).

## Format detection

`libghidra::format_detect` is a pure-Rust port of the Python
`format_detect` module. PE / ELF / Mach-O / fat Mach-O headers map to a
Sleigh language ID without spawning the C++ engine:

```rust
use libghidra::format_detect::detect;

let detected = detect("/usr/bin/ls")?;
assert_eq!(detected.language_id, "x86:LE:64:default");
# Ok::<(), libghidra::Error>(())
```

`detect_and_open(&client, path, compiler_override)` is the convenience
wrapper used by the local `quickstart` example. It works with both
`LocalClient` and `GhidraClient` via the `OpenProgram` trait.

## Pagination (live)

```rust
use libghidra::paginate::fetch_all;

# fn doit(client: libghidra::GhidraClient) -> libghidra::Result<()> {
let all_funcs = fetch_all(|limit, offset| {
    let resp = client.list_functions(0, u64::MAX, limit, offset)?;
    Ok(resp.functions)
})?;
# Ok(()) }
```

See [`examples/pagination.rs`](examples/pagination.rs) for `Paginator`
with custom page sizes.

## API surface

Both backends share the same record/response types in
[`models.rs`](src/models.rs). Method signatures match
`python/src/libghidra/`:

| Area | Methods |
|------|---------|
| Health | `get_status`, `get_capabilities` |
| Session | `open_project`, `close_project`, `list_project_files`, `import_program`, `open_program`, `close_program`, `save_program`, `discard_program`, `get_revision`, `shutdown` (live) |
| Memory | `read_bytes`, `write_bytes` (live), `patch_bytes_batch` (live), `list_memory_blocks` |
| Functions | Function lookup/list/rename, basic blocks, CFG edges, structural analysis (live), function tags (live) |
| Symbols | `get_symbol`, `list_symbols`, `rename_symbol`, `delete_symbol` (live) |
| Xrefs | `list_xrefs` |
| Types | Queries everywhere; mutations on the live backend |
| Decompiler | `get_decompilation`, `list_decompilations` |
| Listing | Instructions, defined strings, comments (live), data items (live), bookmarks (live), breakpoints (live) |

`LocalClient` covers the same 25 methods as Python's `local.py`. The
remaining ~40 methods (mutations + listing extras) are live-only because
the local backend is read-mostly by design — see `cpp/README.md`'s "Out
of scope" section.

## Architecture

```
                                          .--------- live -----------.
                                          |                          |
            ghidra::connect(url)  --->  GhidraClient (ureq, prost)   |
                                                                     |
            ghidra::local()      --->  LocalClient (cxx, JSON)        | shared models, error
                                          |
                                          '--- libghidra::local_whole (C++ static archive)
                                                  |
                                                  '-- 376 embedded Sleigh specs
```

The cxx bridge in [`src/local_ffi.rs`](src/local_ffi.rs) +
[`cpp/bindings/rust_bridge.cpp`](../cpp/bindings/rust_bridge.cpp) emits
each method's payload as a JSON string; the wrapper in
[`src/local.rs`](src/local.rs) deserializes into the same record types
the live backend uses. Same record shape both sides — no fork, no
duplication.

## Protobuf codegen (live only)

Protobuf stubs are auto-regenerated at build time via `build.rs` using
prost-build. Set the `PROTOC` env var to point to a protoc binary to
enable auto-regeneration. If protoc is not available, the build falls
back to the pre-generated stubs in `generated/libghidra.rs`.

The C++ SDK in [`cpp/`](../cpp/) and the [proto contracts](../proto/)
are the reference implementations.

## Comparison with the Python package

| Concern | Python | Rust |
|---------|--------|------|
| Install | `pip install <release-url>` | `git` dep on this repo (live), `cargo binstall libghidra` (local) |
| Live backend | `GhidraClient` (HTTP, requests) | `GhidraClient` (HTTP, ureq) |
| Local backend | `LocalClient` (nanobind → C++) | `LocalClient` (cxx → C++) |
| Sleigh specs | embedded in `_libghidra.pyd/.so` | embedded in the prebuilt archive |
| Format detection | `libghidra.format_detect` | `libghidra::format_detect` |
| Examples | `python/examples/` (25 scripts) | `rust/examples/` (23 scripts) |

If you find behaviour that diverges between the two languages for the
same backend, please open an issue — that's a bug.
