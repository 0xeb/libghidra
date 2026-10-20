# LocalClient API Reference

Reference for the libghidra C++ LocalClient -- an offline binary analysis engine embedding Ghidra's Sleigh decompiler. No Java, no network, no running Ghidra instance required.

## Overview

LocalClient implements the shared `IClient` surface backed by Ghidra's C++ decompiler engine, with unsupported live-Ghidra concepts returning `not_supported`. It supports decompilation, function/symbol/type queries, memory read/write, instruction disassembly, comments, data items, cross-references, and basic block/CFG extraction.

All methods return `StatusOr<T>` -- check `.ok()`, then access `.value`.

### Program-wide enumeration depends on how the program was opened

`IClient` is the shared API for both `HttpClient` (talks to a running Ghidra instance) and
`LocalClient` (this header — standalone C++ decompiler). The standalone decompiler runs no
analysis pass of its own, so what it can enumerate depends on its input:

- **From a Ghidra project** (`OpenProgramRequest::project_path`): functions come from the
  project db's symbol table, `ListXrefs` derives call and data references by decompiling
  them, and `ListLeafFunctions` reads the reference index Ghidra recorded during analysis —
  the same rule the live host applies, so both backends return the same set.
- **From a bare binary** (`program_path`): only loader symbols (PE/ELF exports and imports)
  are known, so enumeration is thin, and `ListLeafFunctions` returns `not_supported` because
  there is no reference index to read. Drive it with **explicit addresses**
  (`GetDecompilation(addr)`, `ListInstructions(start, end)`, `ReadBytes(addr, n)`,
  `CreateFunction(addr, name)`), or route enumeration through `HttpClient` against a host.

`range_end` is an **inclusive** upper bound on every list method, exactly as on the live
host: `(addr, addr)` is a point lookup, and `range_end = 0` or `UINT64_MAX` means "all".

### Out-of-band cancellation (HTTP)

`HttpClient::Cancel()` uses a short-lived control connection rather than the
client's primary RPC connection. It is therefore safe to call from another
thread while the primary client is blocked in a long listing RPC:

```cpp
libghidra::client::HttpClient client(options);
// Worker thread: client.ListInstructions(...)
auto cancelled = client.Cancel();
```

The paired Java extension marks RPCs that were already executing as cancelled.
Long listing loops poll that state and return the RPC error code `cancelled`.
Cancellation is cooperative: operations that do not poll cannot be forcibly
terminated, and a client/extension version mismatch returns an HTTP error.

## Quick Start

```cpp
#include "libghidra/ghidra.hpp"

auto client = ghidra::local({});

ghidra::OpenProgramRequest req;
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
- `ghidra::LocalClientOptions` = `libghidra::client::LocalClientOptions`
- `ghidra::OpenProgramRequest` = `libghidra::client::OpenProgramRequest`
- `ghidra::Result<T>` = `StatusOr<T>`

## Error Handling

Every method returns `StatusOr<T>`:

```cpp
auto result = client->ListFunctions(0, UINT64_MAX, 0, 0);
if (!result.ok()) {
    // result.status.code    -- error code (e.g. "not_found", "unmapped_address")
    // result.status.message -- human-readable description
    return;
}
// result.value is std::optional<T>, guaranteed non-empty when ok() is true
for (auto& f : result.value->functions) { ... }
```

Both backends answer from one lower-snake vocabulary, defined once in
`libghidra/error_codes.hpp` (`error_codes::kNotFound`, ...):

| Code | Meaning |
|------|---------|
| `not_found` | the write names something that does not exist (function, type, member ordinal, local, parameter, symbol, comment, program) |
| `unmapped_address` | the address is in no memory block |
| `not_loaded` | no program is open |
| `invalid_argument` | a malformed request, or a target of the wrong kind (a struct where an enum is needed, data over instructions, a comment inside an instruction) |
| `duplicate_name` | a create or rename would collide with an existing name |
| `not_supported` | this backend cannot do it |
| `parse_error` | a prototype or declaration does not parse |
| `uninitialized_memory` | the address is mapped but holds no bytes |
| `access_conflict` | the target is busy or protected (another program open, a write running past mapped memory) |
| `analysis_running`, `cancelled` | an analysis job owns the program / the request was cancelled |
| `internal_error` | the backend failed for a reason the request cannot fix |
| `unknown_method`, `invalid_payload` | the host does not know the RPC / cannot decode it |
| `config_error` | the backend is not configured for the request (e.g. LocalClient `SaveProgram` without `state_path`) |
| `unknown_type` | a type named as an argument (parameter, local, member or alias target type, `ApplyDataType`'s type) does not resolve |

HttpClient adds transport codes (`connection_failed`, `timeout`, ...) for failures
before the host answers.

**Writes.** A write either succeeds with its effect, or fails with one of these codes
and a message. It never answers ok with a false flag, never ok without its effect, and
never creates something it was not asked for: a rename or signature change refuses an
address with no function (`not_found`) instead of making one; an address in no memory
block is `unmapped_address`; an address inside a function names that function, as reads
do. The upserts are explicit: `SetComment` adds or replaces, `ApplyDataType` on undefined
bytes creates a data item, `CreateType*` create, and `AddPerfBenchmark` replaces a
benchmark with the same id.

`LocalClient` follows the same contract. It reads the program's memory map from the
project (or a bare PE's headers and sections; one block over a raw file), edits types in
place by Ghidra path (`/category/Name`) -- a size change lays out again every struct,
union, array and data item that holds the type by value, as Ghidra's data type manager
does -- and refuses what its engine cannot do safely with `not_supported`: deleting or
replacing a type that a prototype or another type uses, or growing a member of a struct
without packing where no free bytes follow it (Ghidra would truncate the component).

Not found is not an error for a read:

```cpp
auto r = client->GetInstruction(0xdeadbeef);
if (r.ok() && !r.value->instruction) {
    // nothing starts there
}
```

A single-record read (`GetFunction`, `GetSymbol`, `GetInstruction`,
`DecompileFunction`, `GetPcode`, `GetType`, `GetFunctionSignature`) that names
nothing succeeds with the record absent: the response field is unset on the wire,
so it reads as an empty optional / `None`, never as a placeholder record at
address 0. An address inside a function names that function (the decompilation,
signature or function that contains it); an instruction must start at the
address. With no program open these reads fail with `not_loaded`, like every
other read. The offline `LocalClient` answers the same way.

## Session

Live `HttpClient`/headless sessions also expose project lifecycle helpers:
`OpenProject`, `CloseProject`, `ListProjectFiles`, and `ImportProgram`.
Those methods are intentionally `not_supported` by `LocalClient`, because the
offline backend loads one program database rather than a full Ghidra project.

For live project workflows, list or import project programs first, then switch
the active program with `CloseProgram(ShutdownPolicy::kSave)` followed by
`OpenProgram({.project_path = ..., .project_name = ..., .program_path = "/domain/path"})`.
Close the headless host with save enabled to persist the project; later C++,
Python, Rust, GUI, or ghidrasql sessions can reopen it and select saved programs
by domain path. See `examples/list_project_files.cpp`,
`examples/switch_active_program.cpp`, and
`examples/multi_program_strings.cpp`.

### OpenProgram

```cpp
StatusOr<OpenProgramResponse> OpenProgram(const OpenProgramRequest& request)
```

Opens a binary for analysis. Must be called before any query methods.

```cpp
ghidra::OpenProgramRequest req;
req.program_path = "/path/to/binary.exe";
auto r = client->OpenProgram(req);
// r.value->program_name   -- detected program name
// r.value->language_id    -- Sleigh language (e.g. "x86:LE:64:default")
// r.value->compiler_spec  -- compiler spec (e.g. "windows")
// r.value->image_base     -- loaded image base address
```

| Field | Type | Description |
|-------|------|-------------|
| `program_path` | `string` | Path to a binary file (required unless `project_path` is set) |
| `project_path` | `string` | Path to a Ghidra project `.gpr`: the program is read from its database (see below) |
| `project_name` | `string` | Unused by LocalClient |
| `read_only` | `bool` | Unused by LocalClient |
| `language_id` | `string` | Sleigh language for a raw image (e.g. `x86:LE:64:default`) |
| `compiler_spec_id` | `string` | Compiler spec for a raw image (e.g. `windows`) |
| `format` | `string` | Loader format hint (`pe`, `elf`, `raw`, ...) |
| `base_address` | `uint64_t` | Image base for a raw image |

Opened from a project, the offline backend reads what the live host would hand its
decompiler from the program database: functions with their namespaces and thunk flags,
saved signatures (calling convention, no-return, inline, custom parameter storage), saved
local variables, the program's data types (bitfields included), call fixups, instruction
flow overrides and external function pointers. Decompilations use Ghidra's core type names
(`int`, `uint`, `undefined4`, ...) and are printed the host's way (symbol names pass through
Ghidra's C++ name sanitizer), so declarations, signatures and the locals Ghidra saved read
the same on both backends. The standalone dialect names (`int4`, `uint1`, `xunknown8`, ...)
are still accepted as input types.

### CloseProgram

```cpp
StatusOr<CloseProgramResponse> CloseProgram(ShutdownPolicy policy)
```

Closes the current program. Pass `ShutdownPolicy::kSave` to save state first,
`ShutdownPolicy::kDiscard` to abandon changes, or `ShutdownPolicy::kNone` to
perform no save/discard action.

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

Returns native freshness metadata for the current Ghidra program. `modification_number` is Ghidra's own `Program.getModificationNumber()` value, while `program_id` and path/file metadata disambiguate program switches.

```cpp
auto rev = client->GetRevision();
uint64_t id = rev.value->program_id;
uint64_t n = rev.value->modification_number;
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
// s.value->modification_number -- native Ghidra modification number
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

Decompiles the function at `address`. This is a prerequisite for xref and basic block data.

For the live Ghidra host, `DecompilationRecord::pseudocode` is the unchanged
`DecompiledFunction.getC()` string. Tokens and locals are returned in separate
record fields; they are never injected into the pseudocode text. Treat a result
as an exact successful decompilation only when `completed` is true and
`is_fallback` is false. On failure, `pseudocode` may contain a synthetic
diagnostic comment, with the reason in `error_message`.

```cpp
auto d = client->GetDecompilation(0x140001000, 30000);
if (d.ok() && d.value->decompilation) {
    auto& dec = *d.value->decompilation;
    // dec.pseudocode            -- C-like source
    // dec.function_name         -- function name
    // dec.prototype             -- function prototype
    // dec.function_entry_address
    // dec.completed             -- true if decompilation succeeded
    // dec.is_fallback           -- true if pseudocode is diagnostic fallback text
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
auto ds = client->ListDecompilations(0, UINT64_MAX, 0, 0, 60000);
for (auto& d : ds.value->decompilations) {
    if (d.completed) printf("%s: %zu bytes\n", d.function_name.c_str(), d.pseudocode.size());
}
```

Pass `range_start = 0, range_end = UINT64_MAX` for all functions.

### GetPcode (HTTP client only)

```cpp
StatusOr<GetPcodeResponse> GetPcode(
    uint64_t address, PcodeMaturity maturity, int timeout_ms)
```

Returns refined SSA or raw per-instruction P-code from the live Java host.
`PcodeOpRecord::has_address` distinguishes a real source address zero from a
synthetic op with no machine address. `LocalClient` returns `not_supported`
because the offline bridge does not yet expose this contract.

## Functions

### GetFunction

```cpp
StatusOr<GetFunctionResponse> GetFunction(uint64_t address)
```

Gets the function at an entry address or containing an interior address. The
returned record always carries the canonical entry address; callers requiring
exact-entry semantics must compare it with the requested address.

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

Lists functions whose entry lies in `[range_start, range_end]`. `limit=0` returns all. `range_start=0, range_end=UINT64_MAX` covers everything.

```cpp
auto funcs = client->ListFunctions(0, UINT64_MAX, 10, 0);
for (auto& f : funcs.value->functions) {
    printf("0x%llx  %s  (%u bytes)\n", f.entry_address, f.name.c_str(), (unsigned)f.size);
}
```

### CreateFunction

```cpp
StatusOr<CreateFunctionResponse> CreateFunction(uint64_t address,
                                                const std::optional<string>& name)
```

Defines a function whose entry is `address`, named `name` or, unset, `FUN_<address>`; the
response carries its record. `unmapped_address` outside the memory map, `duplicate_name` when
a function already starts there, `invalid_argument` when no instruction starts there. It is the
only write that creates a function: a rename or a signature edit never does.

### RenameFunction

```cpp
StatusOr<RenameFunctionResponse> RenameFunction(uint64_t address, const string& new_name)
```

Renames the function at (or containing) `address`. Increments revision.

### ListLeafFunctions

```cpp
StatusOr<ListFunctionsResponse> ListLeafFunctions(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Functions that make no call: no reference from their body has a call type. The answer is
read from the reference index Ghidra recorded during analysis, so it matches the live host
exactly (import thunks, which Ghidra records as jumps, are leaves). Needs a program opened
from a Ghidra project; a bare binary returns `not_supported`.

```cpp
auto leaves = client->ListLeafFunctions(0, 0, 0, 0);
```

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

Reads raw bytes from the program image, as the host's `Memory.getBytes` does: from the
address up to the end of the mapped, initialized memory it starts in (a read may come back
shorter than asked). An address in no memory block is `unmapped_address`; one in a block
that holds no bytes is `uninitialized_memory`. After `WriteBytes`, returns patched data
from the CoW overlay.

```cpp
auto r = client->ReadBytes(0x140001000, 32);
for (auto b : r.value->data) printf("%02x ", b);
```

### WriteBytes

```cpp
StatusOr<WriteBytesResponse> WriteBytes(uint64_t address, const vector<uint8_t>& data)
```

Writes bytes via a Copy-on-Write overlay. The original binary is never modified; patches are layered on top. Installed lazily on first write.
An address in no memory block is `unmapped_address`; a write that runs out of mapped,
initialized memory is `access_conflict`; empty data is `invalid_argument`.

```cpp
auto w = client->WriteBytes(0x140001000, {0x90, 0x90, 0x90, 0x90});
printf("Wrote %u bytes\n", w.value->bytes_written);
```

Writes land on every decompiler slot, so pooled reads see them.

### PatchBytesBatch

```cpp
StatusOr<PatchBytesBatchResponse> PatchBytesBatch(const vector<BytePatch>& patches)
```

Applies multiple patches atomically: every patch is checked first, and one bad patch
(unmapped, out of mapped memory, no data) fails the batch with nothing written.

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

Lists memory blocks (segments) with permissions. Offline this is the project's own memory
map (the host's block list), a bare PE's headers and sections, or one block over a raw
file. An address is mapped exactly when a block contains it.

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
    // s.value->symbol->is_primary, is_external, is_dynamic,
    // s.value->symbol->is_external_entry_point, symbol_id
}
```

### ListSymbols

```cpp
StatusOr<ListSymbolsResponse> ListSymbols(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Lists symbols in an address range.

### CreateLabel

```cpp
StatusOr<CreateLabelResponse> CreateLabel(uint64_t address, const string& name)
```

Adds the label `name` at `address` (Ghidra's `SymbolTable.createLabel`, `USER_DEFINED`). It never
renames: the address keeps its symbols, and the label is primary only when it had none. As in
Ghidra, a function that still has its default name (`FUN_...`) takes the name instead.
Errors: `unmapped_address`, `duplicate_name` (a symbol of that name is already at the address),
`invalid_argument` (blank or invalid name), `not_loaded`.

### RenameSymbol

```cpp
StatusOr<RenameSymbolResponse> RenameSymbol(uint64_t address, const string& new_name,
                                            const std::optional<string>& old_name = std::nullopt)
```

With `old_name`, renames exactly the symbol of that name at `address` (a function's own symbol or
any label, primary or not); `not_found` when the address has none. Without it, renames the
primary symbol, or creates a label when the address has no symbol.

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

Creates a new type. `kind` is `"struct"`, `"enum"` or `"union"`; another kind is
`invalid_argument`, and a name already taken is `duplicate_name`. A struct `size` gives it that
many undefined bytes.

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

Lists struct fields with `ordinal`, `name`, `member_type`, `offset`, `size`, `comment`, as
the live host does: member types by path name (`/int`, `/rich.pdb/Node *`), and a bitfield
as `<base>:<bits>` (`/uint:9`) with the offset and size of the bytes its bits span. The
member edits below (`AddTypeMember`, `RenameTypeMember`, `SetTypeMemberType`,
`DeleteTypeMember`) do not support a struct with bitfields offline.

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

Gets the full signature for a function: the saved prototype, with data types as
Ghidra path names (e.g. `/int`, `/rich.pdb/Shape *`). A function with no saved
signature reports `undefined name()`. The offline backend reads the signatures
saved in a Ghidra project (and the program's data types) when it opens the
project, so no decompilation is needed.

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

Lists signatures for all functions in range.

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

#### ListInstructionOperands (HTTP client only)

```cpp
StatusOr<ListInstructionOperandsResponse> ListInstructionOperands(
    uint64_t range_start, uint64_t range_end, int limit, int offset)
```

Returns separate operand records (`address`, `operand_index`, `text`,
`type_name`, `ref_type`) from the live Java host. `LocalClient` returns
`not_supported`; its offline listing bridge currently exposes only combined
instruction operand text.

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

The live HTTP client also exposes `ListXrefsFromFunction(function_address,
limit, offset)`. That bounded operation returns `from_function_address` /
`from_function_name` and `to_function_address` / `to_function_name` on each
record, allowing call-graph clients to enrich one function without issuing a
function lookup for every reference. The four fields remain empty on backends
or query modes that do not provide function context.

Uses the decompiler pool for parallel extraction when `pool_size > 1`.

## Unsupported Methods

These methods return `not_supported` on the LocalClient:

| Method | Reason |
|--------|--------|
| `GetPcode` | Live Java host P-code contract is not exposed by the offline bridge |
| `ListInstructionOperands` | Per-operand Ghidra listing metadata is Java-host-only |
| `ListSwitchTables` | Live/structural analysis surface not implemented locally |
| `ListDominators` | Live/structural analysis surface not implemented locally |
| `ListPostDominators` | Live/structural analysis surface not implemented locally |
| `ListLoops` | Live/structural analysis surface not implemented locally |
| `CreateMemoryBlock`, `RemoveMemoryBlock`, `MoveMemoryBlock`, `SetMemoryBlockAttributes` | The offline memory map is read-only |
| `SetProgramOption`, `StartAnalysis`, `CancelAnalysis` | No options model or auto-analysis offline |
| `ImportProgram`, `OpenProject`, `CloseProject` | No project writer offline |

Labels, defined data, comments, bookmarks (breakpoints are bookmarks of type
`GhidraAPI Breakpoint`, as the host stores them) and function tags are read from the project's own
tables; offline edits stay in memory (`SaveProgram` writes the state file). Union members are
edited as on the host. `ParseDeclarations` reads C as Ghidra's `CParser` does: `typedef struct S T;`
is a typedef of `S`, anonymous types are named `_struct_<n>` / `_union_<n>` / `enum_<n>`, function
pointers make function definitions in `/functions`, a redefinition replaces the type in place, and
`const` / `volatile` / `__restrict` are dropped (as they are from `SetFunctionSignature`'s prototype).

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
| | `GetPcode` | No |
| **Functions** | `GetFunction` | Yes |
| | `ListFunctions` | Yes |
| | `CreateFunction` | Yes |
| | `RenameFunction` | Yes |
| | `ListBasicBlocks` | Yes |
| | `ListCFGEdges` | Yes |
| | `ListSwitchTables` | No |
| | `ListDominators` | No |
| | `ListPostDominators` | No |
| | `ListLoops` | No |
| | `ListFunctionTags` | Yes |
| | `CreateFunctionTag` | Yes |
| | `DeleteFunctionTag` | Yes |
| | `ListFunctionTagMappings` | Yes |
| | `TagFunction` | Yes |
| | `UntagFunction` | Yes |
| **Memory** | `ReadBytes` | Yes |
| | `WriteBytes` | Yes (CoW overlay) |
| | `PatchBytesBatch` | Yes (CoW overlay) |
| | `ListMemoryBlocks` | Yes |
| **Symbols** | `GetSymbol` | Yes |
| | `ListSymbols` | Yes |
| | `CreateLabel` | Yes |
| | `RenameSymbol` | Yes |
| | `DeleteSymbol` | Yes |
| **Types** | `GetType` | Yes |
| | `ListTypes` | Yes |
| | `CreateType` | Yes (struct, union, enum) |
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
| | `ParseDeclarations` | Yes |
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
| | `ListInstructionOperands` | No |
| | `GetComments` | Yes |
| | `SetComment` | Yes |
| | `DeleteComment` | Yes |
| | `ListDataItems` | Yes |
| | `RenameDataItem` | Yes |
| | `DeleteDataItem` | Yes |
| | `ListDefinedStrings` | Yes |
| **Xrefs** | `ListXrefs` | Yes (parallel) |
| **Bookmarks** | `ListBookmarks` | Yes |
| | `AddBookmark` | Yes |
| | `DeleteBookmark` | Yes |
| **Breakpoints** | `ListBreakpoints` | Yes |
| | `AddBreakpoint` | Yes |
| | `SetBreakpointEnabled` | Yes |
| | `SetBreakpointKind` | Yes |
| | `SetBreakpointSize` | Yes |
| | `SetBreakpointCondition` | Yes |
| | `SetBreakpointGroup` | Yes |
| | `DeleteBreakpoint` | Yes |

### Pagination Conventions

All `List*` methods accept `limit` and `offset`:
- `limit = 0` -- return all results (no cap)
- `offset = 0` -- start from the beginning

Range parameters (`range_start`, `range_end`) filter by address:
- `range_start = 0, range_end = UINT64_MAX` -- entire address space

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
