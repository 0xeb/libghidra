# libghidra Python Client

Python client for the libghidra typed RPC layer. Communicates with a
running LibGhidraHost extension via binary protobuf over `POST /rpc`.
Includes both sync (`requests`) and async (`aiohttp`) variants.

## Install

```bash
pip install -e libghidra/python          # sync only
pip install -e "libghidra/python[async]"  # sync + async
pip install -e "libghidra/python[cli]"    # adds CLI binary helpers
pip install -e "libghidra/python[local]"  # local ELF/PE/Mach-O detection helpers
pip install -e "libghidra/python[async,cli]"
```

Requires Python 3.12+ and a running LibGhidraHost instance.
The `local` extra is only needed for offline/native workflows; HTTP-only
installs do not pull in binary parser packages.

## Quick Start

```python
import libghidra as ghidra

client = ghidra.connect("http://127.0.0.1:18080")

# Check host health
status = client.get_status()
print(f"Connected: {status.service_name} v{status.service_version}")

# Open a program
resp = client.open_program(ghidra.OpenRequest(
    project_path="C:/ghidra_projects",
    project_name="MyProject",
    program_path="binary.exe",
    analyze=True,
))
print(f"Opened: {resp.program_name}")

# List functions
funcs = client.list_functions(limit=10)
for f in funcs.functions:
    print(f"  {f.name} @ 0x{f.entry_address:x}")

# Decompile
dec = client.get_decompilation(funcs.functions[0].entry_address)
print(dec.decompilation.pseudocode)

# Clean up
client.close_program()
```

## Async Usage

```python
import asyncio
from libghidra.async_client import AsyncGhidraClient
from libghidra import ConnectOptions

async def main():
    async with AsyncGhidraClient(ConnectOptions()) as client:
        status = await client.get_status()
        funcs = await client.list_functions(limit=5)
        for f in funcs.functions:
            print(f"{f.name} @ 0x{f.entry_address:x}")

asyncio.run(main())
```

## Command Line

The package installs a `libghidra` command for quick checks and shell-friendly
workflows. Connected commands talk to a running LibGhidraHost:

```bash
libghidra status --url http://127.0.0.1:18080
libghidra functions --url http://127.0.0.1:18080 --limit 20
libghidra decompile --url http://127.0.0.1:18080 0x140001000
```

The CLI also includes small offline binary helpers:

```bash
libghidra info sample.exe --sections --imports
libghidra strings sample.exe --min-length 6
libghidra disasm sample.exe entry --count 30
```

If the native local backend is available, `functions` and `decompile` can run
without a Ghidra host:

```bash
libghidra functions --local sample.exe
libghidra decompile --local sample.exe 0x401000
```

`LocalClient` auto-detects ELF, PE, Mach-O, and raw data inputs. You can still
pass `language_id` explicitly on `OpenProgramRequest` for unusual targets.

Use `--format json` or `--format csv` on supported commands for scripting.

## Features

- Broad sync API coverage across the host service areas
- Async client coverage for the core read/write, decompiler, listing, memory, session, symbols, xrefs, and type flows
- Binary protobuf transport (same as C++ and Rust clients)
- `libghidra` command for status checks, function listing, decompilation, binary info, strings, and disassembly
- Retry with exponential backoff and jitter
- Typed dataclass models (decoupled from protobuf)
- Semantic error codes matching the RPC protocol
- Async context manager support (`async with`)

## Selected Examples

See [`examples/`](examples/) for the full set of Python scripts.

| Example | Coverage |
|---------|----------|
| [`quickstart.py`](examples/quickstart.py) | Connect, list functions, decompile one |
| [`explore_binary.py`](examples/explore_binary.py) | Survey all areas (memory, types, xrefs, strings) |
| [`annotate_and_export.py`](examples/annotate_and_export.py) | Create types, rename functions, batch decompile |
| [`memory_ops.py`](examples/memory_ops.py) | Memory blocks, read/write/patch bytes |
| [`disassemble.py`](examples/disassemble.py) | Instructions and disassembly listing |
| [`comments.py`](examples/comments.py) | Comment CRUD (EOL, PRE, POST, PLATE, REPEATABLE) |
| [`data_items.py`](examples/data_items.py) | Apply data types, rename/delete data items |
| [`symbols.py`](examples/symbols.py) | Symbol query, rename, delete |
| [`type_system.py`](examples/type_system.py) | Type overview: structs, aliases, enums, unions |
| [`struct_builder.py`](examples/struct_builder.py) | Struct member add/rename/retype/delete |
| [`enum_builder.py`](examples/enum_builder.py) | Enum member add/rename/revalue/delete |
| [`function_signatures.py`](examples/function_signatures.py) | Signatures, parameter mutation, prototype override |
| [`cfg_analysis.py`](examples/cfg_analysis.py) | Basic blocks and CFG edges |
| [`session_lifecycle.py`](examples/session_lifecycle.py) | Status, capabilities, revision, save/discard |
| [`async_explore.py`](examples/async_explore.py) | AsyncGhidraClient with `asyncio` |
| [`decompile_tokens.py`](examples/decompile_tokens.py) | Pseudocode token records and local metadata |
| [`end_to_end.py`](examples/end_to_end.py) | Launch headless Ghidra, analyze, enumerate functions/blocks/decompilation, save, shutdown |
| [`function_tags.py`](examples/function_tags.py) | Function tag CRUD and mappings |
| [`parse_declarations.py`](examples/parse_declarations.py) | Parse C declarations into data types |
| [`structural_analysis.py`](examples/structural_analysis.py) | Switch tables, dominators, post-dominators, and loops |

For the full method-by-method reference, see the [API Reference](docs/api_reference.md).

## API Surface

This table describes the synchronous client. The async client mirrors the core
host operations but does not expose every newer helper method yet.

| Area | Methods |
|------|---------|
| Health | `get_status`, `get_capabilities` |
| Session | `open_program`, `close_program`, `save_program`, `discard_program`, `get_revision`, `shutdown` |
| Memory | `read_bytes`, `write_bytes`, `patch_bytes_batch`, `list_memory_blocks` |
| Functions | `get_function`, `list_functions`, `rename_function`, `list_basic_blocks`, `list_cfg_edges`, `list_switch_tables`, `list_dominators`, `list_post_dominators`, `list_loops`, `list_function_tags`, `create_function_tag`, `delete_function_tag`, `list_function_tag_mappings`, `tag_function`, `untag_function` |
| Symbols | `get_symbol`, `list_symbols`, `rename_symbol`, `delete_symbol` |
| Xrefs | `list_xrefs` |
| Types | `get_type`, `list_types`, `list_type_aliases`, `list_type_unions`, `list_type_enums`, `list_type_enum_members`, `list_type_members`, `get_function_signature`, `list_function_signatures`, `set_function_signature`, `rename_function_parameter`, `set_function_parameter_type`, `rename_function_local`, `set_function_local_type`, `apply_data_type`, `create_type`, `delete_type`, `rename_type`, `create_type_alias`, `delete_type_alias`, `set_type_alias_target`, `create_type_enum`, `delete_type_enum`, `add_type_enum_member`, `delete_type_enum_member`, `rename_type_enum_member`, `set_type_enum_member_value`, `add_type_member`, `delete_type_member`, `rename_type_member`, `set_type_member_type`, `parse_declarations` |
| Decompiler | `get_decompilation`, `list_decompilations` |
| Listing | `get_instruction`, `list_instructions`, `get_comments`, `set_comment`, `delete_comment`, `rename_data_item`, `delete_data_item`, `list_data_items`, `list_bookmarks`, `add_bookmark`, `delete_bookmark`, `list_breakpoints`, `add_breakpoint`, `set_breakpoint_enabled`, `set_breakpoint_kind`, `set_breakpoint_size`, `set_breakpoint_condition`, `set_breakpoint_group`, `delete_breakpoint`, `list_defined_strings` |
