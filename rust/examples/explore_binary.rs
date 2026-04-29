// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// explore_binary: deep-dive over a program already open in LibGhidraHost.
// Mirrors python/examples/explore_binary.py: memory blocks, functions,
// symbols, types, type aliases, enums, xrefs, first-function instructions,
// signature, strings, data items, bookmarks, and backend capabilities.
//
// Usage: cargo run --example explore_binary [host_url]

use libghidra as ghidra;

fn section(title: &str) {
    println!("\n{}", "=".repeat(60));
    println!("  {}", title);
    println!("{}", "=".repeat(60));
    println!();
}

fn unwrap_or_exit<T>(label: &str, r: ghidra::Result<T>) -> T {
    r.unwrap_or_else(|e| {
        eprintln!("{label} failed: {e}");
        std::process::exit(1);
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host_url = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("http://127.0.0.1:18080");
    let client = ghidra::connect(host_url);

    let status = unwrap_or_exit("get_status", client.get_status());
    println!(
        "Connected: {} v{}",
        status.service_name, status.service_version
    );

    section("Memory Blocks");
    let blocks = unwrap_or_exit("list_memory_blocks", client.list_memory_blocks(0, 0));
    for b in &blocks.blocks {
        let perms = format!(
            "{}{}{}",
            if b.is_read { "r" } else { "-" },
            if b.is_write { "w" } else { "-" },
            if b.is_execute { "x" } else { "-" }
        );
        println!(
            "  {:20}  0x{:012x}-0x{:012x}  {}  {} bytes",
            b.name, b.start_address, b.end_address, perms, b.size
        );
    }

    section("Functions (first 20)");
    let funcs = unwrap_or_exit(
        "list_functions",
        client.list_functions(0, u64::MAX, 20, 0),
    );
    for f in &funcs.functions {
        let thunk = if f.is_thunk { " [thunk]" } else { "" };
        println!(
            "  0x{:08x}  {}{}  ({} params, {} bytes)",
            f.entry_address, f.name, thunk, f.parameter_count, f.size
        );
    }

    section("Symbols (first 20)");
    let syms = unwrap_or_exit("list_symbols", client.list_symbols(0, u64::MAX, 20, 0));
    for s in &syms.symbols {
        let mut flags = Vec::new();
        if s.is_primary {
            flags.push("primary");
        }
        if s.is_external {
            flags.push("external");
        }
        let flag_str = if flags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", flags.join(", "))
        };
        println!(
            "  0x{:08x}  {}  ({}){}",
            s.address, s.name, s.r#type, flag_str
        );
    }

    section("Types (first 20)");
    let types = unwrap_or_exit("list_types", client.list_types("", 20, 0));
    for t in &types.types {
        println!(
            "  {:30}  kind={:12}  size={}",
            t.name, t.kind, t.length
        );
    }

    section("Cross-References (first 20)");
    let xrefs = unwrap_or_exit("list_xrefs", client.list_xrefs(0, u64::MAX, 20, 0));
    for x in &xrefs.xrefs {
        let mut flags = Vec::new();
        if x.is_flow {
            flags.push("flow");
        }
        if x.is_memory {
            flags.push("mem");
        }
        let flag_str = if flags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", flags.join(", "))
        };
        println!(
            "  0x{:08x} -> 0x{:08x}  {}{}",
            x.from_address, x.to_address, x.ref_type, flag_str
        );
    }

    if let Some(f) = funcs.functions.first() {
        section(&format!("Instructions in {} (first 10)", f.name));
        let instrs = unwrap_or_exit(
            "list_instructions",
            client.list_instructions(f.start_address, f.end_address, 10, 0),
        );
        for i in &instrs.instructions {
            println!("  0x{:08x}  {}", i.address, i.disassembly);
        }

        section(&format!("Function Signature: {}", f.name));
        match client.get_function_signature(f.entry_address) {
            Ok(sig) => {
                if let Some(s) = sig.signature {
                    println!("  Prototype: {}", s.prototype);
                    println!("  Return:    {}", s.return_type);
                    println!("  Convention: {}", s.calling_convention);
                    println!("  Varargs:   {}", s.has_var_args);
                    for p in &s.parameters {
                        println!("    param[{}]: {} {}", p.ordinal, p.data_type, p.name);
                    }
                }
            }
            Err(e) => println!("  (not available: {e})"),
        }
    }

    section("Defined Strings (first 20)");
    let strings = unwrap_or_exit(
        "list_defined_strings",
        client.list_defined_strings(0, u64::MAX, 20, 0),
    );
    for s in &strings.strings {
        let val = if s.value.len() > 60 {
            format!("{}...", &s.value[..60])
        } else {
            s.value.clone()
        };
        println!("  0x{:08x}  {:?}  ({})", s.address, val, s.data_type);
    }

    section("Backend Capabilities");
    let caps = unwrap_or_exit("get_capabilities", client.get_capabilities());
    for c in &caps {
        let note = if c.note.is_empty() {
            String::new()
        } else {
            format!(" ({})", c.note)
        };
        println!("  {:20}  {}{}", c.id, c.status, note);
    }

    println!();
}
