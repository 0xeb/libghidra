// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// annotate_and_export: create types, rename functions, add comments, then
// batch-decompile and write the output to a file. Mirrors
// python/examples/annotate_and_export.py.
//
// Usage: cargo run --example annotate_and_export [host_url] [output_file]

use std::fs::File;
use std::io::Write;

use libghidra as ghidra;
use libghidra::CommentKind;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host_url = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("http://127.0.0.1:18080");
    let output_file = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("decompiled.c");

    let client = ghidra::connect(host_url);
    let status = client.get_status().unwrap_or_else(|e| {
        eprintln!("Cannot reach host at {host_url}: {e}");
        std::process::exit(1);
    });
    println!(
        "Connected: {} v{}",
        status.service_name, status.service_version
    );

    // -- Create types ---------------------------------------------------------
    println!("\nCreating types...");
    log_result("create_type(context_t)", client.create_type("context_t", "struct", 64));
    log_result(
        "create_type_enum(error_code_t)",
        client.create_type_enum("error_code_t", 4, false),
    );
    for (name, value) in [("ERR_NONE", 0i64), ("ERR_INVALID", 1), ("ERR_TIMEOUT", 2)] {
        log_result(
            &format!("add_type_enum_member(error_code_t, {name})"),
            client.add_type_enum_member("error_code_t", name, value),
        );
    }
    log_result(
        "add_type_member(context_t, flags)",
        client.add_type_member("context_t", "flags", "int", 4),
    );
    log_result(
        "add_type_member(context_t, status)",
        client.add_type_member("context_t", "status", "error_code_t", 4),
    );

    // -- Rename + comment first few functions --------------------------------
    println!("\nAnnotating functions...");
    let renames = [
        ("entry", "program_entry"),
        ("init", "initialize_subsystems"),
        ("main", "application_main"),
    ];
    let funcs = match client.list_functions(0, u64::MAX, 5, 0) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("list_functions failed: {e}");
            std::process::exit(1);
        }
    };
    for f in &funcs.functions {
        for (old, new) in &renames {
            if f.name.to_lowercase().starts_with(old) {
                if let Err(e) = client.rename_function(f.entry_address, new) {
                    println!("  rename_function({}): {e}", f.name);
                }
            }
        }
        let _ = client
            .set_comment(f.entry_address, CommentKind::Plate, "Annotated by libghidra example")
            .map_err(|e| println!("  set_comment({}): {e}", f.name));
    }

    // -- Batch decompile and dump --------------------------------------------
    println!("\nDecompiling functions to {}...", output_file);
    let decomps = match client.list_decompilations(0, u64::MAX, 0, 0, 30_000) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("list_decompilations failed: {e}");
            std::process::exit(1);
        }
    };

    let mut out = File::create(output_file).unwrap_or_else(|e| {
        eprintln!("could not open {output_file}: {e}");
        std::process::exit(1);
    });
    for d in &decomps.decompilations {
        if d.pseudocode.is_empty() {
            continue;
        }
        let _ = writeln!(
            out,
            "// {} @ 0x{:x}\n{}\n",
            d.function_name, d.function_entry_address, d.pseudocode
        );
    }
    println!("Wrote {} functions to {}", decomps.decompilations.len(), output_file);
}

fn log_result<T>(label: &str, r: ghidra::Result<T>) {
    match r {
        Ok(_) => println!("  {label}: ok"),
        Err(e) => println!("  {label}: {e}"),
    }
}
