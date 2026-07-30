// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// quickstart: Connect to a running LibGhidraHost, list functions, and decompile one.
//
// Usage: quickstart [host_url] [project_path] [program_path]
//
// Defaults: http://127.0.0.1:18080, expects a program already open in Ghidra.

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host_url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());

    let client = ghidra::connect(host_url);

    // 1. Check host health
    let status = match client.get_status() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot reach host at {host_url}: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "Connected: {} v{} (mode: {})",
        status.service_name, status.service_version, status.host_mode
    );

    // 2. Open a program (if project path provided on command line)
    if args.len() >= 4 {
        let req = ghidra::OpenProgramRequest {
            project_path: args[2].clone(),
            program_path: args[3].clone(),
            ..Default::default()
        };
        match client.open_program(&req) {
            Ok(open) => {
                println!(
                    "Opened: {} (lang={}, base=0x{:x})",
                    open.program_name, open.language_id, open.image_base
                );
            }
            Err(e) => {
                eprintln!("OpenProgram failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // 3. List the first 10 functions
    let funcs = match client.list_functions(0, u64::MAX, 10, 0) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ListFunctions failed: {e}");
            std::process::exit(1);
        }
    };

    println!("\nFunctions ({} shown):", funcs.functions.len());
    for f in &funcs.functions {
        println!("  0x{:x}  {}  ({} bytes)", f.entry_address, f.name, f.size);
    }

    // 4. Decompile the first function
    if let Some(f) = funcs.functions.first() {
        println!("\nDecompiling {} at 0x{:x}...", f.name, f.entry_address);
        match client.get_decompilation(f.entry_address, 30000) {
            Ok(resp) => {
                if let Some(d) = &resp.decompilation {
                    if !d.pseudocode.is_empty() {
                        println!("\n{}", d.pseudocode);
                    } else {
                        eprintln!("Decompilation returned empty pseudocode");
                    }
                } else {
                    eprintln!("Decompilation failed: empty result");
                }
            }
            Err(e) => eprintln!("Decompilation failed: {e}"),
        }
    }
}
