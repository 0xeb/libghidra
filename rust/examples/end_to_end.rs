// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// end_to_end: Launch headless Ghidra, analyze a binary, enumerate functions
// with basic blocks and decompilation, save the project, and shut down.
//
// Usage:
//   end_to_end --ghidra <ghidra_dist> --binary <target.exe> [--port <port>]
//
// Prerequisites:
//   - Ghidra distribution with the LibGhidraHost extension installed
//     (install via: gradle installExtension -PGHIDRA_INSTALL_DIR=<dist>)

use libghidra as ghidra;

fn analyze(client: &ghidra::GhidraClient) {
    let funcs = match client.list_functions(0, u64::MAX, 0, 0) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ListFunctions failed: {e}");
            return;
        }
    };
    println!(
        "\n{}\n  {} functions found\n{}\n",
        "=".repeat(70),
        funcs.functions.len(),
        "=".repeat(70)
    );

    for func in &funcs.functions {
        println!(
            "--- {} @ 0x{:x}  ({} bytes, {} params) ---",
            func.name, func.entry_address, func.size, func.parameter_count
        );

        // Basic blocks
        match client.list_basic_blocks(func.start_address, func.end_address, 0, 0) {
            Ok(bb) if !bb.blocks.is_empty() => {
                println!("  Basic blocks ({}):", bb.blocks.len());
                for b in &bb.blocks {
                    println!(
                        "    0x{:x}..0x{:x}  in_degree={}  out_degree={}",
                        b.start_address, b.end_address, b.in_degree, b.out_degree
                    );
                }
            }
            Ok(_) => println!("  Basic blocks: (none)"),
            Err(e) => println!("  Basic blocks error: {e}"),
        }

        // CFG edges
        match client.list_cfg_edges(func.start_address, func.end_address, 0, 0) {
            Ok(edges) if !edges.edges.is_empty() => {
                println!("  CFG edges ({}):", edges.edges.len());
                for e in &edges.edges {
                    println!(
                        "    0x{:x} -> 0x{:x}  ({})",
                        e.src_block_start, e.dst_block_start, e.edge_kind
                    );
                }
            }
            Ok(_) => {}
            Err(e) => println!("  CFG edges error: {e}"),
        }

        // Decompilation
        match client.get_decompilation(func.entry_address, 30000) {
            Ok(resp) => {
                if let Some(d) = &resp.decompilation {
                    if d.completed && !d.pseudocode.is_empty() {
                        let lines: Vec<&str> = d.pseudocode.trim().lines().collect();
                        println!("  Decompilation ({} lines):", lines.len());
                        for line in &lines {
                            println!("    {line}");
                        }
                    } else if !d.error_message.is_empty() {
                        println!("  Decompilation error: {}", d.error_message);
                    } else {
                        println!("  Decompilation: (empty)");
                    }
                }
            }
            Err(e) => println!("  Decompilation failed: {e}"),
        }

        println!();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut ghidra_dir = String::new();
    let mut binary = String::new();
    let mut port: u16 = 18080;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ghidra" if i + 1 < args.len() => {
                ghidra_dir = args[i + 1].clone();
                i += 2;
            }
            "--binary" if i + 1 < args.len() => {
                binary = args[i + 1].clone();
                i += 2;
            }
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(18080);
                i += 2;
            }
            _ => {
                eprintln!(
                    "Usage: {} --ghidra <ghidra_dist> --binary <target> [--port N]",
                    args[0]
                );
                std::process::exit(1);
            }
        }
    }
    if ghidra_dir.is_empty() || binary.is_empty() {
        eprintln!("ERROR: --ghidra and --binary are required");
        std::process::exit(1);
    }

    let mut h = match ghidra::launch_headless(ghidra::HeadlessOptions {
        ghidra_dir,
        binary,
        port,
        on_output: Some(Box::new(|line| println!("  [ghidra] {line}"))),
        ..Default::default()
    }) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    };

    let status = match h.get_status() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot reach host: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "\nConnected: {} v{} (mode: {})\n",
        status.service_name, status.service_version, status.host_mode
    );

    analyze(&h);

    println!("Saving project...");
    match h.save_program() {
        Ok(r) => println!("  saved={}", r.saved),
        Err(e) => println!("  save failed: {e}"),
    }

    let code = h.close(true);
    println!("  Ghidra exited with code {code}");
    println!("\nDone.");
}
