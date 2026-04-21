// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// disassemble: List functions, pick one, and disassemble its instructions.
//
// Usage: disassemble [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. List the first 20 functions
    let funcs = match client.list_functions(0, u64::MAX, 20, 0) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ListFunctions failed (is a program open?): {e}");
            std::process::exit(1);
        }
    };

    if funcs.functions.is_empty() {
        eprintln!("No functions found in the current program.");
        std::process::exit(1);
    }

    println!("Functions ({} shown):", funcs.functions.len());
    for f in &funcs.functions {
        println!(
            "  0x{:08x}  {:<40} {} bytes, {} params",
            f.entry_address, f.name, f.size, f.parameter_count
        );
    }

    // 2. Pick the largest function for a more interesting disassembly
    let target = funcs.functions.iter().max_by_key(|f| f.size).unwrap();

    println!(
        "\nSelected '{}' (0x{:08x}, {} bytes) for disassembly.",
        target.name, target.entry_address, target.size
    );

    // 3. Get the single instruction at the entry point
    let entry_insn = client
        .get_instruction(target.entry_address)
        .unwrap_or_else(|e| {
            eprintln!("GetInstruction failed: {e}");
            std::process::exit(1);
        });

    if let Some(insn) = &entry_insn.instruction {
        println!(
            "\nEntry instruction: 0x{:08x}  {}  (len={})",
            insn.address, insn.disassembly, insn.length
        );
    } else {
        println!(
            "\nNo instruction at entry point 0x{:08x}.",
            target.entry_address
        );
    }

    // 4. List all instructions within the function's address range
    let listing = client
        .list_instructions(target.start_address, target.end_address, 500, 0)
        .unwrap_or_else(|e| {
            eprintln!("ListInstructions failed: {e}");
            std::process::exit(1);
        });

    println!(
        "\nDisassembly of '{}' ({} instructions):\n",
        target.name,
        listing.instructions.len()
    );

    for insn in &listing.instructions {
        println!("  0x{:08x}  {}", insn.address, insn.disassembly);
    }

    // 5. Also get the full function record to show prototype
    let func_detail = client
        .get_function(target.entry_address)
        .unwrap_or_else(|e| {
            eprintln!("GetFunction failed: {e}");
            std::process::exit(1);
        });

    if let Some(f) = &func_detail.function {
        println!("\nFunction details:");
        println!("  Name:       {}", f.name);
        println!("  Namespace:  {}", f.namespace_name);
        println!("  Prototype:  {}", f.prototype);
        println!("  Is thunk:   {}", f.is_thunk);
        println!("  Params:     {}", f.parameter_count);
        println!(
            "  Range:      0x{:08x}..0x{:08x} ({} bytes)",
            f.start_address, f.end_address, f.size
        );
    }

    println!("\nDone.");
}
