// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// symbols: List symbols, inspect one, rename it, and restore the original name.
//
// Usage: symbols [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. List the first 20 symbols
    let syms = match client.list_symbols(0, u64::MAX, 20, 0) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ListSymbols failed (is a program open?): {e}");
            std::process::exit(1);
        }
    };

    println!("Symbols ({} shown):", syms.symbols.len());
    for s in &syms.symbols {
        println!(
            "  0x{:08x}  {:<30} type={:<12} ns={} primary={}",
            s.address, s.name, s.r#type, s.namespace_name, s.is_primary
        );
    }

    if syms.symbols.is_empty() {
        eprintln!("No symbols found.");
        std::process::exit(1);
    }

    // 2. Pick a symbol to inspect (prefer a function symbol)
    let target = syms
        .symbols
        .iter()
        .find(|s| s.r#type == "Function")
        .unwrap_or(&syms.symbols[0]);

    let addr = target.address;
    let original_name = target.name.clone();
    println!(
        "\nSelected symbol: '{}' at 0x{:08x} (type={})",
        original_name, addr, target.r#type
    );

    // 3. Get the symbol by address
    let detail = client.get_symbol(addr).unwrap_or_else(|e| {
        eprintln!("GetSymbol failed: {e}");
        std::process::exit(1);
    });

    if let Some(s) = &detail.symbol {
        println!("\nSymbol details:");
        println!("  ID:          {}", s.symbol_id);
        println!("  Name:        {}", s.name);
        println!("  Full name:   {}", s.full_name);
        println!("  Type:        {}", s.r#type);
        println!("  Namespace:   {}", s.namespace_name);
        println!("  Source:      {}", s.source);
        println!("  Primary:     {}", s.is_primary);
        println!("  External:    {}", s.is_external);
        println!("  Dynamic:     {}", s.is_dynamic);
    }

    // 4. Rename the symbol
    let new_name = format!("{}_renamed", original_name);
    println!("\nRenaming '{}' -> '{}'...", original_name, new_name);
    let rename = client.rename_symbol(addr, &new_name).unwrap_or_else(|e| {
        eprintln!("RenameSymbol failed: {e}");
        std::process::exit(1);
    });
    println!("  renamed={}, name=\"{}\"", rename.renamed, rename.name);

    // 5. Verify the rename
    let verify = client.get_symbol(addr).unwrap();
    if let Some(s) = &verify.symbol {
        println!("  Verified: symbol is now '{}'", s.name);
    }

    // 6. Restore original name
    println!("\nRestoring original name '{}'...", original_name);
    let restore = client
        .rename_symbol(addr, &original_name)
        .unwrap_or_else(|e| {
            eprintln!("Restore failed: {e}");
            std::process::exit(1);
        });
    println!("  renamed={}, name=\"{}\"", restore.renamed, restore.name);

    // 7. Final verification
    let final_check = client.get_symbol(addr).unwrap();
    if let Some(s) = &final_check.symbol {
        println!("  Verified: symbol restored to '{}'", s.name);
    }

    // 8. Show a second page of symbols for pagination demo
    let page2 = client.list_symbols(0, u64::MAX, 10, 20).unwrap();
    println!(
        "\nPagination: symbols 20..30 ({} returned):",
        page2.symbols.len()
    );
    for s in &page2.symbols {
        println!("  0x{:08x}  {}", s.address, s.name);
    }

    println!("\nDone.");
}
