// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// pagination: Demonstrate fetch_all and Paginator for paginated API results.
//
// Usage: pagination [host_url]

use ghidra::paginate::{fetch_all, Paginator};
use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. fetch_all: collect every function in one call
    println!("=== fetch_all: all functions ===\n");
    let all_funcs = fetch_all(|limit, offset| {
        let resp = client.list_functions(0, u64::MAX, limit, offset)?;
        Ok(resp.functions)
    })
    .unwrap_or_else(|e| {
        eprintln!("fetch_all(list_functions) failed: {e}");
        std::process::exit(1);
    });
    println!("Total functions: {}", all_funcs.len());
    for (i, f) in all_funcs.iter().enumerate().take(10) {
        println!(
            "  [{:>3}] 0x{:x}  {}  ({} bytes)",
            i, f.entry_address, f.name, f.size
        );
    }
    if all_funcs.len() > 10 {
        println!("  ... and {} more", all_funcs.len() - 10);
    }

    // 2. Paginator with custom page size: iterate symbols page by page
    println!("\n=== Paginator: symbols (page_size=25) ===\n");
    let paginator = Paginator::new(|limit, offset| {
        let resp = client.list_symbols(0, u64::MAX, limit, offset)?;
        Ok(resp.symbols)
    })
    .page_size(25);

    let mut page_num = 0;
    let mut total_symbols = 0;
    for page in paginator {
        let items = page.unwrap_or_else(|e| {
            eprintln!("Paginator page failed: {e}");
            std::process::exit(1);
        });
        if items.is_empty() {
            break;
        }
        page_num += 1;
        total_symbols += items.len();
        println!(
            "Page {}: {} symbols (first: '{}', last: '{}')",
            page_num,
            items.len(),
            items.first().map_or("?", |s| &s.name),
            items.last().map_or("?", |s| &s.name),
        );
        // Stop after 5 pages for demonstration purposes
        if page_num >= 5 {
            println!("  (stopping after 5 pages for demo)");
            break;
        }
    }
    println!(
        "\nSymbols seen across {} pages: {}",
        page_num, total_symbols
    );

    // 3. fetch_all for signatures: collect all function signatures
    println!("\n=== fetch_all: all function signatures ===\n");
    let all_sigs = fetch_all(|limit, offset| {
        let resp = client.list_function_signatures(0, u64::MAX, limit, offset)?;
        Ok(resp.signatures)
    })
    .unwrap_or_else(|e| {
        eprintln!("fetch_all(list_function_signatures) failed: {e}");
        std::process::exit(1);
    });
    println!("Total signatures: {}", all_sigs.len());
    for sig in all_sigs.iter().take(5) {
        println!(
            "  0x{:x}  {} -> {}",
            sig.function_entry_address, sig.function_name, sig.prototype
        );
    }
    if all_sigs.len() > 5 {
        println!("  ... and {} more", all_sigs.len() - 5);
    }

    // 4. Compare counts
    println!("\n=== Summary ===");
    println!("  Functions:  {}", all_funcs.len());
    println!("  Signatures: {}", all_sigs.len());
    println!(
        "  Symbols:    {}+ (first {} pages)",
        total_symbols, page_num
    );
}
