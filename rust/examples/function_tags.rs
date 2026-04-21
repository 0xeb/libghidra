// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// function_tags: Create tags, tag/untag functions, list mappings, clean up.
//
// Usage: function_tags [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. Create two tags
    println!("--- Creating tags ---");
    let t1 = client
        .create_function_tag("crypto", "Cryptographic routines")
        .unwrap_or_else(|e| {
            eprintln!("create_function_tag 'crypto' failed: {e}");
            std::process::exit(1);
        });
    println!("  Created 'crypto' (created={})", t1.created);

    let t2 = client
        .create_function_tag("network", "Network I/O functions")
        .unwrap_or_else(|e| {
            eprintln!("create_function_tag 'network' failed: {e}");
            std::process::exit(1);
        });
    println!("  Created 'network' (created={})", t2.created);

    // 2. List all tags
    let tags = client.list_function_tags().unwrap_or_else(|e| {
        eprintln!("list_function_tags failed: {e}");
        std::process::exit(1);
    });
    println!("\n--- All function tags ({} total) ---", tags.tags.len());
    for t in &tags.tags {
        println!("  name='{}' comment='{}'", t.name, t.comment);
    }

    // 3. Tag first two functions
    let funcs = client
        .list_functions(0, u64::MAX, 2, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_functions failed: {e}");
            std::process::exit(1);
        });

    println!("\n--- Tagging functions ---");
    for f in &funcs.functions {
        let r = client
            .tag_function(f.entry_address, "crypto")
            .unwrap_or_else(|e| {
                eprintln!("tag_function failed: {e}");
                std::process::exit(1);
            });
        println!("  Tagged {} with 'crypto' (updated={})", f.name, r.updated);
    }

    // Also tag first with 'network'
    if let Some(first) = funcs.functions.first() {
        let r = client
            .tag_function(first.entry_address, "network")
            .unwrap_or_else(|e| {
                eprintln!("tag_function failed: {e}");
                std::process::exit(1);
            });
        println!(
            "  Tagged {} with 'network' (updated={})",
            first.name, r.updated
        );
    }

    // 4. List all mappings
    let mappings = client.list_function_tag_mappings(0).unwrap_or_else(|e| {
        eprintln!("list_function_tag_mappings failed: {e}");
        std::process::exit(1);
    });
    println!(
        "\n--- All tag mappings ({} total) ---",
        mappings.mappings.len()
    );
    for m in &mappings.mappings {
        println!("  0x{:x} -> '{}'", m.function_entry, m.tag_name);
    }

    // 5. List mappings for first function only
    if let Some(first) = funcs.functions.first() {
        let fm = client
            .list_function_tag_mappings(first.entry_address)
            .unwrap_or_else(|e| {
                eprintln!("list_function_tag_mappings (filtered) failed: {e}");
                std::process::exit(1);
            });
        println!(
            "\n--- Tags for {} (0x{:x}) ---",
            first.name, first.entry_address
        );
        for m in &fm.mappings {
            println!("  '{}'", m.tag_name);
        }
    }

    // 6. Untag and clean up
    println!("\n--- Cleanup ---");
    for f in &funcs.functions {
        let _ = client.untag_function(f.entry_address, "crypto");
    }
    if let Some(first) = funcs.functions.first() {
        let _ = client.untag_function(first.entry_address, "network");
    }
    println!("  Untagged all functions");

    let _ = client.delete_function_tag("crypto");
    let _ = client.delete_function_tag("network");
    println!("  Deleted both tags");
}
