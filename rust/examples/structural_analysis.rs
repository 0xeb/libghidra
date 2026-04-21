// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// structural_analysis: Demonstrate structural analysis RPCs (switch tables, dominators,
// post-dominators, loops) and decompile token inspection.
//
// Usage: structural_analysis [host_url]

use libghidra as ghidra;
use std::collections::HashMap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. Get server status
    let status = client.get_status().unwrap_or_else(|e| {
        eprintln!("get_status failed: {e}");
        std::process::exit(1);
    });
    println!(
        "Connected to {} v{} (mode={})",
        status.service_name, status.service_version, status.host_mode
    );

    // 2. List functions and pick the first non-trivial one (size > 64 bytes)
    let funcs = client
        .list_functions(0, u64::MAX, 200, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_functions failed: {e}");
            std::process::exit(1);
        });
    let target = funcs
        .functions
        .iter()
        .find(|f| f.size > 64)
        .unwrap_or_else(|| {
            eprintln!("No non-trivial function found (size > 64 bytes)");
            std::process::exit(1);
        });
    println!(
        "\nSelected function: {} at 0x{:x} ({} bytes)",
        target.name, target.entry_address, target.size
    );

    let range_start = target.entry_address;
    let range_end = target.entry_address + target.size;

    // 3. Switch tables
    let switch_resp = client
        .list_switch_tables(range_start, range_end, 100, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_switch_tables failed: {e}");
            std::process::exit(1);
        });
    println!(
        "\nSwitch tables ({} found):",
        switch_resp.switch_tables.len()
    );
    for st in &switch_resp.switch_tables {
        println!(
            "  switch at 0x{:x}: {} cases, default -> 0x{:x}",
            st.switch_address, st.case_count, st.default_address
        );
        for c in &st.cases {
            println!("    case {} -> 0x{:x}", c.value, c.target_address);
        }
    }

    // 4. Dominators (immediate dominator tree)
    let dom_resp = client
        .list_dominators(range_start, range_end, 1000, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_dominators failed: {e}");
            std::process::exit(1);
        });
    println!("\nDominators ({} blocks):", dom_resp.dominators.len());
    for d in &dom_resp.dominators {
        if d.is_entry {
            println!("  0x{:x} [ENTRY] depth={}", d.block_address, d.depth);
        } else {
            println!(
                "  0x{:x} idom=0x{:x} depth={}",
                d.block_address, d.idom_address, d.depth
            );
        }
    }

    // Build dominator tree children map for summary
    let mut dom_children: HashMap<u64, Vec<u64>> = HashMap::new();
    for d in &dom_resp.dominators {
        if !d.is_entry {
            dom_children
                .entry(d.idom_address)
                .or_default()
                .push(d.block_address);
        }
    }
    let max_dom_depth = dom_resp
        .dominators
        .iter()
        .map(|d| d.depth)
        .max()
        .unwrap_or(0);
    println!("  Max dominator tree depth: {max_dom_depth}");

    // 5. Post-dominators (immediate post-dominator tree)
    let pdom_resp = client
        .list_post_dominators(range_start, range_end, 1000, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_post_dominators failed: {e}");
            std::process::exit(1);
        });
    println!(
        "\nPost-dominators ({} blocks):",
        pdom_resp.post_dominators.len()
    );
    for pd in &pdom_resp.post_dominators {
        if pd.is_exit {
            println!("  0x{:x} [EXIT] depth={}", pd.block_address, pd.depth);
        } else {
            println!(
                "  0x{:x} ipdom=0x{:x} depth={}",
                pd.block_address, pd.ipdom_address, pd.depth
            );
        }
    }
    let max_pdom_depth = pdom_resp
        .post_dominators
        .iter()
        .map(|pd| pd.depth)
        .max()
        .unwrap_or(0);
    println!("  Max post-dominator tree depth: {max_pdom_depth}");

    // 6. Loops (natural loops detected via back edges)
    let loops_resp = client
        .list_loops(range_start, range_end, 100, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_loops failed: {e}");
            std::process::exit(1);
        });
    println!("\nLoops ({} found):", loops_resp.loops.len());
    for lp in &loops_resp.loops {
        println!(
            "  header=0x{:x} back_edge_from=0x{:x} kind={} blocks={} depth={}",
            lp.header_address, lp.back_edge_source, lp.loop_kind, lp.block_count, lp.depth
        );
    }

    // 7. Decompile the function and inspect tokens
    let decomp_resp = client
        .get_decompilation(target.entry_address, 30000)
        .unwrap_or_else(|e| {
            eprintln!("get_decompilation failed: {e}");
            std::process::exit(1);
        });
    let decomp = decomp_resp.decompilation.unwrap_or_else(|| {
        eprintln!("No decompilation returned");
        std::process::exit(1);
    });
    println!("\nDecompilation of '{}':", decomp.function_name);
    println!("  Prototype: {}", decomp.prototype);
    println!("  Completed: {}", decomp.completed);
    println!("  Locals: {}", decomp.locals.len());
    println!("  Tokens: {}", decomp.tokens.len());

    // Token kind histogram
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    for tok in &decomp.tokens {
        *kind_counts.entry(format!("{:?}", tok.kind)).or_default() += 1;
    }
    println!("\n  Token kind breakdown:");
    let mut sorted_kinds: Vec<_> = kind_counts.into_iter().collect();
    sorted_kinds.sort_by(|a, b| b.1.cmp(&a.1));
    for (kind, count) in &sorted_kinds {
        println!("    {kind:<16} {count}");
    }

    // Show first 20 tokens as a sample
    let sample_count = decomp.tokens.len().min(20);
    println!("\n  First {sample_count} tokens:");
    for tok in decomp.tokens.iter().take(sample_count) {
        let extra = if !tok.var_name.is_empty() {
            format!(" (var={})", tok.var_name)
        } else {
            String::new()
        };
        println!(
            "    L{}:C{} {:?} {:?}{}",
            tok.line_number, tok.column_offset, tok.kind, tok.text, extra
        );
    }

    // 8. Summary
    println!(
        "\n--- Structural Analysis Summary for '{}' ---",
        target.name
    );
    println!("  Function size:        {} bytes", target.size);
    println!(
        "  Switch tables:        {}",
        switch_resp.switch_tables.len()
    );
    println!(
        "  Total switch cases:   {}",
        switch_resp
            .switch_tables
            .iter()
            .map(|s| s.case_count)
            .sum::<u32>()
    );
    println!("  Dominator nodes:      {}", dom_resp.dominators.len());
    println!("  Max dom depth:        {max_dom_depth}");
    println!(
        "  Post-dominator nodes: {}",
        pdom_resp.post_dominators.len()
    );
    println!("  Max pdom depth:       {max_pdom_depth}");
    println!("  Natural loops:        {}", loops_resp.loops.len());
    println!("  Decompile tokens:     {}", decomp.tokens.len());
    println!("  Decompile locals:     {}", decomp.locals.len());
}
