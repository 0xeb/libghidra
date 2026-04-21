// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// cfg_analysis: List basic blocks and CFG edges, build adjacency info, print summary.
//
// Usage: cfg_analysis [host_url]

use libghidra as ghidra;
use std::collections::HashMap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. List functions and pick the first non-trivial one (size > 16 bytes)
    let funcs = client
        .list_functions(0, u64::MAX, 50, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_functions failed: {e}");
            std::process::exit(1);
        });
    let target = funcs
        .functions
        .iter()
        .find(|f| f.size > 16)
        .unwrap_or_else(|| {
            eprintln!("No non-trivial function found (size > 16 bytes)");
            std::process::exit(1);
        });
    println!(
        "Selected function: {} at 0x{:x} ({} bytes)",
        target.name, target.entry_address, target.size
    );

    // 2. List basic blocks within the function range
    let range_start = target.entry_address;
    let range_end = target.entry_address + target.size;
    let blocks_resp = client
        .list_basic_blocks(range_start, range_end, 1000, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_basic_blocks failed: {e}");
            std::process::exit(1);
        });
    println!("\nBasic blocks ({} total):", blocks_resp.blocks.len());
    for b in &blocks_resp.blocks {
        println!(
            "  0x{:x}..0x{:x}  (in_degree={}, out_degree={})",
            b.start_address, b.end_address, b.in_degree, b.out_degree
        );
    }

    // 3. List CFG edges within the function range
    let edges_resp = client
        .list_cfg_edges(range_start, range_end, 1000, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_cfg_edges failed: {e}");
            std::process::exit(1);
        });
    println!("\nCFG edges ({} total):", edges_resp.edges.len());
    for e in &edges_resp.edges {
        println!(
            "  0x{:x} -> 0x{:x}  (kind={})",
            e.src_block_start, e.dst_block_start, e.edge_kind
        );
    }

    // 4. Build adjacency list (successors per block)
    let mut successors: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut predecessors: HashMap<u64, Vec<u64>> = HashMap::new();
    for e in &edges_resp.edges {
        successors
            .entry(e.src_block_start)
            .or_default()
            .push(e.dst_block_start);
        predecessors
            .entry(e.dst_block_start)
            .or_default()
            .push(e.src_block_start);
    }

    // 5. Identify entry and exit blocks
    let entry_blocks: Vec<u64> = blocks_resp
        .blocks
        .iter()
        .filter(|b| b.in_degree == 0)
        .map(|b| b.start_address)
        .collect();
    let exit_blocks: Vec<u64> = blocks_resp
        .blocks
        .iter()
        .filter(|b| b.out_degree == 0)
        .map(|b| b.start_address)
        .collect();

    // 6. Summary
    println!("\n--- CFG Summary for '{}' ---", target.name);
    println!("  Total blocks:     {}", blocks_resp.blocks.len());
    println!("  Total edges:      {}", edges_resp.edges.len());
    println!(
        "  Entry blocks:     {:?}",
        entry_blocks
            .iter()
            .map(|a| format!("0x{:x}", a))
            .collect::<Vec<_>>()
    );
    println!(
        "  Exit blocks:      {:?}",
        exit_blocks
            .iter()
            .map(|a| format!("0x{:x}", a))
            .collect::<Vec<_>>()
    );

    // 7. Print adjacency detail for each block
    println!("\nAdjacency detail:");
    for b in &blocks_resp.blocks {
        let succ = successors.get(&b.start_address);
        let pred = predecessors.get(&b.start_address);
        let succ_str = succ.map_or_else(
            || "none".to_string(),
            |v| {
                v.iter()
                    .map(|a| format!("0x{:x}", a))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        );
        let pred_str = pred.map_or_else(
            || "none".to_string(),
            |v| {
                v.iter()
                    .map(|a| format!("0x{:x}", a))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        );
        println!(
            "  0x{:x}: preds=[{}] succs=[{}]",
            b.start_address, pred_str, succ_str
        );
    }
}
