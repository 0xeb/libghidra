// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// decompile_tokens: Structured analysis of decompilation token streams.
//
// Usage: decompile_tokens [host_url]
//
// Demonstrates structured token-stream analysis: reconstructing source lines,
// finding function calls, mapping variables, listing type references, and
// performing token-level search directly from the decompilation output.

use libghidra as ghidra;
use std::collections::{BTreeMap, BTreeSet, HashMap};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. List functions and pick a non-trivial one (size > 64 bytes)
    let funcs = client
        .list_functions(0, u64::MAX, 50, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_functions failed: {e}");
            std::process::exit(1);
        });
    let target = funcs
        .functions
        .iter()
        .find(|f| f.size > 64)
        .or(funcs.functions.first())
        .unwrap_or_else(|| {
            eprintln!("No functions found");
            std::process::exit(1);
        });
    println!(
        "Function: {} at 0x{:x} ({} bytes)",
        target.name, target.entry_address, target.size
    );

    // 2. Decompile
    let resp = client
        .get_decompilation(target.entry_address, 30000)
        .unwrap_or_else(|e| {
            eprintln!("get_decompilation failed: {e}");
            std::process::exit(1);
        });
    let d = resp.decompilation.unwrap_or_else(|| {
        eprintln!("No decompilation result");
        std::process::exit(1);
    });
    let tokens = &d.tokens;
    let locals = &d.locals;
    println!(
        "\nDecompiled {}: {} tokens, {} locals",
        target.name,
        tokens.len(),
        locals.len()
    );

    // ======================================================================
    // 3. Reconstruct source lines
    // ======================================================================
    println!("\n=== Reconstructed source ===");
    let mut lines: BTreeMap<i32, String> = BTreeMap::new();
    for tok in tokens {
        lines
            .entry(tok.line_number)
            .or_default()
            .push_str(&tok.text);
    }
    for (line_num, text) in &lines {
        println!("{:4} | {}", line_num, text);
    }

    // ======================================================================
    // 4. Function calls (kind == Function) — ctree_v_calls equivalent
    // ======================================================================
    println!("\n=== Function calls (ctree_v_calls equivalent) ===");
    let mut call_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for tok in tokens {
        if matches!(tok.kind, ghidra::DecompileTokenKind::Function) {
            *call_counts.entry(&tok.text).or_default() += 1;
        }
    }
    if call_counts.is_empty() {
        println!("  (no function call tokens)");
    }
    for (name, count) in &call_counts {
        println!("  {:<30} {} reference(s)", name, count);
    }

    // ======================================================================
    // 5. Variable map (kind == Variable | Parameter) — ctree_lvars equivalent
    // ======================================================================
    println!("\n=== Variable map (ctree_lvars equivalent) ===");
    struct VarInfo {
        ref_count: usize,
        var_type: String,
        var_storage: String,
        role: String,
    }
    let mut var_map: BTreeMap<String, VarInfo> = BTreeMap::new();
    for tok in tokens {
        let is_var = matches!(
            tok.kind,
            ghidra::DecompileTokenKind::Variable | ghidra::DecompileTokenKind::Parameter
        );
        if !is_var {
            continue;
        }
        let name = if tok.var_name.is_empty() {
            tok.text.clone()
        } else {
            tok.var_name.clone()
        };
        let info = var_map.entry(name).or_insert_with(|| VarInfo {
            ref_count: 0,
            var_type: String::new(),
            var_storage: String::new(),
            role: String::new(),
        });
        info.ref_count += 1;
        if !tok.var_type.is_empty() {
            info.var_type = tok.var_type.clone();
        }
        if !tok.var_storage.is_empty() {
            info.var_storage = tok.var_storage.clone();
        }
        info.role = format!("{:?}", tok.kind).to_lowercase();
    }

    println!(
        "  {:<20} {:<8} {:<10} {:<20} STORAGE",
        "NAME", "REFS", "ROLE", "TYPE"
    );
    println!("  {}", "-".repeat(70));
    for (name, info) in &var_map {
        let vtype = if info.var_type.is_empty() {
            "-"
        } else {
            &info.var_type
        };
        let vstor = if info.var_storage.is_empty() {
            "-"
        } else {
            &info.var_storage
        };
        println!(
            "  {:<20} {:<8} {:<10} {:<20} {}",
            name, info.ref_count, info.role, vtype, vstor
        );
    }

    // Cross-reference with locals
    println!("\n  Locals from decompilation ({}):", locals.len());
    for local in locals {
        let in_tokens = var_map.contains_key(&local.name);
        let tag = if in_tokens {
            "[in tokens]"
        } else {
            "[not in tokens]"
        };
        println!(
            "    {:<18} type={:<16} storage={:<12} {}",
            local.name, local.data_type, local.storage, tag
        );
    }

    // ======================================================================
    // 6. Type references (kind == Type)
    // ======================================================================
    println!("\n=== Type references ===");
    let type_refs: BTreeSet<&str> = tokens
        .iter()
        .filter(|t| matches!(t.kind, ghidra::DecompileTokenKind::Type))
        .map(|t| t.text.as_str())
        .collect();
    if type_refs.is_empty() {
        println!("  (no type tokens)");
    }
    for t in &type_refs {
        println!("  {}", t);
    }

    // ======================================================================
    // 7. Token kind distribution
    // ======================================================================
    println!("\n=== Token kind distribution ===");
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    for tok in tokens {
        *kind_counts
            .entry(format!("{:?}", tok.kind).to_lowercase())
            .or_default() += 1;
    }
    let mut kind_vec: Vec<_> = kind_counts.iter().collect();
    kind_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (kind, count) in &kind_vec {
        println!("  {:<14} {}", kind, count);
    }

    // ======================================================================
    // 8. Token search (search for first variable name with line context)
    // ======================================================================
    let pattern = var_map
        .keys()
        .next()
        .cloned()
        .unwrap_or_else(|| "return".to_string());
    println!("\n=== Token search for \"{}\" ===", pattern);
    for tok in tokens {
        if tok.text.contains(&pattern) {
            let kind_str = format!("{:?}", tok.kind).to_lowercase();
            let line_ctx = lines.get(&tok.line_number).map_or("", |s| s.as_str());
            println!(
                "  line {:3} col {:3}  [{:<10}]  \"{}\"  -->  {}",
                tok.line_number, tok.column_offset, kind_str, tok.text, line_ctx
            );
        }
    }

    // ======================================================================
    // Summary
    // ======================================================================
    println!("\n=== Summary ===");
    println!("  Function:       {}", target.name);
    println!("  Total tokens:   {}", tokens.len());
    println!("  Source lines:   {}", lines.len());
    println!("  Callees:        {}", call_counts.len());
    println!("  Variables:      {}", var_map.len());
    println!("  Types used:     {}", type_refs.len());
    println!("  Locals:         {}", locals.len());
}
