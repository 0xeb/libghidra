// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// function_signatures: Inspect and mutate function signatures via the Ghidra API.
//
// Usage: function_signatures [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. List the first 10 functions
    let funcs = client
        .list_functions(0, u64::MAX, 10, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_functions failed: {e}");
            std::process::exit(1);
        });
    if funcs.functions.is_empty() {
        eprintln!("No functions found. Is a program open?");
        std::process::exit(1);
    }
    println!("Functions ({} shown):", funcs.functions.len());
    for f in &funcs.functions {
        println!("  0x{:x}  {}", f.entry_address, f.name);
    }

    let target = &funcs.functions[0];
    let addr = target.entry_address;
    println!("\nTarget: {} at 0x{:x}", target.name, addr);

    // 2. Decompile the target (populates signature data)
    let decomp = client.get_decompilation(addr, 30000).unwrap_or_else(|e| {
        eprintln!("get_decompilation failed: {e}");
        std::process::exit(1);
    });
    if let Some(d) = &decomp.decompilation {
        let preview: String = d.pseudocode.lines().take(3).collect::<Vec<_>>().join("\n");
        println!("Decompiled (first 3 lines):\n{preview}");
    }

    // 3. Get the function signature
    let sig_resp = client.get_function_signature(addr).unwrap_or_else(|e| {
        eprintln!("get_function_signature failed: {e}");
        std::process::exit(1);
    });
    if let Some(sig) = &sig_resp.signature {
        println!("\nSignature: {}", sig.prototype);
        println!("  return_type: {}", sig.return_type);
        println!("  calling_convention: {}", sig.calling_convention);
        println!("  has_var_args: {}", sig.has_var_args);
        println!("  parameters ({}):", sig.parameters.len());
        for p in &sig.parameters {
            println!(
                "    [{}] '{}' : {} (auto={}, forced_indirect={})",
                p.ordinal, p.name, p.data_type, p.is_auto_parameter, p.is_forced_indirect
            );
        }
    }

    // 4. List signatures in batch (first 5)
    let sigs = client
        .list_function_signatures(0, u64::MAX, 5, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_function_signatures failed: {e}");
            std::process::exit(1);
        });
    println!("\nBatch signatures ({} shown):", sigs.signatures.len());
    for s in &sigs.signatures {
        println!("  0x{:x}  {}", s.function_entry_address, s.prototype);
    }

    // 5. Rename the first parameter (if any non-auto params exist)
    if let Some(sig) = &sig_resp.signature {
        if let Some(p) = sig.parameters.iter().find(|p| !p.is_auto_parameter) {
            let rename_resp = client
                .rename_function_parameter(addr, p.ordinal as i32, "renamed_param")
                .unwrap_or_else(|e| {
                    eprintln!("rename_function_parameter failed: {e}");
                    std::process::exit(1);
                });
            println!(
                "\nRenamed parameter ordinal {} -> '{}' (updated={})",
                p.ordinal, rename_resp.name, rename_resp.updated
            );

            // 6. Change the parameter type
            let retype_resp = client
                .set_function_parameter_type(addr, p.ordinal as i32, "int")
                .unwrap_or_else(|e| {
                    eprintln!("set_function_parameter_type failed: {e}");
                    std::process::exit(1);
                });
            println!(
                "Retyped parameter ordinal {} -> '{}' (updated={})",
                p.ordinal, retype_resp.data_type, retype_resp.updated
            );
        }
    }

    // 7. Set a new prototype for the function
    let calling_convention = sig_resp
        .signature
        .as_ref()
        .map(|s| s.calling_convention.clone())
        .unwrap_or_default();
    let new_proto = format!("int {}(int a, int b)", target.name);
    let set_resp = client
        .set_function_signature(addr, &new_proto, &calling_convention)
        .unwrap_or_else(|e| {
            eprintln!("set_function_signature failed: {e}");
            std::process::exit(1);
        });
    println!(
        "\nSet prototype -> '{}' (updated={})",
        set_resp.prototype, set_resp.updated
    );

    // 8. Verify the new signature
    let verify = client.get_function_signature(addr).unwrap_or_else(|e| {
        eprintln!("get_function_signature (verify) failed: {e}");
        std::process::exit(1);
    });
    if let Some(sig) = &verify.signature {
        println!("Verified: {}", sig.prototype);
    }
}
