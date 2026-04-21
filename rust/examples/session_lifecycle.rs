// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// session_lifecycle: Check status, capabilities, and revision; mutate; observe; discard.
//
// Usage: session_lifecycle [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. Check host status
    let status = client.get_status().unwrap_or_else(|e| {
        eprintln!("get_status failed: {e}");
        std::process::exit(1);
    });
    println!("Host status:");
    println!(
        "  service:  {} v{}",
        status.service_name, status.service_version
    );
    println!("  mode:     {}", status.host_mode);
    println!("  ok:       {}", status.ok);
    println!("  revision: {}", status.program_revision);
    if !status.warnings.is_empty() {
        println!("  warnings: {:?}", status.warnings);
    }

    // 2. Get capabilities
    let caps = client.get_capabilities().unwrap_or_else(|e| {
        eprintln!("get_capabilities failed: {e}");
        std::process::exit(1);
    });
    println!("\nCapabilities ({} total):", caps.len());
    for c in &caps {
        let note = if c.note.is_empty() {
            String::new()
        } else {
            format!(" -- {}", c.note)
        };
        println!("  [{}] {}{}", c.status, c.id, note);
    }

    // 3. Get current revision
    let rev_before = client.get_revision().unwrap_or_else(|e| {
        eprintln!("get_revision failed: {e}");
        std::process::exit(1);
    });
    println!("\nRevision before mutation: {}", rev_before.revision);

    // 4. Make a mutation: rename the first function
    let funcs = client
        .list_functions(0, u64::MAX, 1, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_functions failed: {e}");
            std::process::exit(1);
        });
    if funcs.functions.is_empty() {
        eprintln!("No functions found. Is a program open?");
        std::process::exit(1);
    }
    let target = &funcs.functions[0];
    let original_name = target.name.clone();
    let temp_name = format!("{}_lifecycle_test", original_name);
    println!(
        "\nRenaming 0x{:x}: '{}' -> '{}'",
        target.entry_address, original_name, temp_name
    );

    let rename_resp = client
        .rename_function(target.entry_address, &temp_name)
        .unwrap_or_else(|e| {
            eprintln!("rename_function failed: {e}");
            std::process::exit(1);
        });
    println!(
        "Renamed: '{}' (renamed={})",
        rename_resp.name, rename_resp.renamed
    );

    // 5. Observe revision change
    let rev_after = client.get_revision().unwrap_or_else(|e| {
        eprintln!("get_revision (after) failed: {e}");
        std::process::exit(1);
    });
    println!("\nRevision after mutation: {}", rev_after.revision);
    if rev_after.revision > rev_before.revision {
        println!(
            "Revision advanced by {}",
            rev_after.revision - rev_before.revision
        );
    } else {
        println!("Warning: revision did not advance");
    }

    // 6. Discard all changes (restores original state)
    let discard_resp = client.discard_program().unwrap_or_else(|e| {
        eprintln!("discard_program failed: {e}");
        std::process::exit(1);
    });
    println!("\nDiscarded changes (discarded={})", discard_resp.discarded);

    // 7. Verify the function name was restored
    let verify = client
        .list_functions(0, u64::MAX, 1, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_functions (verify) failed: {e}");
            std::process::exit(1);
        });
    if let Some(f) = verify.functions.first() {
        println!(
            "Verified: function at 0x{:x} is now '{}'",
            f.entry_address, f.name
        );
        if f.name == original_name {
            println!("Discard successful: name restored to original.");
        } else {
            println!(
                "Unexpected: name is '{}', expected '{}'",
                f.name, original_name
            );
        }
    }

    // 8. Final revision
    let rev_final = client.get_revision().unwrap_or_else(|e| {
        eprintln!("get_revision (final) failed: {e}");
        std::process::exit(1);
    });
    println!("\nFinal revision: {}", rev_final.revision);
}
