// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// comments: Full CRUD lifecycle for comments at a function entry point.
//
// Usage: comments [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. Find a function to annotate
    let funcs = match client.list_functions(0, u64::MAX, 5, 0) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ListFunctions failed (is a program open?): {e}");
            std::process::exit(1);
        }
    };

    let target = match funcs.functions.first() {
        Some(f) => f,
        None => {
            eprintln!("No functions found.");
            std::process::exit(1);
        }
    };

    let addr = target.entry_address;
    println!("Target function: '{}' at 0x{:08x}\n", target.name, addr);

    // 2. Set all five comment kinds at the entry address
    let kinds = [
        (ghidra::CommentKind::Eol, "End-of-line comment from Rust"),
        (ghidra::CommentKind::Pre, "Pre-comment: setup phase"),
        (ghidra::CommentKind::Post, "Post-comment: cleanup follows"),
        (
            ghidra::CommentKind::Plate,
            "=== PLATE: Main entry point ===",
        ),
        (
            ghidra::CommentKind::Repeatable,
            "Repeatable note: called from ISR",
        ),
    ];

    println!("Setting {} comment kinds...", kinds.len());
    for (kind, text) in &kinds {
        let result = client.set_comment(addr, *kind, text).unwrap_or_else(|e| {
            eprintln!("SetComment({kind:?}) failed: {e}");
            std::process::exit(1);
        });
        println!("  {:?}: updated={}", kind, result.updated);
    }

    // 3. Read comments back to verify
    let comments = client
        .get_comments(addr, addr + 1, 50, 0)
        .unwrap_or_else(|e| {
            eprintln!("GetComments failed: {e}");
            std::process::exit(1);
        });

    println!(
        "\nComments at 0x{:08x} ({} found):",
        addr,
        comments.comments.len()
    );
    for c in &comments.comments {
        println!("  [{:?}] \"{}\"", c.kind, c.text);
    }

    // 4. Delete the repeatable comment
    println!("\nDeleting Repeatable comment...");
    let del = client
        .delete_comment(addr, ghidra::CommentKind::Repeatable)
        .unwrap_or_else(|e| {
            eprintln!("DeleteComment failed: {e}");
            std::process::exit(1);
        });
    println!("  deleted={}", del.deleted);

    // 5. Verify deletion
    let after = client.get_comments(addr, addr + 1, 50, 0).unwrap();
    println!(
        "\nComments after deletion ({} remaining):",
        after.comments.len()
    );
    for c in &after.comments {
        println!("  [{:?}] \"{}\"", c.kind, c.text);
    }

    // 6. Update an existing comment (overwrite EOL)
    println!("\nUpdating EOL comment...");
    let upd = client
        .set_comment(addr, ghidra::CommentKind::Eol, "Updated EOL comment")
        .unwrap();
    println!("  updated={}", upd.updated);

    // 7. Clean up: remove all remaining comments
    println!("\nCleaning up all comments...");
    for (kind, _) in &kinds {
        // Delete is idempotent; already-deleted ones return deleted=false
        let _ = client.delete_comment(addr, *kind);
    }

    let final_check = client.get_comments(addr, addr + 1, 50, 0).unwrap();
    println!(
        "Final comment count at 0x{:08x}: {}",
        addr,
        final_check.comments.len()
    );

    println!("\nDone.");
}
