// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// enum_builder: Create an enum type, add/rename/retype/delete members, then clean up.
//
// Usage: enum_builder [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. Create a 4-byte unsigned enum
    let enum_name = "ErrorCode";
    let created = client
        .create_type_enum(enum_name, 4, false)
        .unwrap_or_else(|e| {
            eprintln!("create_type_enum failed: {e}");
            std::process::exit(1);
        });
    println!("Created enum '{}' (updated={})", enum_name, created.updated);

    // 2. Add four members
    let entries = [
        ("OK", 0),
        ("NOT_FOUND", 1),
        ("PERMISSION_DENIED", 2),
        ("INTERNAL_ERROR", 3),
    ];
    for (name, value) in &entries {
        let resp = client
            .add_type_enum_member(enum_name, name, *value)
            .unwrap_or_else(|e| {
                eprintln!("add_type_enum_member '{name}' failed: {e}");
                std::process::exit(1);
            });
        println!("  Added '{name}' = {value} (updated={})", resp.updated);
    }

    // 3. List all members
    let members_resp = client
        .list_type_enum_members(enum_name, 100, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_type_enum_members failed: {e}");
            std::process::exit(1);
        });
    println!(
        "\nMembers of '{enum_name}' ({} total):",
        members_resp.members.len()
    );
    for m in &members_resp.members {
        println!(
            "  ordinal={} name='{}' value={}",
            m.ordinal, m.name, m.value
        );
    }

    // 4. Rename 'NOT_FOUND' (ordinal 1) -> 'ERR_NOT_FOUND'
    let rename_resp = client
        .rename_type_enum_member(enum_name, 1, "ERR_NOT_FOUND")
        .unwrap_or_else(|e| {
            eprintln!("rename_type_enum_member failed: {e}");
            std::process::exit(1);
        });
    println!(
        "\nRenamed ordinal 1 -> 'ERR_NOT_FOUND' (updated={})",
        rename_resp.updated
    );

    // 5. Change the value of 'INTERNAL_ERROR' (ordinal 3) from 3 to 99
    let set_resp = client
        .set_type_enum_member_value(enum_name, 3, 99)
        .unwrap_or_else(|e| {
            eprintln!("set_type_enum_member_value failed: {e}");
            std::process::exit(1);
        });
    println!(
        "Changed ordinal 3 value -> 99 (updated={})",
        set_resp.updated
    );

    // 6. Delete 'PERMISSION_DENIED' (ordinal 2)
    let delete_resp = client
        .delete_type_enum_member(enum_name, 2)
        .unwrap_or_else(|e| {
            eprintln!("delete_type_enum_member failed: {e}");
            std::process::exit(1);
        });
    println!("Deleted ordinal 2 (deleted={})", delete_resp.deleted);

    // 7. Verify final state
    let final_members = client
        .list_type_enum_members(enum_name, 100, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_type_enum_members (final) failed: {e}");
            std::process::exit(1);
        });
    println!("\nFinal members ({} total):", final_members.members.len());
    for m in &final_members.members {
        println!(
            "  ordinal={} name='{}' value={}",
            m.ordinal, m.name, m.value
        );
    }

    // 8. Clean up: delete the enum
    let cleanup = client.delete_type_enum(enum_name).unwrap_or_else(|e| {
        eprintln!("delete_type_enum failed: {e}");
        std::process::exit(1);
    });
    println!(
        "\nCleaned up enum '{}' (deleted={})",
        enum_name, cleanup.deleted
    );
}
