// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// struct_builder: Create a struct type, add/rename/retype/delete members, then clean up.
//
// Usage: struct_builder [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. Create a struct type
    let struct_name = "ExampleStruct";
    let created = client
        .create_type(struct_name, "struct", 32)
        .unwrap_or_else(|e| {
            eprintln!("create_type failed: {e}");
            std::process::exit(1);
        });
    println!(
        "Created struct '{}' (updated={})",
        struct_name, created.updated
    );

    // 2. Add three fields
    let fields = [
        ("flags", "uint", 4),
        ("buffer_ptr", "pointer", 8),
        ("length", "uint", 4),
    ];
    for (name, dtype, size) in &fields {
        let resp = client
            .add_type_member(struct_name, name, dtype, *size as u64)
            .unwrap_or_else(|e| {
                eprintln!("add_type_member '{name}' failed: {e}");
                std::process::exit(1);
            });
        println!(
            "  Added field '{name}' (type={dtype}, size={size}, updated={})",
            resp.updated
        );
    }

    // 3. List all members
    let members_resp = client
        .list_type_members(struct_name, 100, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_type_members failed: {e}");
            std::process::exit(1);
        });
    println!(
        "\nMembers of '{struct_name}' ({} total):",
        members_resp.members.len()
    );
    for m in &members_resp.members {
        println!(
            "  ordinal={} name='{}' type='{}' offset={} size={}",
            m.ordinal, m.name, m.member_type, m.offset, m.size
        );
    }

    // 4. Rename the first member: flags -> status_flags
    let rename_resp = client
        .rename_type_member(struct_name, 0, "status_flags")
        .unwrap_or_else(|e| {
            eprintln!("rename_type_member failed: {e}");
            std::process::exit(1);
        });
    println!(
        "\nRenamed ordinal 0 -> 'status_flags' (updated={})",
        rename_resp.updated
    );

    // 5. Change the type of 'buffer_ptr' (ordinal 1) to 'byte *'
    let retype_resp = client
        .set_type_member_type(struct_name, 1, "byte *")
        .unwrap_or_else(|e| {
            eprintln!("set_type_member_type failed: {e}");
            std::process::exit(1);
        });
    println!(
        "Retyped ordinal 1 -> 'byte *' (updated={})",
        retype_resp.updated
    );

    // 6. Delete the last member (ordinal 2, 'length')
    let delete_resp = client
        .delete_type_member(struct_name, 2)
        .unwrap_or_else(|e| {
            eprintln!("delete_type_member failed: {e}");
            std::process::exit(1);
        });
    println!("Deleted ordinal 2 (deleted={})", delete_resp.deleted);

    // 7. Verify final state
    let final_members = client
        .list_type_members(struct_name, 100, 0)
        .unwrap_or_else(|e| {
            eprintln!("list_type_members (final) failed: {e}");
            std::process::exit(1);
        });
    println!("\nFinal members ({} total):", final_members.members.len());
    for m in &final_members.members {
        println!(
            "  ordinal={} name='{}' type='{}' offset={} size={}",
            m.ordinal, m.name, m.member_type, m.offset, m.size
        );
    }

    // 8. Clean up: delete the struct
    let cleanup = client.delete_type(struct_name).unwrap_or_else(|e| {
        eprintln!("delete_type failed: {e}");
        std::process::exit(1);
    });
    println!(
        "\nCleaned up struct '{}' (deleted={})",
        struct_name, cleanup.deleted
    );
}
