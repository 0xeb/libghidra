// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// type_system: Browse types, create structs, aliases, enums, and clean up.
//
// Usage: type_system [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. List existing types (first page)
    let types = match client.list_types("", 15, 0) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ListTypes failed (is a program open?): {e}");
            std::process::exit(1);
        }
    };

    println!("Types ({} shown):", types.types.len());
    for t in &types.types {
        println!(
            "  {:<30} kind={:<10} len={:<4} path={}",
            t.name, t.kind, t.length, t.path_name
        );
    }

    // 2. Search for a specific built-in type
    println!("\nSearching for 'int' types...");
    let int_types = client.list_types("int", 10, 0).unwrap();
    for t in &int_types.types {
        println!("  {:<20} kind={}", t.name, t.kind);
    }

    // 3. Get details for a specific type
    if let Some(first) = types.types.first() {
        let detail = client.get_type(&first.path_name).unwrap_or_else(|e| {
            eprintln!("GetType failed: {e}");
            std::process::exit(1);
        });
        if let Some(t) = &detail.r#type {
            println!("\nType detail for '{}':", t.name);
            println!("  ID:       {}", t.type_id);
            println!("  Path:     {}", t.path_name);
            println!("  Category: {}", t.category_path);
            println!("  Display:  {}", t.display_name);
            println!("  Kind:     {}", t.kind);
            println!("  Length:   {}", t.length);
        }
    }

    // 4. Create a new struct type
    let struct_name = "RustExampleStruct";
    println!("\nCreating struct '{}'...", struct_name);
    let create = client
        .create_type(struct_name, "struct", 16)
        .unwrap_or_else(|e| {
            eprintln!("CreateType failed: {e}");
            std::process::exit(1);
        });
    println!("  updated={}", create.updated);

    // 5. Verify the struct exists
    let search = client.list_types(struct_name, 5, 0).unwrap();
    println!(
        "  Found {} type(s) matching '{}'",
        search.types.len(),
        struct_name
    );

    // 6. Create a type alias pointing to our struct
    let alias_name = "RustExampleAlias";
    println!("\nCreating alias '{}' -> '{}'...", alias_name, struct_name);
    let alias = client
        .create_type_alias(alias_name, struct_name)
        .unwrap_or_else(|e| {
            eprintln!("CreateTypeAlias failed: {e}");
            std::process::exit(1);
        });
    println!("  updated={}", alias.updated);

    // 7. List aliases to verify
    let aliases = client.list_type_aliases(alias_name, 5, 0).unwrap();
    println!(
        "  Aliases matching '{}': {}",
        alias_name,
        aliases.aliases.len()
    );

    // 8. Create an enum type
    let enum_name = "RustExampleEnum";
    println!("\nCreating enum '{}' (width=4, signed=false)...", enum_name);
    let enu = client
        .create_type_enum(enum_name, 4, false)
        .unwrap_or_else(|e| {
            eprintln!("CreateTypeEnum failed: {e}");
            std::process::exit(1);
        });
    println!("  updated={}", enu.updated);

    // 9. Rename the struct
    let new_struct_name = "RustExampleStructRenamed";
    println!("\nRenaming '{}' -> '{}'...", struct_name, new_struct_name);
    let rn = client
        .rename_type(struct_name, new_struct_name)
        .unwrap_or_else(|e| {
            eprintln!("RenameType failed: {e}");
            std::process::exit(1);
        });
    println!("  updated={}, name=\"{}\"", rn.updated, rn.name);

    // 10. Clean up: delete everything we created
    println!("\nCleaning up...");

    let del_alias = client.delete_type_alias(alias_name);
    println!(
        "  Delete alias '{}': {}",
        alias_name,
        match &del_alias {
            Ok(d) => format!("deleted={}", d.deleted),
            Err(e) => format!("error={e}"),
        }
    );

    let del_enum = client.delete_type_enum(enum_name);
    println!(
        "  Delete enum '{}': {}",
        enum_name,
        match &del_enum {
            Ok(d) => format!("deleted={}", d.deleted),
            Err(e) => format!("error={e}"),
        }
    );

    let del_struct = client.delete_type(new_struct_name);
    println!(
        "  Delete struct '{}': {}",
        new_struct_name,
        match &del_struct {
            Ok(d) => format!("deleted={}", d.deleted),
            Err(e) => format!("error={e}"),
        }
    );

    // 11. Confirm cleanup
    let final_check = client.list_types("RustExample", 10, 0).unwrap();
    println!(
        "\nTypes matching 'RustExample' after cleanup: {}",
        final_check.types.len()
    );

    println!("\nDone.");
}
