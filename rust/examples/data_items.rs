// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// data_items: Apply data types, list data items, rename, and delete.
//
// Usage: data_items [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. Find a memory block to get a valid address range
    let blocks = match client.list_memory_blocks(10, 0) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ListMemoryBlocks failed (is a program open?): {e}");
            std::process::exit(1);
        }
    };

    let block = match blocks.blocks.first() {
        Some(b) => b,
        None => {
            eprintln!("No memory blocks found.");
            std::process::exit(1);
        }
    };

    // Pick an address a bit into the block to avoid header conflicts
    let base = block.start_address + 0x40;
    println!("Using address 0x{:08x} in block '{}'.\n", base, block.name);

    // 2. Apply a data type at the chosen address
    println!("Applying 'dword' data type at 0x{:08x}...", base);
    let apply = client.apply_data_type(base, "dword").unwrap_or_else(|e| {
        eprintln!("ApplyDataType failed: {e}");
        std::process::exit(1);
    });
    println!(
        "  updated={}, data_type=\"{}\"",
        apply.updated, apply.data_type
    );

    // 3. Apply another data type nearby
    let addr2 = base + 0x10;
    println!("Applying 'byte[8]' at 0x{:08x}...", addr2);
    let apply2 = client
        .apply_data_type(addr2, "byte[8]")
        .unwrap_or_else(|e| {
            eprintln!("ApplyDataType failed: {e}");
            std::process::exit(1);
        });
    println!(
        "  updated={}, data_type=\"{}\"",
        apply2.updated, apply2.data_type
    );

    // 4. List data items in the range
    let items = client
        .list_data_items(base, base + 0x100, 50, 0)
        .unwrap_or_else(|e| {
            eprintln!("ListDataItems failed: {e}");
            std::process::exit(1);
        });

    println!("\nData items in range ({} found):", items.data_items.len());
    for d in &items.data_items {
        println!(
            "  0x{:08x}  {:<20} type={:<12} size={} value=\"{}\"",
            d.address, d.name, d.data_type, d.size, d.value_repr
        );
    }

    // 5. Rename the first data item we created
    println!("\nRenaming data item at 0x{:08x}...", base);
    let rename = client
        .rename_data_item(base, "my_config_dword")
        .unwrap_or_else(|e| {
            eprintln!("RenameDataItem failed: {e}");
            std::process::exit(1);
        });
    println!("  updated={}, new name=\"{}\"", rename.updated, rename.name);

    // 6. Verify the rename
    let after_rename = client.list_data_items(base, base + 0x08, 10, 0).unwrap();
    for d in &after_rename.data_items {
        println!(
            "  0x{:08x}  name=\"{}\"  type={}",
            d.address, d.name, d.data_type
        );
    }

    // 7. Delete the second data item
    println!("\nDeleting data item at 0x{:08x}...", addr2);
    let del = client.delete_data_item(addr2).unwrap_or_else(|e| {
        eprintln!("DeleteDataItem failed: {e}");
        std::process::exit(1);
    });
    println!("  deleted={}", del.deleted);

    // 8. Delete the first one too (clean up)
    println!("Deleting data item at 0x{:08x}...", base);
    let del2 = client.delete_data_item(base).unwrap();
    println!("  deleted={}", del2.deleted);

    // 9. Final listing to confirm cleanup
    let final_items = client.list_data_items(base, base + 0x100, 50, 0).unwrap();
    println!(
        "\nData items remaining in range: {}",
        final_items.data_items.len()
    );

    println!("\nDone.");
}
