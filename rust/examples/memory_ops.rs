// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// memory_ops: Memory block inspection, byte reads, writes, and batch patching.
//
// Usage: memory_ops [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. List memory blocks
    let blocks = match client.list_memory_blocks(50, 0) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ListMemoryBlocks failed (is a program open?): {e}");
            std::process::exit(1);
        }
    };

    println!("Memory blocks ({}):", blocks.blocks.len());
    for blk in &blocks.blocks {
        println!(
            "  {:<16} 0x{:08x}..0x{:08x}  size={:<8} R={} W={} X={}",
            blk.name,
            blk.start_address,
            blk.end_address,
            blk.size,
            blk.is_read as u8,
            blk.is_write as u8,
            blk.is_execute as u8,
        );
    }

    // 2. Read the first 64 bytes from the first block
    let first = match blocks.blocks.first() {
        Some(b) => b,
        None => {
            eprintln!("No memory blocks found.");
            std::process::exit(1);
        }
    };

    let read_len: u32 = std::cmp::min(64, first.size as u32);
    let read = client
        .read_bytes(first.start_address, read_len)
        .unwrap_or_else(|e| {
            eprintln!("ReadBytes failed: {e}");
            std::process::exit(1);
        });

    println!(
        "\nFirst {} bytes of '{}' at 0x{:08x}:",
        read.data.len(),
        first.name,
        first.start_address
    );
    hex_dump(&read.data, first.start_address);

    // 3. Write a small marker (4 bytes) at the block start
    let marker: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let write = client
        .write_bytes(first.start_address, &marker)
        .unwrap_or_else(|e| {
            eprintln!("WriteBytes failed: {e}");
            std::process::exit(1);
        });
    println!(
        "\nWriteBytes: {} bytes written at 0x{:08x}",
        write.bytes_written, first.start_address
    );

    // 4. Verify the write by reading back
    let verify = client.read_bytes(first.start_address, 4).unwrap();
    println!("Read-back after write:");
    hex_dump(&verify.data, first.start_address);

    // 5. Batch-patch two locations: start+8 and start+16
    let patches = vec![
        ghidra::BytePatch {
            address: first.start_address + 8,
            data: vec![0xCA, 0xFE],
        },
        ghidra::BytePatch {
            address: first.start_address + 16,
            data: vec![0xBA, 0xBE],
        },
    ];
    let batch = client.patch_bytes_batch(&patches).unwrap_or_else(|e| {
        eprintln!("PatchBytesBatch failed: {e}");
        std::process::exit(1);
    });
    println!(
        "\nPatchBytesBatch: {} patches, {} bytes written",
        batch.patch_count, batch.bytes_written
    );

    // 6. Final read to see all modifications
    let final_read = client.read_bytes(first.start_address, 32).unwrap();
    println!("\nFinal state (first 32 bytes):");
    hex_dump(&final_read.data, first.start_address);
}

/// Print a classic hex dump: offset, hex bytes, ASCII.
fn hex_dump(data: &[u8], base: u64) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base + (i * 16) as u64;
        print!("  {:08x}  ", addr);
        for (j, &b) in chunk.iter().enumerate() {
            if j == 8 {
                print!(" ");
            }
            print!("{:02x} ", b);
        }
        // Pad if less than 16 bytes
        for j in chunk.len()..16 {
            if j == 8 {
                print!(" ");
            }
            print!("   ");
        }
        print!(" |");
        for &b in chunk {
            let c = if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            };
            print!("{c}");
        }
        println!("|");
    }
}
