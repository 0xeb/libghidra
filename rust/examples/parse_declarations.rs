// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// parse_declarations: Import C type declarations, verify, clean up.
//
// Usage: parse_declarations [host_url]

use libghidra as ghidra;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map_or("http://127.0.0.1:18080", |s| s.as_str());
    let client = ghidra::connect(url);

    // 1. Parse a block of C declarations
    let decls = r#"
typedef enum ExampleOpcode {
    OP_NONE = 0,
    OP_INIT = 1,
    OP_PROCESS = 2,
    OP_SHUTDOWN = 3
} ExampleOpcode;

typedef struct ExampleHeader {
    int magic;
    int version;
    int flags;
} ExampleHeader;

typedef struct ExamplePacket {
    ExampleHeader header;
    ExampleOpcode opcode;
    int payload_size;
} ExamplePacket;
"#;

    println!("--- Parsing C declarations ---");
    let result = client.parse_declarations(decls).unwrap_or_else(|e| {
        eprintln!("parse_declarations failed: {e}");
        std::process::exit(1);
    });
    println!("Types created: {}", result.types_created);
    for name in &result.type_names {
        println!("  + {name}");
    }
    if !result.errors.is_empty() {
        println!("Errors:");
        for err in &result.errors {
            println!("  ! {err}");
        }
    }

    // 2. Verify the types exist in the type system
    println!("\n--- Verifying types ---");
    let check_names = ["/ExampleOpcode", "/ExampleHeader", "/ExamplePacket"];
    for name in &check_names {
        match client.get_type(name) {
            Ok(resp) => {
                if let Some(t) = &resp.r#type {
                    println!("  {name}: kind={} length={}", t.kind, t.length);
                } else {
                    println!("  {name}: NOT FOUND");
                }
            }
            Err(_) => println!("  {name}: NOT FOUND"),
        }
    }

    // 3. Clean up: delete the types we created
    println!("\n--- Cleanup ---");
    for name in check_names.iter().rev() {
        let _ = client.delete_type(name);
    }
    println!("  Deleted all example types");
}
