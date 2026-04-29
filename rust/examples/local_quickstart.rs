// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// local_quickstart: open a binary in offline mode and decompile a function.
//
// Requires the `local` feature:
//   cargo run --features local --example local_quickstart -- <BINARY> <0xADDR>
//
// Mirrors python/examples/local_quickstart.py.

#[cfg(not(feature = "local"))]
fn main() {
    eprintln!(
        "this example requires the `local` feature: \
         cargo run --features local --example local_quickstart -- <binary> <0xaddr>"
    );
    std::process::exit(2);
}

#[cfg(feature = "local")]
fn main() {
    use libghidra::format_detect::detect_and_open;
    use libghidra::{local_with, LocalClientOptions};

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: local_quickstart <BINARY> <0xADDR>");
        std::process::exit(2);
    }
    let binary = &args[1];
    let address = parse_address(&args[2]).unwrap_or_else(|e| {
        eprintln!("could not parse address {:?}: {}", &args[2], e);
        std::process::exit(2);
    });

    let client = local_with(LocalClientOptions::auto()).unwrap_or_else(|e| {
        eprintln!("create LocalClient failed: {e}");
        std::process::exit(1);
    });

    // detect_and_open: parse the binary headers to pick a Sleigh language ID,
    // then call open_program for us. Returns the detection so we can print it.
    let detected = detect_and_open(&client, binary, None).unwrap_or_else(|e| {
        eprintln!("detect_and_open failed: {e}");
        std::process::exit(1);
    });
    println!(
        "Loaded {} ({}, {}-bit {}, language={})",
        binary, detected.format, detected.bits, detected.endian, detected.language_id
    );

    // Decompile the function at the requested address.
    let resp = client.get_decompilation(address, 30_000).unwrap_or_else(|e| {
        eprintln!("get_decompilation failed: {e}");
        std::process::exit(1);
    });

    let Some(d) = resp.decompilation else {
        eprintln!("no decompilation returned for 0x{:x}", address);
        std::process::exit(1);
    };

    println!("\n--- {} @ 0x{:x} ---", d.function_name, d.function_entry_address);
    if d.pseudocode.is_empty() {
        eprintln!("(empty pseudocode; error_message: {})", d.error_message);
        std::process::exit(1);
    }
    println!("{}", d.pseudocode);
}

#[cfg(feature = "local")]
fn parse_address(s: &str) -> Result<u64, std::num::ParseIntError> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16)
    } else {
        s.parse::<u64>()
    }
}
