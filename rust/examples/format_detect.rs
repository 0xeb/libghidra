// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// format_detect: identify the binary format and Sleigh language ID for one
// or more files without opening them. Pure-Rust; no live or local feature
// required.
//
// Usage: cargo run --example format_detect -- <FILE> [<FILE>...]

use libghidra::format_detect::detect;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: format_detect <FILE> [<FILE>...]");
        std::process::exit(2);
    }

    let mut had_error = false;
    for path in &args {
        match detect(path) {
            Ok(d) => {
                println!(
                    "{}\n  format       = {}\n  language_id  = {}\n  compiler     = {}\n  bits         = {}\n  endian       = {}\n  machine      = {}{}{}",
                    path,
                    d.format,
                    d.language_id,
                    d.compiler_spec_id,
                    d.bits,
                    d.endian,
                    d.machine,
                    d.base_address
                        .map(|b| format!("\n  base_address = 0x{:x}", b))
                        .unwrap_or_default(),
                    if d.warnings.is_empty() {
                        String::new()
                    } else {
                        format!("\n  warnings     = {:?}", d.warnings)
                    }
                );
            }
            Err(e) => {
                eprintln!("{}: {}", path, e);
                had_error = true;
            }
        }
    }
    if had_error {
        std::process::exit(1);
    }
}
