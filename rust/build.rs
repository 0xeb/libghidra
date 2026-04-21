// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Build script: auto-regenerate Rust protobuf stubs when .proto files change.
//
// If protoc is available (via PROTOC env var or PATH), prost-build compiles
// the .proto files into OUT_DIR. Otherwise, falls back to the pre-generated
// stubs in generated/libghidra.rs.

use std::path::{Path, PathBuf};

fn main() {
    if std::env::var_os("PROTOC").is_none() {
        if let Ok(path) = protoc_bin_vendored::protoc_bin_path() {
            std::env::set_var("PROTOC", path);
        }
    }
    if std::env::var_os("PROTOC_INCLUDE").is_none() {
        if let Ok(path) = protoc_bin_vendored::include_path() {
            std::env::set_var("PROTOC_INCLUDE", path);
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_root = manifest_dir
        .parent() // rust -> libghidra
        .unwrap()
        .join("proto");
    let proto_dir = proto_root.join("libghidra");
    let fallback = manifest_dir.join("generated").join("libghidra.rs");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed={}", proto_dir.display());
    println!("cargo:rerun-if-changed={}", fallback.display());

    // Collect .proto files
    let protos: Vec<PathBuf> = std::fs::read_dir(&proto_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "proto"))
        .collect();

    if protos.is_empty() {
        // Proto dir not available (e.g., shallow checkout) — use fallback
        copy_fallback(&fallback, &out_dir);
        return;
    }

    let includes: &[PathBuf] = &[proto_root];

    let mut config = prost_build::Config::new();
    config.out_dir(&out_dir);

    match config.compile_protos(&protos, includes) {
        Ok(()) => {}
        Err(e) => {
            println!(
                "cargo:warning=prost-build failed ({}), using pre-generated stubs",
                e
            );
            copy_fallback(&fallback, &out_dir);
        }
    }
}

fn copy_fallback(fallback: &Path, out_dir: &Path) {
    let dest = out_dir.join("libghidra.rs");
    std::fs::copy(fallback, &dest).expect("failed to copy pre-generated stubs to OUT_DIR");
}
