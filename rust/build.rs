// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Build script.
//
// Always:
//   - Regenerate Rust protobuf stubs via prost-build, falling back to the
//     pre-generated stubs in `generated/libghidra.rs` when protoc is
//     unavailable.
//
// When the `local` feature is enabled (CARGO_FEATURE_LOCAL is set):
//   - Compile the cxx FFI bridge in `cpp/bindings/rust_bridge.cpp`,
//     linking against the C++ libghidra engine.
//   - Look for headers and static libs via either:
//       LIBGHIDRA_PREBUILT_DIR  (single root with include/ and lib/)
//     or:
//       LIBGHIDRA_INCLUDE_DIR + LIBGHIDRA_LIB_DIR (set separately)
//   - Emit `cargo:rustc-link-lib=...` directives for the engine and its
//     transitive dependencies.
//   - When env vars aren't set, emit a `cargo:warning` and skip the C++
//     build. `cargo check` still succeeds; `cargo build` will fail at
//     link time with unresolved symbols.

use std::path::{Path, PathBuf};

fn main() {
    build_proto();
    build_local_bridge();
}

// ---------------------------------------------------------------------------
// Always-on: protobuf stubs for the live (HTTP) backend
// ---------------------------------------------------------------------------

fn build_proto() {
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

    let protos: Vec<PathBuf> = std::fs::read_dir(&proto_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "proto"))
        .collect();

    if protos.is_empty() {
        copy_fallback(&fallback, &out_dir);
        return;
    }

    let includes: &[PathBuf] = &[proto_root];

    let mut config = prost_build::Config::new();
    let _ = config.out_dir(&out_dir);

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

// ---------------------------------------------------------------------------
// Conditional: cxx FFI bridge for the `local` (offline) backend
// ---------------------------------------------------------------------------

fn build_local_bridge() {
    if std::env::var_os("CARGO_FEATURE_LOCAL").is_none() {
        return;
    }

    println!("cargo:rerun-if-env-changed=LIBGHIDRA_PREBUILT_DIR");
    println!("cargo:rerun-if-env-changed=LIBGHIDRA_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=LIBGHIDRA_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LIBGHIDRA_LINK_LIBS");
    println!("cargo:rerun-if-env-changed=LIBGHIDRA_NO_LINK");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cpp_root = manifest_dir.parent().unwrap().join("cpp");
    let bridge_cpp = cpp_root.join("bindings").join("rust_bridge.cpp");
    let bridge_hpp = cpp_root
        .join("bindings")
        .join("include")
        .join("libghidra")
        .join("rust_bridge.hpp");
    let bindings_inc = cpp_root.join("bindings").join("include");
    let public_inc = cpp_root.join("include");

    println!("cargo:rerun-if-changed={}", bridge_cpp.display());
    println!("cargo:rerun-if-changed={}", bridge_hpp.display());

    // Resolve include and library locations.
    let prebuilt = std::env::var("LIBGHIDRA_PREBUILT_DIR").ok();
    let extra_include = std::env::var("LIBGHIDRA_INCLUDE_DIR")
        .ok()
        .or_else(|| prebuilt.as_deref().map(|d| format!("{}/include", d)));
    let lib_dir = std::env::var("LIBGHIDRA_LIB_DIR")
        .ok()
        .or_else(|| prebuilt.as_deref().map(|d| format!("{}/lib", d)));

    let no_link = std::env::var_os("LIBGHIDRA_NO_LINK").is_some();

    let Some(extra_include) = extra_include else {
        println!(
            "cargo:warning=libghidra `local` feature is enabled but \
             neither LIBGHIDRA_PREBUILT_DIR nor LIBGHIDRA_INCLUDE_DIR is set; \
             skipping C++ bridge build. `cargo check` will pass but `cargo \
             build`/`cargo test` will fail at link time with unresolved symbols. \
             See rust/README.md for setup instructions."
        );
        return;
    };

    // Compile the cxx bridge into a static archive.
    let mut build = cxx_build::bridge("src/local_ffi.rs");
    let _ = build
        .file(&bridge_cpp)
        .include(&bindings_inc)
        .include(&public_inc)
        .include(&extra_include)
        .std("c++20")
        .flag_if_supported("/EHsc")
        .flag_if_supported("/std:c++20")
        .warnings(false);

    if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build.compile("libghidra_rust_bridge");
    })) {
        println!(
            "cargo:warning=cxx_build failed for libghidra rust bridge: {:?}. \
             Make sure LIBGHIDRA_PREBUILT_DIR points at a libghidra SDK with \
             headers under include/ and static libs under lib/.",
            e
        );
        return;
    }

    if no_link {
        // User opted out of linker directives (e.g. they're staging a custom
        // link line). The cxx bridge compiled but the final binary will only
        // link if they emit their own -l directives.
        return;
    }

    // Library search path.
    if let Some(dir) = lib_dir.as_deref() {
        println!("cargo:rustc-link-search=native={}", dir);
    } else {
        println!(
            "cargo:warning=LIBGHIDRA_LIB_DIR / LIBGHIDRA_PREBUILT_DIR not set; \
             cxx bridge compiled but no library search path emitted. Set \
             LIBGHIDRA_LIB_DIR before linking."
        );
    }

    // On Debian/Ubuntu the system protobuf-lite static archive lives under
    // /usr/lib/<multiarch-triple>/, which rustc does not search by default.
    // Resolve the triple via `gcc -print-multiarch` so this works on every
    // multi-arch system without a hardcoded list.
    let target_os_for_multiarch = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os_for_multiarch == "linux" {
        if let Ok(out) = std::process::Command::new("gcc")
            .arg("-print-multiarch")
            .output()
        {
            if out.status.success() {
                if let Ok(triple) = std::str::from_utf8(&out.stdout) {
                    let triple = triple.trim();
                    if !triple.is_empty() {
                        println!("cargo:rustc-link-search=native=/usr/lib/{}", triple);
                    }
                }
            }
        }
    }
    // Allow users to inject extra search paths (e.g. for Homebrew protobuf
    // on macOS) without hand-editing build.rs. Colon-separated.
    if let Ok(extra) = std::env::var("LIBGHIDRA_EXTRA_LIB_PATHS") {
        for p in extra.split(':').filter(|s| !s.is_empty()) {
            println!("cargo:rustc-link-search=native={}", p);
        }
    }
    println!("cargo:rerun-if-env-changed=LIBGHIDRA_EXTRA_LIB_PATHS");

    // Library list. Default mirrors what the Python wheel CI links against.
    //
    // We have to walk a fine line here. rustc's `-l static=foo` directive
    // SHOULD locate `libfoo.a` in the search paths and pass it to the
    // linker — but in practice, with our setup, rustc silently dropped
    // every `static=` directive except the one with `+whole-archive` on
    // it (observed on aarch64 with rustc 1.95). Symptoms: the cc
    // invocation contained `liblibghidra_local.a` but neither
    // `liblibghidra_client.a` nor `libbfd.a` despite both being declared.
    // To sidestep that quirk, we pass static libs as raw linker arguments
    // (`-Wl,-Bstatic`, `-Wl,/abs/path/to/lib.a`) which the linker can't
    // ignore. Dynamic libs still go through rustc-link-lib so the search-
    // path resolution + --as-needed handling works as expected.
    //
    // `+whole-archive` is required for libghidra_local: Ghidra's
    // ArchitectureCapability and loader code register themselves via
    // static initializers, and libbfd-using objects (loadimage_bfd,
    // bfd_arch, etc.) are otherwise dropped because the cxx bridge
    // doesn't directly reference their symbols.
    if let Some(lib_dir_str) = lib_dir.as_deref() {
        let abs = |stem: &str| format!("{}/lib{}.a", lib_dir_str, stem);

        // cargo:rustc-link-arg=ARG places ARG at the END of the cc command,
        // AFTER the rustc-link-lib dylibs. With ld's default --as-needed
        // behaviour, libm/libstdc++ would be dropped (no unresolved symbols
        // by the time they're scanned) and only the static archives that
        // come after them surface refs to sqrt etc., yielding "DSO missing
        // from command line". Wrap the whole static-archive group in
        // --push-state/--no-as-needed plus a redundant -lm/-lstdc++ so
        // those DSOs stay alive long enough to satisfy the archives.
        println!("cargo:rustc-link-arg=-Wl,--push-state");
        println!("cargo:rustc-link-arg=-Wl,--no-as-needed");

        // Whole-archive: pull in every .o so static initializers and the
        // loader code survive the linker's --gc-sections.
        if std::path::Path::new(&abs("libghidra_local")).exists() {
            println!("cargo:rustc-link-arg=-Wl,--whole-archive");
            println!("cargo:rustc-link-arg=-Wl,{}", abs("libghidra_local"));
            println!("cargo:rustc-link-arg=-Wl,--no-whole-archive");
        }

        // Other libghidra archives + bundled libbfd/libiberty/etc. as
        // explicit `-Wl,/abs/path/to/lib.a` so they're not silently dropped.
        for stem in &["libghidra_client", "bfd", "iberty", "sframe", "zstd"] {
            let path = abs(stem);
            if std::path::Path::new(&path).exists() {
                println!("cargo:rustc-link-arg=-Wl,{}", path);
            }
        }

        // Re-list dynamic deps after the static archives so their unresolved
        // symbols actually find homes — the earlier -l<name> before the
        // archives get dropped by --as-needed since at that point nothing
        // refers to them yet. Specifically:
        //   sqrt           (libghidra_local::float.cc)         -> libm
        //   __stack_chk_*  (libbfd built with -fstack-protector)-> libc
        //   __aarch64_*    (libgcc atomic builtins)             -> libgcc_s
        //   compress*      (libbfd compressed-section handling) -> libz
        for lib in &["m", "c", "gcc_s", "z"] {
            println!("cargo:rustc-link-arg=-l{}", lib);
        }

        // glibc ≥ 2.36 (Debian bookworm+, Ubuntu 24.04+, Fedora 36+) moved
        // __stack_chk_guard from libc.so.6 to ld-linux.so (the ELF
        // interpreter). When a source-built libiberty.a / libbfd.a was
        // compiled with -fstack-protector-strong, the linker errors with
        // "DSO missing from command line" unless ld-linux.so is on the
        // command line explicitly. Emit it here. Harmless on older glibc
        // (manylinux 2.28 ≈ glibc 2.28) where the symbol is still in libc.
        // Only attempt when build host is Linux — readelf+/proc/self/exe is
        // Linux-only.
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
            if let Some(interp) = elf_interpreter() {
                println!("cargo:rustc-link-arg={}", interp);
            }
        }

        println!("cargo:rustc-link-arg=-Wl,--pop-state");

        // libbfd ≥ 2.38 references libzstd for ELF section decompression.
        // Outside --no-as-needed so ld drops -lzstd cleanly when bfd was
        // built without zstd support (manylinux_2_28's bfd ~2.30 does not
        // reference it). libzstd.so is universally available on Linux
        // distros shipping our prebuilt archive; on the rare host without
        // it, the user gets a clear "cannot find -lzstd" — solvable by
        // installing libzstd-dev / zstd-devel.
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
            println!("cargo:rustc-link-arg=-lzstd");
        }
    } else {
        // No prebuilt-dir: fall back to rustc-link-lib so a hand-built SDK
        // with -L set externally still resolves through rustc's normal path.
        println!("cargo:rustc-link-lib=static:+whole-archive=libghidra_local");
        println!("cargo:rustc-link-lib=static=libghidra_client");
    }

    // Dynamic deps still go through rustc-link-lib (search-path-aware).
    // Order matters with --as-needed: libs that satisfy unresolved symbols
    // from the static archives above must come first. libm is listed early
    // because libghidra_local.a's float.cc references sqrt; libstdc++
    // pulls libm.so.6 implicitly but ld errors out with "DSO missing from
    // command line" unless we also list it explicitly.
    let dylibs = std::env::var("LIBGHIDRA_LINK_DYLIBS")
        .unwrap_or_else(|_| "m,protobuf-lite,z".to_string());
    for lib in dylibs.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        println!("cargo:rustc-link-lib=dylib={}", lib);
    }
    println!("cargo:rerun-if-env-changed=LIBGHIDRA_LINK_DYLIBS");

    // Platform-specific runtime deps (libbfd / libiberty are handled above
    // via the explicit -Wl,/abs/path/to/lib.a route when the prebuilt
    // archive bundles them; otherwise we fall back to system libbfd here).
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let bundled_bfd = lib_dir
        .as_deref()
        .map(|d| std::path::Path::new(&format!("{}/libbfd.a", d)).exists())
        .unwrap_or(false);
    match target_os.as_str() {
        "linux" => {
            if !bundled_bfd {
                // No bundled libbfd.a in the SDK — link the system libbfd.so.
                // Note: this exposes the user to bfd ABI shifts between
                // binutils versions; bundling is preferred (CI does this on
                // the linux-* matrix).
                println!("cargo:rustc-link-lib=dylib=bfd");
            }
            println!("cargo:rustc-link-lib=dylib=dl");
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=stdc++");
        }
        "macos" => {
            println!("cargo:rustc-link-lib=dylib=c++");
        }
        "windows" => {
            println!("cargo:rustc-link-lib=dylib=ws2_32");
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Helper: read the ELF interpreter (ld-linux.so) of the build host process.
//
// On glibc ≥ 2.36 (Debian bookworm+, Ubuntu 24.04+, Fedora 36+),
// `__stack_chk_guard` moved out of libc.so.6 into ld-linux.so. A
// source-built libiberty.a or libbfd.a compiled with
// -fstack-protector-strong references that symbol, and GNU ld errors with
// "DSO missing from command line" unless ld-linux.so is on the command
// line explicitly. We resolve the path by parsing `readelf -l` of the
// running build process — same interpreter the resulting binary will
// use when build host == target host.
// ---------------------------------------------------------------------------
fn elf_interpreter() -> Option<String> {
    let out = std::process::Command::new("readelf")
        .args(["-l", "/proc/self/exe"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = std::str::from_utf8(&out.stdout).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.split("Requesting program interpreter:").nth(1) {
            let path = rest.trim().trim_end_matches(']').trim().to_string();
            if !path.is_empty() && std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }
    }
    None
}
