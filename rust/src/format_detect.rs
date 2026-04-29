// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Pure-Rust port of `python/src/libghidra/format_detect.py`. Identifies
// the binary format (PE / ELF / Mach-O / fat Mach-O / raw) and maps the
// header to a Sleigh language ID + compiler spec ID.
//
// No external parser dependencies (no `goblin`, no `object`) — keeps the
// crate small and matches the Python module's hand-rolled minimal-header
// parsing. The fields read here are the same ones the Python tests
// synthesize; richer parsing (full PE optional header, ELF program
// headers, etc.) is intentionally out of scope.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::{Error, ErrorCode, Result};
use crate::models::OpenProgramRequest;

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Result of binary format and language detection. Mirrors
/// `DetectedBinary` in `format_detect.py`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectedBinary {
    /// "pe", "elf", "macho", "macho-fat", or "raw".
    pub format: String,
    /// Sleigh language ID, e.g. `"x86:LE:64:default"`.
    pub language_id: String,
    /// Default compiler spec ID for the format/architecture.
    pub compiler_spec_id: String,
    /// Address bus width.
    pub bits: u32,
    /// "LE" or "BE".
    pub endian: String,
    /// Human-readable architecture name (e.g. "AArch64", "x86_64").
    pub machine: String,
    /// Image base when the format reports one (PE), else `None`.
    pub base_address: Option<u64>,
    /// Non-fatal advisories (e.g. fat Mach-O slices skipped).
    pub warnings: Vec<String>,
}

/// Detection failure. Mirrors `FormatDetectError` and `UnsupportedFormatError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedFormatError(pub String);

impl std::fmt::Display for UnsupportedFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UnsupportedFormatError {}

impl From<UnsupportedFormatError> for Error {
    fn from(e: UnsupportedFormatError) -> Self {
        Error::new(ErrorCode::NotSupported, e.0)
    }
}

/// Detect format and language from a file on disk.
pub fn detect(path: impl AsRef<Path>) -> Result<DetectedBinary> {
    let mut f = File::open(path.as_ref())
        .map_err(|e| Error::new(ErrorCode::ConfigError, format!("{}: {}", path.as_ref().display(), e)))?;
    let mut buf = Vec::new();
    let _ = f
        .read_to_end(&mut buf)
        .map_err(|e| Error::new(ErrorCode::ConfigError, e.to_string()))?;
    detect_bytes(&buf)
}

/// Detect format and language from a byte slice.
pub fn detect_bytes(data: &[u8]) -> Result<DetectedBinary> {
    detect_buffer(data).map_err(Into::into)
}

/// Trait implemented by anything that can `open_program`. Lets
/// `detect_and_open` work with both `LocalClient` and `GhidraClient`
/// without introducing a hard cross-module dependency.
pub trait OpenProgram {
    type Output;
    fn open_program(&self, req: OpenProgramRequest) -> Result<Self::Output>;
}

/// Detect a binary, then open it via `client.open_program(...)`. Returns
/// the detection (with `compiler_spec_id` overridden if the caller passed
/// `Some(_)`). Mirrors `detect_and_open` in `format_detect.py`.
pub fn detect_and_open<C: OpenProgram>(
    client: &C,
    path: impl AsRef<Path>,
    compiler_spec_id: Option<&str>,
) -> Result<DetectedBinary> {
    let detected = detect(path.as_ref())?;
    let compiler = compiler_spec_id
        .map(|s| s.to_string())
        .unwrap_or_else(|| detected.compiler_spec_id.clone());

    let req = OpenProgramRequest {
        program_path: path.as_ref().to_string_lossy().into_owned(),
        language_id: detected.language_id.clone(),
        compiler_spec_id: compiler.clone(),
        format: detected.format.clone(),
        base_address: detected.base_address.unwrap_or(0),
        ..Default::default()
    };
    let _ = client.open_program(req)?;

    if compiler == detected.compiler_spec_id {
        Ok(detected)
    } else {
        Ok(DetectedBinary {
            compiler_spec_id: compiler,
            ..detected
        })
    }
}

// ---------------------------------------------------------------------------
// Internals — header dispatch
// ---------------------------------------------------------------------------

const RAW_LANGUAGE_ID: &str = "DATA:LE:64:default";
const RAW_COMPILER_SPEC_ID: &str = "pointer64";

const FAT_MAGIC: &[[u8; 4]] = &[
    [0xca, 0xfe, 0xba, 0xbe],
    [0xbe, 0xba, 0xfe, 0xca],
    [0xca, 0xfe, 0xba, 0xbf],
    [0xbf, 0xba, 0xfe, 0xca],
];

const MACHO_MAGIC: &[[u8; 4]] = &[
    [0xfe, 0xed, 0xfa, 0xce],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xce, 0xfa, 0xed, 0xfe],
    [0xcf, 0xfa, 0xed, 0xfe],
];

fn detect_buffer(data: &[u8]) -> std::result::Result<DetectedBinary, UnsupportedFormatError> {
    if data.len() < 4 {
        return Err(UnsupportedFormatError(
            "file is too small to identify a binary format".into(),
        ));
    }

    if data.starts_with(b"MZ") {
        return detect_pe(data);
    }
    if data.starts_with(b"\x7fELF") {
        return detect_elf(data);
    }
    let head = &data[..4];
    if FAT_MAGIC.iter().any(|m| head == m) {
        return detect_fat_macho(data);
    }
    if MACHO_MAGIC.iter().any(|m| head == m) {
        return detect_macho(data);
    }

    validated(DetectedBinary {
        format: "raw".into(),
        language_id: RAW_LANGUAGE_ID.into(),
        compiler_spec_id: RAW_COMPILER_SPEC_ID.into(),
        bits: 64,
        endian: "LE".into(),
        machine: "raw-data".into(),
        base_address: None,
        warnings: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// PE (Windows / EFI)
// ---------------------------------------------------------------------------

/// PE machine code → (Sleigh ID, default compiler, machine name).
/// Mirrors `_PE_MACHINE_MAP` in `format_detect.py`.
fn pe_lookup(machine: u16) -> Option<(&'static str, &'static str, &'static str)> {
    match machine {
        0x014C => Some(("x86:LE:32:default", "windows", "x86")),
        0x8664 => Some(("x86:LE:64:default", "windows", "x86_64")),
        0x01C0 => Some(("ARM:LE:32:v8", "windows", "ARM")),
        0x01C4 => Some(("ARM:LE:32:v8", "windows", "ARMNT")),
        0xAA64 => Some(("AARCH64:LE:64:v8A", "windows", "ARM64")),
        _ => None,
    }
}

fn detect_pe(data: &[u8]) -> std::result::Result<DetectedBinary, UnsupportedFormatError> {
    if data.len() < 0x40 {
        return Err(UnsupportedFormatError(
            "unsupported PE file: truncated MS-DOS stub".into(),
        ));
    }
    let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if data.len() < pe_offset + 0x18 || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(UnsupportedFormatError(
            "unsupported PE file: bad PE signature".into(),
        ));
    }
    let machine_off = pe_offset + 4;
    let machine = u16::from_le_bytes([data[machine_off], data[machine_off + 1]]);
    let Some((language_id, compiler, machine_name)) = pe_lookup(machine) else {
        return Err(UnsupportedFormatError(format!(
            "unsupported PE machine 0x{:04x}",
            machine
        )));
    };

    // Optional header begins at pe_offset + 0x18 + 4 = pe_offset + 0x18 (this is
    // the size_of_optional_header offset is at +0x14; the optional header itself
    // starts after the COFF FILE_HEADER which is 0x18 bytes incl. the PE sig).
    // Magic at +0x18 from PE sig, ImageBase at +0x18 + 0x18 = +0x30 for PE32+.
    let opt_off = pe_offset + 0x18;
    let mut base_address: Option<u64> = None;
    if data.len() >= opt_off + 0x20 {
        let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
        if magic == 0x20B && data.len() >= opt_off + 0x20 {
            // PE32+ : ImageBase is u64 at opt_off + 0x18.
            let ib_off = opt_off + 0x18;
            base_address = Some(u64::from_le_bytes(
                data[ib_off..ib_off + 8].try_into().unwrap(),
            ));
        } else if magic == 0x10B && data.len() >= opt_off + 0x20 {
            // PE32 : ImageBase is u32 at opt_off + 0x1C.
            let ib_off = opt_off + 0x1C;
            base_address = Some(
                u32::from_le_bytes(data[ib_off..ib_off + 4].try_into().unwrap()) as u64,
            );
        }
    }

    validated(DetectedBinary {
        format: "pe".into(),
        language_id: language_id.into(),
        compiler_spec_id: compiler.into(),
        bits: bits_from_language(language_id),
        endian: "LE".into(),
        machine: machine_name.into(),
        base_address,
        warnings: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

/// ELF e_machine → (architecture family, uses_class_bits, machine name).
/// Mirrors `_ELF_MACHINE_MAP` in `format_detect.py`. `uses_class_bits=true`
/// means the address size comes from EI_CLASS; otherwise the architecture
/// name implies it (ARM=32, AARCH64=64).
fn elf_machine_lookup(e_machine: u16) -> Option<(&'static str, bool, &'static str)> {
    match e_machine {
        3 => Some(("x86", true, "Intel 80386")),
        8 => Some(("MIPS", true, "MIPS")),
        20 => Some(("PowerPC", true, "PowerPC")),
        40 => Some(("ARM", false, "ARM")),
        62 => Some(("x86", true, "AMD x86-64")),
        183 => Some(("AARCH64", false, "AArch64")),
        243 => Some(("RISCV", true, "RISC-V")),
        _ => None,
    }
}

/// `(arch, bits, endian)` → `(language_id, compiler)`. Mirrors `_ELF_SLEIGH`.
fn elf_sleigh_lookup(
    arch: &str,
    bits: u32,
    endian: &str,
) -> Option<(&'static str, &'static str)> {
    Some(match (arch, bits, endian) {
        ("x86", 32, "LE") => ("x86:LE:32:default", "gcc"),
        ("x86", 64, "LE") => ("x86:LE:64:default", "gcc"),
        ("ARM", 32, "LE") => ("ARM:LE:32:v8", "default"),
        ("ARM", 32, "BE") => ("ARM:BE:32:v8", "default"),
        ("AARCH64", 64, "LE") => ("AARCH64:LE:64:v8A", "default"),
        ("AARCH64", 64, "BE") => ("AARCH64:BE:64:v8A", "default"),
        ("MIPS", 32, "BE") => ("MIPS:BE:32:default", "default"),
        ("MIPS", 32, "LE") => ("MIPS:LE:32:default", "default"),
        ("MIPS", 64, "BE") => ("MIPS:BE:64:default", "default"),
        ("MIPS", 64, "LE") => ("MIPS:LE:64:default", "default"),
        ("PowerPC", 32, "BE") => ("PowerPC:BE:32:default", "default"),
        ("PowerPC", 64, "BE") => ("PowerPC:BE:64:default", "default"),
        ("PowerPC", 64, "LE") => ("PowerPC:LE:64:default", "default"),
        ("RISCV", 32, "LE") => ("RISCV:LE:32:default", "default"),
        ("RISCV", 64, "LE") => ("RISCV:LE:64:default", "default"),
        _ => return None,
    })
}

fn detect_elf(data: &[u8]) -> std::result::Result<DetectedBinary, UnsupportedFormatError> {
    if data.len() < 20 {
        return Err(UnsupportedFormatError(
            "unsupported ELF file: truncated header".into(),
        ));
    }
    let ei_class = data[4];
    let ei_data = data[5];
    let bits: u32 = match ei_class {
        1 => 32,
        2 => 64,
        _ => {
            return Err(UnsupportedFormatError(format!(
                "unsupported ELF file: bad ei_class {}",
                ei_class
            )))
        }
    };
    let endian = match ei_data {
        1 => "LE",
        2 => "BE",
        _ => {
            return Err(UnsupportedFormatError(format!(
                "unsupported ELF file: bad ei_data {}",
                ei_data
            )))
        }
    };

    // e_machine at offset 0x12, byte order from ei_data.
    let e_machine = if endian == "LE" {
        u16::from_le_bytes([data[0x12], data[0x13]])
    } else {
        u16::from_be_bytes([data[0x12], data[0x13]])
    };

    let Some((arch, uses_class_bits, machine)) = elf_machine_lookup(e_machine) else {
        return Err(UnsupportedFormatError(format!(
            "unsupported ELF e_machine {}",
            e_machine
        )));
    };

    let bits = if uses_class_bits {
        bits
    } else if arch == "ARM" {
        32
    } else {
        64
    };

    let Some((language_id, compiler)) = elf_sleigh_lookup(arch, bits, endian) else {
        return Err(UnsupportedFormatError(format!(
            "unsupported ELF architecture {} {}-bit {}",
            machine, bits, endian
        )));
    };

    validated(DetectedBinary {
        format: "elf".into(),
        language_id: language_id.into(),
        compiler_spec_id: compiler.into(),
        bits,
        endian: endian.into(),
        machine: machine.into(),
        base_address: None,
        warnings: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Mach-O
// ---------------------------------------------------------------------------

/// Mach-O cputype → (Sleigh ID, default compiler, machine name).
/// Mirrors `_MACHO_CPU_MAP` in `format_detect.py`.
fn macho_cpu_lookup(cputype: u32) -> Option<(&'static str, &'static str, &'static str)> {
    match cputype {
        7 => Some(("x86:LE:32:default", "default", "x86")),
        12 => Some(("ARM:LE:32:v8", "default", "ARM")),
        0x01000007 => Some(("x86:LE:64:default", "default", "x86_64")),
        0x0100000C => Some(("AARCH64:LE:64:v8A", "default", "ARM64")),
        _ => None,
    }
}

fn detect_macho(data: &[u8]) -> std::result::Result<DetectedBinary, UnsupportedFormatError> {
    detect_macho_header(data, "macho", Vec::new())
}

fn detect_macho_header(
    data: &[u8],
    format_name: &str,
    warns: Vec<String>,
) -> std::result::Result<DetectedBinary, UnsupportedFormatError> {
    if data.len() < 8 {
        return Err(UnsupportedFormatError(
            "unsupported Mach-O file: truncated header".into(),
        ));
    }
    let magic = &data[..4];
    let cputype = if magic == [0xce, 0xfa, 0xed, 0xfe] || magic == [0xcf, 0xfa, 0xed, 0xfe] {
        u32::from_le_bytes(data[4..8].try_into().unwrap())
    } else {
        u32::from_be_bytes(data[4..8].try_into().unwrap())
    };

    let Some((language_id, compiler, machine)) = macho_cpu_lookup(cputype) else {
        return Err(UnsupportedFormatError(format!(
            "unsupported Mach-O cputype 0x{:08x}",
            cputype
        )));
    };

    validated(DetectedBinary {
        format: format_name.into(),
        language_id: language_id.into(),
        compiler_spec_id: compiler.into(),
        bits: bits_from_language(language_id),
        endian: if language_id.contains(":LE:") { "LE".into() } else { "BE".into() },
        machine: machine.into(),
        base_address: None,
        warnings: warns,
    })
}

fn detect_fat_macho(data: &[u8]) -> std::result::Result<DetectedBinary, UnsupportedFormatError> {
    if data.len() < 8 {
        return Err(UnsupportedFormatError(
            "unsupported Mach-O file: truncated fat header".into(),
        ));
    }
    let magic = &data[..4];
    let big_endian = magic == [0xca, 0xfe, 0xba, 0xbe] || magic == [0xca, 0xfe, 0xba, 0xbf];
    let stride: usize = if magic == [0xca, 0xfe, 0xba, 0xbf] || magic == [0xbf, 0xba, 0xfe, 0xca] {
        32
    } else {
        20
    };
    let nfat_arch = if big_endian {
        u32::from_be_bytes(data[4..8].try_into().unwrap())
    } else {
        u32::from_le_bytes(data[4..8].try_into().unwrap())
    } as usize;

    let mut skipped: Vec<String> = Vec::new();
    let mut offset = 8usize;
    for _ in 0..nfat_arch {
        if data.len() < offset + 4 {
            return Err(UnsupportedFormatError(
                "unsupported Mach-O file: truncated fat arch".into(),
            ));
        }
        let cputype = if big_endian {
            u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
        };
        offset += stride;
        if let Some(entry) = macho_cpu_lookup(cputype) {
            let mut warns = Vec::new();
            if !skipped.is_empty() {
                warns.push(format!(
                    "skipped unsupported Mach-O fat slice(s): {}",
                    skipped.join(", ")
                ));
            }
            // Build a synthetic Mach-O header just to reuse detect_macho_header
            // — but we already have the entry; emit directly.
            let (language_id, compiler, machine) = entry;
            return validated(DetectedBinary {
                format: "macho-fat".into(),
                language_id: language_id.into(),
                compiler_spec_id: compiler.into(),
                bits: bits_from_language(language_id),
                endian: if language_id.contains(":LE:") {
                    "LE".into()
                } else {
                    "BE".into()
                },
                machine: machine.into(),
                base_address: None,
                warnings: warns,
            });
        } else {
            skipped.push(format!("0x{:08x}", cputype));
        }
    }
    Err(UnsupportedFormatError(
        "unsupported Mach-O binary: no supported architecture slices".into(),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validated(detected: DetectedBinary) -> std::result::Result<DetectedBinary, UnsupportedFormatError> {
    if !known_languages::contains(&detected.language_id) {
        return Err(UnsupportedFormatError(format!(
            "detected language ID '{}' is not embedded",
            detected.language_id
        )));
    }
    Ok(detected)
}

fn bits_from_language(language_id: &str) -> u32 {
    language_id
        .split(':')
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// LANGUAGE_IDS — curated subset of Ghidra Sleigh language IDs known to be
// present in the engine's embedded specs. The full set is generated by
// `cpp/embed_specs.py` for Python; for Rust we maintain the subset that
// `format_detect` ever produces. A future change can replace this with a
// generated file emitted alongside `python/src/libghidra/known_languages.py`.
// ---------------------------------------------------------------------------
mod known_languages {
    pub fn contains(id: &str) -> bool {
        IDS.binary_search(&id).is_ok()
    }

    /// Sorted for binary search. Must contain every value `format_detect`
    /// can put in `DetectedBinary.language_id`.
    static IDS: &[&str] = &[
        "AARCH64:BE:64:v8A",
        "AARCH64:LE:64:v8A",
        "ARM:BE:32:v8",
        "ARM:LE:32:v8",
        "DATA:LE:64:default",
        "MIPS:BE:32:default",
        "MIPS:BE:64:default",
        "MIPS:LE:32:default",
        "MIPS:LE:64:default",
        "PowerPC:BE:32:default",
        "PowerPC:BE:64:default",
        "PowerPC:LE:64:default",
        "RISCV:LE:32:default",
        "RISCV:LE:64:default",
        "x86:LE:32:default",
        "x86:LE:64:default",
    ];

    #[cfg(test)]
    pub fn ids() -> &'static [&'static str] {
        IDS
    }
}

// `LANGUAGE_IDS` re-exported for tests that want to enumerate the set.
#[cfg(test)]
pub fn language_ids() -> &'static [&'static str] {
    known_languages::ids()
}

// ---------------------------------------------------------------------------
// LocalClient bridge: implement OpenProgram for it (gated so live/local-only
// builds compile without each other).
// ---------------------------------------------------------------------------

#[cfg(feature = "local")]
impl OpenProgram for crate::local::LocalClient {
    type Output = crate::models::OpenProgramResponse;
    fn open_program(&self, req: OpenProgramRequest) -> Result<Self::Output> {
        crate::local::LocalClient::open_program(self, req)
    }
}

#[cfg(feature = "live")]
impl OpenProgram for crate::client::GhidraClient {
    type Output = crate::models::OpenProgramResponse;
    fn open_program(&self, req: OpenProgramRequest) -> Result<Self::Output> {
        crate::client::GhidraClient::open_program(self, &req)
    }
}
