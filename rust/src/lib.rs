// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// libghidra: Rust client for the Ghidra decompiler with two backends.
//
//   * `live`  (default) — HTTP/RPC to a running Ghidra Desktop with the
//                         libghidra extension installed (or a headless
//                         project session launched via `launch_headless_project`).
//   * `local`           — offline backend; links the C++ libghidra engine
//                         and embedded Sleigh specs, no Ghidra install
//                         required at runtime.
//
// `cargo add libghidra`                          → live only
// `cargo add libghidra --features local`         → live + local
// `cargo add libghidra --no-default-features --features local` → local only
#![warn(unused_results)]

pub mod error;
pub mod format_detect;
pub mod models;

#[cfg(feature = "live")]
mod client;
#[cfg(feature = "live")]
mod convert;
#[cfg(feature = "live")]
pub mod headless;
#[cfg(feature = "live")]
pub mod paginate;
#[cfg(feature = "live")]
#[doc(hidden)]
pub mod proto;
#[cfg(feature = "live")]
mod retry;

#[cfg(feature = "local")]
pub mod local;
#[cfg(feature = "local")]
mod local_ffi;

pub use error::{Error, ErrorCode, Result};
pub use models::*;

#[cfg(feature = "live")]
pub use client::{ClientOptions, GhidraClient};
#[cfg(feature = "live")]
pub use headless::{launch_headless_project, HeadlessClient, HeadlessProjectOptions};

#[cfg(feature = "local")]
pub use local::{LocalClient, LocalClientOptions};

// -- Convenience factories ----------------------------------------------------

/// Create a live (HTTP) client for a Ghidra host at the given URL.
///
/// ```no_run
/// use libghidra as ghidra;
/// let client = ghidra::connect("http://127.0.0.1:18080");
/// ```
#[cfg(feature = "live")]
pub fn connect(url: &str) -> GhidraClient {
    GhidraClient::new(ClientOptions {
        base_url: url.to_string(),
        ..Default::default()
    })
}

/// Create a local (offline) client with default options (auto-detect arch).
///
/// Requires the `local` feature.
///
/// ```no_run
/// # #[cfg(feature = "local")] {
/// use libghidra as ghidra;
/// let client = ghidra::local()?;
/// # Ok::<(), ghidra::Error>(())
/// # }
/// ```
#[cfg(feature = "local")]
pub fn local() -> Result<LocalClient> {
    LocalClient::new(LocalClientOptions::default())
}

/// Create a local (offline) client with the given options.
#[cfg(feature = "local")]
pub fn local_with(opts: LocalClientOptions) -> Result<LocalClient> {
    LocalClient::new(opts)
}

// -- Core type aliases --------------------------------------------------------

#[cfg(feature = "live")]
pub type Client = GhidraClient;
#[cfg(feature = "live")]
pub type ConnectOptions = ClientOptions;

// -- Short type aliases (always available; types live in `models`) ------------

pub type Function = FunctionRecord;
pub type Symbol = SymbolRecord;
pub type Decompilation = DecompilationRecord;
pub type Instruction = InstructionRecord;
pub type Xref = XrefRecord;
pub type Type = TypeRecord;
pub type Comment = CommentRecord;
pub type MemoryBlock = MemoryBlockRecord;
pub type BasicBlock = BasicBlockRecord;
pub type CFGEdge = CFGEdgeRecord;
pub type DataItem = DataItemRecord;
pub type Bookmark = BookmarkRecord;
pub type Breakpoint = BreakpointRecord;
pub type Parameter = ParameterRecord;
pub type Signature = FunctionSignatureRecord;
pub type DefinedString = DefinedStringRecord;
pub type TypeMember = TypeMemberRecord;
pub type TypeEnum = TypeEnumRecord;
pub type TypeEnumMember = TypeEnumMemberRecord;
pub type TypeAlias = TypeAliasRecord;
pub type TypeUnion = TypeUnionRecord;
pub type FunctionTag = FunctionTagRecord;
pub type FunctionTagMapping = FunctionTagMappingRecord;
pub type SwitchTable = SwitchTableRecord;
pub type SwitchCase = SwitchCaseRecord;
pub type Dominator = DominatorRecord;
pub type PostDominator = PostDominatorRecord;
pub type Loop = LoopRecord;
pub type DecompileToken = DecompileTokenRecord;
