// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
#![warn(unused_results)]

mod client;
mod convert;
pub mod error;
pub mod headless;
pub mod models;
pub mod paginate;
#[doc(hidden)]
pub mod proto;
mod retry;

pub use client::{ClientOptions, GhidraClient};
pub use error::{Error, ErrorCode, Result};
pub use headless::{launch_headless, HeadlessClient, HeadlessOptions};
pub use models::*;

// -- Convenience factory ------------------------------------------------------

/// Create a client for a libghidra host at the given URL.
///
/// ```no_run
/// use libghidra as ghidra;
/// let client = ghidra::connect("http://127.0.0.1:18080");
/// ```
pub fn connect(url: &str) -> GhidraClient {
    GhidraClient::new(ClientOptions {
        base_url: url.to_string(),
        ..Default::default()
    })
}

// -- Core type aliases --------------------------------------------------------

pub type Client = GhidraClient;
pub type ConnectOptions = ClientOptions;

// -- Short type aliases -------------------------------------------------------

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
pub type OpenRequest = OpenProgramRequest;
