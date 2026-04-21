// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Convenience facade: short aliases in the `ghidra::` namespace.
//
//   #include "libghidra/ghidra.hpp"
//   auto client = ghidra::connect("http://127.0.0.1:18080");
//   auto client = ghidra::local({.default_arch = "x86:LE:64:default"});

#pragma once

#include "libghidra/api.hpp"
#include "libghidra/headless.hpp"
#include "libghidra/http.hpp"
#include "libghidra/local.hpp"

namespace ghidra {

// --- Core types ---
using Client = libghidra::client::IClient;
using Status = libghidra::client::Status;
template <typename T>
using Result = libghidra::client::StatusOr<T>;

// --- Factories ---
inline std::unique_ptr<Client> connect(const std::string& url,
                                       libghidra::client::HttpClientOptions opts = {}) {
  opts.base_url = url;
  return libghidra::client::CreateHttpClient(std::move(opts));
}

inline std::unique_ptr<Client> connect(libghidra::client::HttpClientOptions opts = {}) {
  return libghidra::client::CreateHttpClient(std::move(opts));
}

inline std::unique_ptr<Client> local(libghidra::client::LocalClientOptions opts = {}) {
  return libghidra::client::CreateLocalClient(std::move(opts));
}

// --- Headless ---
using HeadlessOptions = libghidra::client::HeadlessOptions;
using HeadlessClient = libghidra::client::HeadlessClient;

inline HeadlessClient launch_headless(HeadlessOptions opts) {
  return libghidra::client::LaunchHeadless(std::move(opts));
}

// --- Options ---
using ConnectOptions = libghidra::client::HttpClientOptions;
using LocalOptions = libghidra::client::LocalClientOptions;
using OpenRequest = libghidra::client::OpenProgramRequest;

// --- Enums ---
using ShutdownPolicy = libghidra::client::ShutdownPolicy;
using CommentKind = libghidra::client::CommentKind;
using DecompileLocalKind = libghidra::client::DecompileLocalKind;

// --- Records ---
using Function = libghidra::client::FunctionRecord;
using Symbol = libghidra::client::SymbolRecord;
using Decompilation = libghidra::client::DecompilationRecord;
using DecompileLocal = libghidra::client::DecompileLocalRecord;
using Instruction = libghidra::client::InstructionRecord;
using Xref = libghidra::client::XrefRecord;
using Type = libghidra::client::TypeRecord;
using Comment = libghidra::client::CommentRecord;
using MemoryBlock = libghidra::client::MemoryBlockRecord;
using BasicBlock = libghidra::client::BasicBlockRecord;
using CFGEdge = libghidra::client::CFGEdgeRecord;
using DataItem = libghidra::client::DataItemRecord;
using Bookmark = libghidra::client::BookmarkRecord;
using Breakpoint = libghidra::client::BreakpointRecord;
using Parameter = libghidra::client::ParameterRecord;
using Signature = libghidra::client::FunctionSignatureRecord;
using DefinedString = libghidra::client::DefinedStringRecord;
using TypeMember = libghidra::client::TypeMemberRecord;
using TypeEnum = libghidra::client::TypeEnumRecord;
using TypeEnumMember = libghidra::client::TypeEnumMemberRecord;
using TypeAlias = libghidra::client::TypeAliasRecord;
using TypeUnion = libghidra::client::TypeUnionRecord;

}  // namespace ghidra
