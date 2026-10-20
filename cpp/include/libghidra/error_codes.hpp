// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

// The RPC error vocabulary: every Status::code a backend reports for a request
// it refuses. Both backends use these strings (the Java host spells them in
// SessionRpcException); never spell a code by hand.
//
// The write contract: a write either succeeds with its effect, or fails with one
// of these codes and a message. It never answers ok with a false flag, and never
// ok without its effect.
//
// HttpClient adds transport codes of its own (connection_failed, timeout,
// encode_error, ...) for failures that happen before the host answers.

namespace libghidra::client::error_codes {

/// The write names something that does not exist: a function, type, member
/// ordinal, local, parameter, symbol, comment, program, ...
inline constexpr const char* kNotFound = "not_found";
/// The address is not inside any memory block of the program.
inline constexpr const char* kUnmappedAddress = "unmapped_address";
/// No program is open.
inline constexpr const char* kNotLoaded = "not_loaded";
/// The request is malformed or names the wrong kind of thing (a struct where an
/// enum is required, instructions where data is applied, ...).
inline constexpr const char* kInvalidArgument = "invalid_argument";
/// A create or rename would collide with an existing name.
inline constexpr const char* kDuplicateName = "duplicate_name";
/// This backend cannot do it.
inline constexpr const char* kNotSupported = "not_supported";
/// Text the request carries (a prototype, a declaration) does not parse.
inline constexpr const char* kParseError = "parse_error";
/// The address is mapped but its block holds no bytes.
inline constexpr const char* kUninitializedMemory = "uninitialized_memory";
/// The target exists but is busy or protected (another program open, a write
/// running past mapped memory, ...).
inline constexpr const char* kAccessConflict = "access_conflict";
/// An analysis job owns the program.
inline constexpr const char* kAnalysisRunning = "analysis_running";
/// The request was cancelled.
inline constexpr const char* kCancelled = "cancelled";
/// The backend failed for a reason the request cannot fix.
inline constexpr const char* kInternalError = "internal_error";
/// The host does not know the RPC method.
inline constexpr const char* kUnknownMethod = "unknown_method";
/// The request payload does not decode.
inline constexpr const char* kInvalidPayload = "invalid_payload";
/// The backend is not configured for the request (e.g. no state path to save to).
inline constexpr const char* kConfigError = "config_error";
/// A type named as an argument (a parameter, local, member or alias target type,
/// ApplyDataType's type) does not resolve; the write's target itself is fine.
inline constexpr const char* kUnknownType = "unknown_type";

}  // namespace libghidra::client::error_codes
