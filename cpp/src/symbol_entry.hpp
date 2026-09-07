// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

// Typed views over Ghidra's SymbolEntry hierarchy.
//
// A symbol's storage is either address-mapped or dynamic (hash-identified).
// Upstream models that with two subclasses -- MapEntry owns getAddr(),
// DynamicEntry owns getHash() -- so the kind is a TYPE, not a value.
//
// These helpers just make the downcast null-safe and named. They deliberately
// do NOT reproduce the pre-split base class's sentinel convention, where
// getAddr() returned an invalid Address to mean "this is dynamic" and
// getHash() returned 0 to mean "this is mapped". Encoding the discriminator in
// a magic value is the thing the split removed; callers branch on the type.
//
// Include AFTER libdecomp.hh -- this header names Ghidra types directly and
// does not pull in the decompiler headers itself.

namespace libghidra::detail {

// The entry's address-mapped view, or nullptr when its storage is dynamic.
inline const ghidra::MapEntry* as_map_entry(const ghidra::SymbolEntry* entry) {
  return entry ? dynamic_cast<const ghidra::MapEntry*>(entry) : nullptr;
}

// The entry's dynamic (hash-identified) view, or nullptr when it is mapped.
inline const ghidra::DynamicEntry* as_dynamic_entry(
    const ghidra::SymbolEntry* entry) {
  return entry ? dynamic_cast<const ghidra::DynamicEntry*>(entry) : nullptr;
}

}  // namespace libghidra::detail
