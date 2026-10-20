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

// Visit the global scope and every namespace scope below it, parents first.
// Function-local scopes (ScopeLocal) are skipped: their symbols are variables.
// Functions loaded from a Ghidra project live in their namespace's scope, so a
// walk of the global scope alone misses them.
template <class Fn>
void for_each_namespace_scope(ghidra::Scope* scope, Fn&& fn) {
  if (scope == nullptr || !scope->isGlobal()) return;
  fn(scope);
  for (auto it = scope->childrenBegin(); it != scope->childrenEnd(); ++it)
    for_each_namespace_scope(it->second, fn);
}

// The symbol entry starting exactly at `addr`, in whichever namespace owns the
// address (Database::mapScope), then that scope's parents up to the global one.
inline ghidra::SymbolEntry* find_addr_any_scope(ghidra::Architecture* arch,
                                                const ghidra::Address& addr) {
  ghidra::Scope* global = arch->symboltab->getGlobalScope();
  for (ghidra::Scope* s = arch->symboltab->mapScope(global, addr, ghidra::Address());
       s != nullptr; s = s->getParent()) {
    if (ghidra::SymbolEntry* e = s->findAddr(addr, ghidra::Address())) return e;
  }
  return nullptr;
}

// Ghidra Namespace.getName(true) for a decompiler scope: the scope names from
// the outermost namespace down, joined by "::"; the global scope is "Global".
inline std::string namespace_path(const ghidra::Scope* scope) {
  std::string path;
  for (; scope != nullptr && scope->getParent() != nullptr; scope = scope->getParent())
    path = path.empty() ? scope->getDisplayName() : scope->getDisplayName() + "::" + path;
  return path.empty() ? "Global" : path;
}

}  // namespace libghidra::detail
