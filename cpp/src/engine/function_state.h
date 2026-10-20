// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

// What the program database says about a function, kept beside the decompiler
// so every decompile starts from it -- the way the live host rebuilds each
// function from its database before every decompile. Include after
// libdecomp.hh.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ghidra_standalone {

/// A locked prototype as the database (or a later edit) set it. A decompile
/// changes the Funcdata's copy -- clearAnalysis resets every size-locked
/// "undefined" to the core undefined1 (resetSizeLockType) -- so records and
/// the next decompile read this one instead.
struct SavedPrototype {
    ghidra::PrototypePieces pieces;
    bool output_locked = true;   // a DEFAULT ("undefined") return is not locked
    // Custom variable storage: every parameter (and the return value) sits
    // where the database says, not where the calling convention puts it.
    bool custom = false;
    std::vector<ghidra::Address> input_storage;
    ghidra::Address output_storage;
};

/// A saved local variable (LOCAL_VAR symbol): the host hands these to its
/// decompiler with every decompile (LocalSymbolMap.grabFromFunction), name
/// locked, type locked unless the type is undefined.
struct SavedLocal {
    std::string name;
    ghidra::Address addr;
    ghidra::Datatype* type = nullptr;
    bool type_locked = false;
};

struct ProjectFunctionState {
    std::map<std::uint64_t, SavedPrototype> prototypes;       // by entry address
    std::map<std::uint64_t, std::vector<SavedLocal>> locals;   // by entry address
    std::size_t skipped_locals = 0;  // storage this backend cannot place (not stack/register)
    // The calling convention of each DEFAULT (unlocked) signature. The host
    // locks it unless it is "unknown" (FunctionPrototype.grabFromFunction), and
    // an unlocked model does not survive a decompile, so it is put back before
    // every decompile and read back from here.
    std::map<std::uint64_t, ghidra::ProtoModel*> default_models;
};

/// Bring `fd` back to its saved state before a decompile: reinstall the saved
/// prototype and re-add every saved local the last clearAnalysis dropped.
void prepareSavedFunction(ghidra::Funcdata* fd, const ProjectFunctionState& state);

/// Install `saved` as `fd`'s locked prototype. A custom-storage prototype goes
/// through FuncProto::decode (the only way to mark storage custom), keeping
/// the no-return / inline flags and any call fixup `fd` already carries.
void installSavedPrototype(ghidra::Funcdata* fd, const SavedPrototype& saved);

}  // namespace ghidra_standalone
