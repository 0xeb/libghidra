// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ghidra {
class Architecture;
class Datatype;
}  // namespace ghidra

namespace ghidra_db {
struct ProjectData;
}

namespace ghidra_standalone {

struct ProjectFunctionState;  // function_state.h

/// Ghidra category path of every program data type loaded into the decompiler,
/// keyed by the decompiler type id. Loaded types carry their Ghidra data type
/// id as that id (as the Java host's decompiler interface does), so two
/// same-named types in different categories stay distinct.
using TypeCategories = std::map<std::uint64_t, std::string>;

struct ProjectSignatureStats {
    std::size_t types = 0;           // data types materialised
    std::size_t type_failures = 0;   // stood in for by "undefined"
    std::size_t locked = 0;          // saved prototypes applied locked
    std::size_t unlocked = 0;        // DEFAULT signatures: calling convention only
};

/// Load a project's data types and saved function signatures into `arch`: every
/// program data type becomes a decompiler Datatype, every non-DEFAULT signature
/// becomes a locked prototype and a DEFAULT one keeps its calling convention.
/// Functions must already exist (loadProject names them). The locked
/// prototypes and every function's saved locals go into `state`, which
/// prepareSavedFunction() replays before each decompile.
///
/// `data_types`, when given, receives the decompiler type of every defined data
/// item (by address), built the way the host's PcodeDataTypeManager encodes it:
/// strings as char arrays of the item's length, other data-only built-ins as
/// opaque types of their length. Items it cannot type are left out.
ProjectSignatureStats applyProjectSignatures(ghidra::Architecture* arch,
                                             const ghidra_db::ProjectData& data,
                                             TypeCategories& categories,
                                             ProjectFunctionState& state,
                                             std::map<std::uint64_t, ghidra::Datatype*>* data_types = nullptr);

/// A function definition, as PcodeDataTypeManager.encodeFunctionDefinition sends
/// one: a code type carrying its prototype (FunctionPrototype(FunctionSignature)
/// with voidInputIsVarargs: an empty parameter list is variadic).
struct FunctionDefinitionSpec {
    std::string name;
    std::uint64_t id = 0;                 // 0: derived from the name
    ghidra::Datatype* output = nullptr;   // nullptr: void
    std::vector<std::pair<std::string, ghidra::Datatype*>> params;
    std::string calling_convention;       // "unknown", "default" or a model name
    bool has_var_args = false;
    bool no_return = false;
};
ghidra::Datatype* makeFunctionDefinition(ghidra::Architecture* arch, const FunctionDefinitionSpec& spec);

/// An enum of `size` bytes with these values (signed when one is negative).
ghidra::Datatype* makeEnumType(ghidra::Architecture* arch, const std::string& name, std::uint64_t id,
                               int size, const std::vector<std::pair<std::string, std::int64_t>>& values);

/// EnumDataType's length for these values: at least `initial`, and as long as
/// getMinimumPossibleLength() needs.
int enumLengthFor(const std::vector<std::pair<std::string, std::int64_t>>& values, int initial);

/// Ghidra DataType.getName() for a decompiler data-type: pointers "T *",
/// arrays "T[n]"; named types (the host's core types included) by name.
std::string ghidraTypeName(ghidra::Datatype* type, int pointer_size);

/// Ghidra DataType.getPathName(): the category path of the named type at the
/// bottom of any pointer/array chain, then ghidraTypeName().
std::string ghidraTypePath(ghidra::Datatype* type, int pointer_size,
                           const TypeCategories* categories);

}  // namespace ghidra_standalone
