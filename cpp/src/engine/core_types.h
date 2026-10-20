// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <iosfwd>
#include <string>
#include <vector>

namespace ghidra {
class Architecture;
class TypeFactory;
}  // namespace ghidra

namespace ghidra_standalone {

/// One core data-type as the live host announces it to its decompiler.
struct CoreTypeSpec {
    std::string name;
    int size = 0;
    std::string metatype;   // "void", "unknown", "int", "uint", "float", "code", "bool"
    bool is_char = false;   // one-byte character type
    bool is_utf = false;    // wide character type
};

/// The sizes Ghidra's DataOrganization carries, with its defaults
/// (DataOrganizationImpl.DEFAULT_*).
struct DataOrganizationSizes {
    int char_size = 1;
    bool signed_char = true;
    int wchar_size = 2;
    int short_size = 2;
    int int_size = 4;
    int long_size = 4;
    int long_long_size = 8;
    int float_size = 4;
    int double_size = 8;
    int long_double_size = 8;
};

/// PcodeDataTypeManager.generateCoreTypes: the core types the host sends for a
/// program with this data organization (C display names).
std::vector<CoreTypeSpec> hostCoreTypes(const DataOrganizationSizes& org);

/// A raw-binary Architecture whose core types are the host's (`int`, `uint`,
/// `undefined4`, `longlong` ...) instead of the standalone dialect (`int4`,
/// `uint4`, `xunknown4`, `int8` ...), sized from the compiler spec's
/// <data_organization>. Every core type's id is Datatype::hashName(name), the
/// id TypeFactory::getBase(size, meta, name) gives a program's built-in type,
/// so a program `int` and the core `int` are one Datatype.
ghidra::Architecture* buildRawArchitecture(const std::string& filename, const std::string& target,
                                           std::ostream* errors);

/// Accept the standalone dialect names (`int4`, `uint1`, `xunknown8`,
/// `wchar2` ...) and C spellings the grammar lacks (`unsigned int`,
/// `long long` ...) as input: each becomes a typedef of the host core type of
/// that size and kind. Names that already exist are left alone.
void registerTypeNameAliases(ghidra::Architecture* arch);

}  // namespace ghidra_standalone
