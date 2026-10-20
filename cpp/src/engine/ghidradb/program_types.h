// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once
#include "db_record.h"

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ghidra_db {

// Data type id layout (DataTypeManagerDB): the top byte selects the table.
enum class DataTypeKind : int {
    BUILT_IN = 0,
    COMPOSITE = 1,
    COMPONENT = 2,
    ARRAY = 3,
    POINTER = 4,
    TYPEDEF = 5,
    FUNCTION_DEF = 6,
    PARAMETER = 7,
    ENUM = 8,
    BITFIELD = 9,  // encoded ids only; no table
};

inline DataTypeKind dataTypeKind(int64_t id) {
    return static_cast<DataTypeKind>(static_cast<uint64_t>(id) >> 56);
}

// DataTypeManager.DEFAULT_DATATYPE_ID ("undefined") and NULL_DATATYPE_ID.
static constexpr int64_t DEFAULT_DATATYPE_ID = 0;
static constexpr int64_t NULL_DATATYPE_ID = -1;

// One row of a data type table, normalised across tables.
struct DataTypeEntry {
    DataTypeKind kind = DataTypeKind::BUILT_IN;
    std::string name;          // Ghidra getName() (composites, typedefs, enums, ...)
    std::string class_name;    // built-ins: the Java class, e.g. ...IntegerDataType
    int64_t category = 0;      // "Categories" key
    int64_t target = NULL_DATATYPE_ID;  // pointer/typedef/array element type id
    int length = 0;            // composite/enum size, pointer length (-1 = default),
                               // array element length
    int count = 0;             // array element count
    bool is_union = false;
    // A composite's packing ("Pack": -1 disabled, 0 default, > 0 explicit). A
    // structure without packing keeps its undefined bytes as components.
    int pack = -1;
    // A function definition: its return type, calling convention name
    // ("unknown", "default" or a "Calling Conventions" name) and flags.
    int64_t return_type = DEFAULT_DATATYPE_ID;
    std::string calling_convention;
    bool has_var_args = false;
    bool no_return = false;
};

// "Function Parameters": one parameter of a function definition.
struct FuncDefParam {
    int64_t type_id = DEFAULT_DATATYPE_ID;
    std::string name;
    int ordinal = 0;
    int length = 0;
};

// "Component Data Types": one field of a composite.
struct ComponentEntry {
    int offset = 0;
    int64_t type_id = DEFAULT_DATATYPE_ID;
    std::string name;
    int size = 0;
    int ordinal = 0;
};

// The program's data type manager, as stored in the project db.
struct ProgramTypes {
    std::map<int64_t, DataTypeEntry> types;                  // by data type id
    std::map<int64_t, std::vector<ComponentEntry>> components;  // composite id -> fields
    std::map<int64_t, std::vector<std::pair<std::string, int64_t>>> enum_values;  // enum id
    std::map<int64_t, std::pair<std::string, int64_t>> categories;  // id -> (name, parent)
    std::map<int64_t, std::vector<FuncDefParam>> funcdef_params;  // function definition id

    // Ghidra CategoryPath of a category id: "/" for the root, "/a/b" below it.
    std::string categoryPath(int64_t category) const;
};

// Read every data type table of a program db into `out`.
void readProgramTypes(BufferFile& bf, const std::vector<MasterTableEntry>& tables,
                      ProgramTypes& out);

} // namespace ghidra_db
