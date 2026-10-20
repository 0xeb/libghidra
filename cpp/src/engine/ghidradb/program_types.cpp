// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "program_types.h"
#include "btree.h"

#include <algorithm>
#include <functional>

namespace ghidra_db {

// Column indices (ghidra.program.database.data.*DBAdapter).
static constexpr int BUILTIN_NAME_COL = 0, BUILTIN_CLASS_COL = 1, BUILTIN_CAT_COL = 2;
static constexpr int PTR_DT_COL = 0, PTR_CAT_COL = 1, PTR_LENGTH_COL = 2;
static constexpr int TYPEDEF_DT_COL = 0, TYPEDEF_NAME_COL = 2, TYPEDEF_CAT_COL = 3;
static constexpr int COMPOSITE_NAME_COL = 0, COMPOSITE_UNION_COL = 2, COMPOSITE_CAT_COL = 3,
                     COMPOSITE_LENGTH_COL = 4;
static constexpr int COMPONENT_PARENT_COL = 0, COMPONENT_OFFSET_COL = 1, COMPONENT_DT_COL = 2,
                     COMPONENT_NAME_COL = 3, COMPONENT_SIZE_COL = 5, COMPONENT_ORDINAL_COL = 6;
static constexpr int ARRAY_DT_COL = 0, ARRAY_DIM_COL = 1, ARRAY_LENGTH_COL = 2, ARRAY_CAT_COL = 3;
static constexpr int FUNCDEF_NAME_COL = 0, FUNCDEF_CAT_COL = 2, FUNCDEF_RETURN_COL = 3,
                     FUNCDEF_FLAGS_COL = 4, FUNCDEF_CALLCONV_COL = 5;
static constexpr int FUNCDEF_VARARG_FLAG = 0x1, FUNCDEF_NORETURN_FLAG = 0x2;
static constexpr int PARAM_PARENT_COL = 0, PARAM_DT_COL = 1, PARAM_NAME_COL = 2,
                     PARAM_ORDINAL_COL = 4, PARAM_LENGTH_COL = 5;
static constexpr int ENUM_NAME_COL = 0, ENUM_CAT_COL = 2, ENUM_SIZE_COL = 3;
static constexpr int ENUM_VALUE_NAME_COL = 0, ENUM_VALUE_VALUE_COL = 1, ENUM_VALUE_ENUM_COL = 2;
static constexpr int CATEGORY_NAME_COL = 0, CATEGORY_PARENT_COL = 1;

std::string ProgramTypes::categoryPath(int64_t category) const {
    std::vector<const std::string*> parts;
    for (int depth = 0; depth < 256; ++depth) {
        auto it = categories.find(category);
        if (it == categories.end() || it->second.second < 0 || it->second.first.empty())
            break;  // the root category has no parent and no name
        parts.push_back(&it->second.first);
        category = it->second.second;
    }
    if (parts.empty()) return "/";
    std::string path;
    for (auto r = parts.rbegin(); r != parts.rend(); ++r) path += "/" + **r;
    return path;
}

void readProgramTypes(BufferFile& bf, const std::vector<MasterTableEntry>& tables,
                      ProgramTypes& out) {
    auto each = [&](const char* name, size_t min_cols,
                    const std::function<void(const Record&)>& fn) {
        for (const auto& t : tables) {
            if (t.name != name || t.indexed_column != -1) continue;
            BTreeReader(bf).iterateRecords(t.root_buffer_id, t.schema,
                [&](const Record& r) -> bool {
                    if (r.fields.size() >= min_cols) fn(r);
                    return true;
                });
            return;
        }
    };

    each("Categories", 2, [&](const Record& r) {
        out.categories[r.key.asLong()] = {r.fields[CATEGORY_NAME_COL].asString(),
                                          r.fields[CATEGORY_PARENT_COL].asLong()};
    });
    each("Built-in datatypes", 3, [&](const Record& r) {
        DataTypeEntry& t = out.types[r.key.asLong()];
        t.kind = DataTypeKind::BUILT_IN;
        t.name = r.fields[BUILTIN_NAME_COL].asString();
        t.class_name = r.fields[BUILTIN_CLASS_COL].asString();
        t.category = r.fields[BUILTIN_CAT_COL].asLong();
    });
    each("Pointers", 3, [&](const Record& r) {
        DataTypeEntry& t = out.types[r.key.asLong()];
        t.kind = DataTypeKind::POINTER;
        t.target = r.fields[PTR_DT_COL].asLong();
        t.category = r.fields[PTR_CAT_COL].asLong();
        t.length = r.fields[PTR_LENGTH_COL].asInt();
    });
    each("Typedefs", 4, [&](const Record& r) {
        DataTypeEntry& t = out.types[r.key.asLong()];
        t.kind = DataTypeKind::TYPEDEF;
        t.target = r.fields[TYPEDEF_DT_COL].asLong();
        t.name = r.fields[TYPEDEF_NAME_COL].asString();
        t.category = r.fields[TYPEDEF_CAT_COL].asLong();
    });
    each("Composite Data Types", 5, [&](const Record& r) {
        DataTypeEntry& t = out.types[r.key.asLong()];
        t.kind = DataTypeKind::COMPOSITE;
        t.name = r.fields[COMPOSITE_NAME_COL].asString();
        t.is_union = r.fields[COMPOSITE_UNION_COL].asLong() != 0;
        t.category = r.fields[COMPOSITE_CAT_COL].asLong();
        t.length = r.fields[COMPOSITE_LENGTH_COL].asInt();
        if (r.fields.size() > 11 && !r.fields[11].is_null) t.pack = r.fields[11].asInt();
    });
    each("Arrays", 4, [&](const Record& r) {
        DataTypeEntry& t = out.types[r.key.asLong()];
        t.kind = DataTypeKind::ARRAY;
        t.target = r.fields[ARRAY_DT_COL].asLong();
        t.count = r.fields[ARRAY_DIM_COL].asInt();
        t.length = r.fields[ARRAY_LENGTH_COL].asInt();
        t.category = r.fields[ARRAY_CAT_COL].asLong();
    });
    // CallingConventionDBAdapter: 0 unknown, 1 default, >= 2 a "Calling
    // Conventions" key (a ByteField key: a FixedKey b-tree).
    std::map<int, std::string> conventions;
    each("Calling Conventions", 1, [&](const Record& r) {
        conventions[static_cast<int>(r.key.asLong())] = r.fields[0].asString();
    });
    each("Function Definitions", 3, [&](const Record& r) {
        DataTypeEntry& t = out.types[r.key.asLong()];
        t.kind = DataTypeKind::FUNCTION_DEF;
        t.name = r.fields[FUNCDEF_NAME_COL].asString();
        t.category = r.fields[FUNCDEF_CAT_COL].asLong();
        if (r.fields.size() > FUNCDEF_RETURN_COL && !r.fields[FUNCDEF_RETURN_COL].is_null)
            t.return_type = r.fields[FUNCDEF_RETURN_COL].asLong();
        if (r.fields.size() > FUNCDEF_FLAGS_COL) {
            const int flags = static_cast<int>(r.fields[FUNCDEF_FLAGS_COL].asLong());
            t.has_var_args = (flags & FUNCDEF_VARARG_FLAG) != 0;
            t.no_return = (flags & FUNCDEF_NORETURN_FLAG) != 0;
        }
        int cc = 0;
        if (r.fields.size() > FUNCDEF_CALLCONV_COL)
            cc = static_cast<int>(r.fields[FUNCDEF_CALLCONV_COL].asLong());
        auto conv = conventions.find(cc);
        t.calling_convention = cc == 1 ? "default"
                               : (cc == 0 || conv == conventions.end()) ? "unknown"
                                                                        : conv->second;
    });
    each("Function Parameters", 5, [&](const Record& r) {
        FuncDefParam p;
        p.type_id = r.fields[PARAM_DT_COL].asLong();
        p.name = r.fields[PARAM_NAME_COL].is_null ? std::string() : r.fields[PARAM_NAME_COL].asString();
        p.ordinal = r.fields[PARAM_ORDINAL_COL].asInt();
        if (r.fields.size() > PARAM_LENGTH_COL) p.length = r.fields[PARAM_LENGTH_COL].asInt();
        out.funcdef_params[r.fields[PARAM_PARENT_COL].asLong()].push_back(std::move(p));
    });
    each("Enumeration Data Types", 4, [&](const Record& r) {
        DataTypeEntry& t = out.types[r.key.asLong()];
        t.kind = DataTypeKind::ENUM;
        t.name = r.fields[ENUM_NAME_COL].asString();
        t.category = r.fields[ENUM_CAT_COL].asLong();
        t.length = r.fields[ENUM_SIZE_COL].asInt();
    });
    each("Enumeration Values", 3, [&](const Record& r) {
        out.enum_values[r.fields[ENUM_VALUE_ENUM_COL].asLong()].emplace_back(
            r.fields[ENUM_VALUE_NAME_COL].asString(), r.fields[ENUM_VALUE_VALUE_COL].asLong());
    });
    each("Component Data Types", 7, [&](const Record& r) {
        ComponentEntry c;
        c.offset = r.fields[COMPONENT_OFFSET_COL].asInt();
        c.type_id = r.fields[COMPONENT_DT_COL].asLong();
        c.name = r.fields[COMPONENT_NAME_COL].asString();
        c.size = r.fields[COMPONENT_SIZE_COL].asInt();
        c.ordinal = r.fields[COMPONENT_ORDINAL_COL].asInt();
        out.components[r.fields[COMPONENT_PARENT_COL].asLong()].push_back(std::move(c));
    });
    for (auto& [id, params] : out.funcdef_params)
        std::sort(params.begin(), params.end(),
                  [](const FuncDefParam& a, const FuncDefParam& b) { return a.ordinal < b.ordinal; });
    for (auto& [id, fields] : out.components)
        std::sort(fields.begin(), fields.end(),
                  [](const ComponentEntry& a, const ComponentEntry& b) {
                      return a.ordinal < b.ordinal;
                  });
}

} // namespace ghidra_db
