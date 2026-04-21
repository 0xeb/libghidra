// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once
#include "buffer_file.h"
#include <variant>
#include <set>

namespace ghidra_db {

// Field type codes (matches Java db.Field constants)
enum class FieldType : uint8_t {
    BYTE = 0,
    SHORT = 1,
    INT = 2,
    LONG = 3,
    STRING = 4,
    BINARY = 5,
    BOOLEAN = 6,
    FIXED10 = 7,
};

// A dynamically-typed database field value.
struct FieldValue {
    FieldType type = FieldType::LONG;
    bool is_null = false;

    // Primitive values
    int8_t byte_val = 0;
    int16_t short_val = 0;
    int32_t int_val = 0;
    int64_t long_val = 0;
    bool bool_val = false;

    // Variable-length values
    std::string string_val;
    std::vector<uint8_t> binary_val;

    int64_t asLong() const;
    int32_t asInt() const;
    std::string asString() const;
};

// Schema: describes the key type and column types for a table.
struct Schema {
    int32_t version = 0;
    FieldType key_type = FieldType::LONG;
    std::vector<FieldType> field_types;
    std::vector<std::string> field_names;
    std::string key_name;
    std::set<int> sparse_columns;
    bool is_variable_length = false;
    int32_t fixed_length = 0; // total fixed record length (0 if variable)

    // Decode from the master table record fields
    static Schema decode(int32_t version, uint8_t key_type_byte,
                         const std::vector<uint8_t>& field_type_bytes,
                         const std::string& packed_names);

    bool useLongKeyNodes() const;
    bool useVariableKeyNodes() const;
};

// A single database record (one row).
struct Record {
    FieldValue key;
    std::vector<FieldValue> fields;

    // Read record data from a buffer at the given offset.
    // Returns the offset after the last byte read.
    int32_t read(const uint8_t* buf, int32_t offset, const Schema& schema);
};

// DBParms: reads parameter integers from buffer 0.
struct DBParms {
    int32_t master_table_root = -1;

    // Read from buffer 0 data.
    bool read(const std::vector<uint8_t>& buf0);
};

// MasterTableEntry: one entry from the master table.
struct MasterTableEntry {
    int64_t table_num = 0;
    std::string name;
    int32_t schema_version = 0;
    int32_t root_buffer_id = -1;
    int32_t record_count = 0;
    int32_t indexed_column = -1;
    Schema schema;
};

// Read a single field value from buffer at offset. Returns new offset.
int32_t readField(const uint8_t* buf, int32_t offset, FieldType type, FieldValue& out);

// Compute the fixed storage size of a field type. Returns -1 for variable-length types.
int fixedFieldSize(FieldType type);

} // namespace ghidra_db
