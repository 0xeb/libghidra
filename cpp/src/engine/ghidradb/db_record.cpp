// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "db_record.h"
#include <sstream>

namespace ghidra_db {

// ----- FieldValue helpers -----

int64_t FieldValue::asLong() const {
    switch (type) {
        case FieldType::BYTE:    return byte_val;
        case FieldType::SHORT:   return short_val;
        case FieldType::INT:     return int_val;
        case FieldType::LONG:    return long_val;
        case FieldType::BOOLEAN: return bool_val ? 1 : 0;
        default: return 0;
    }
}

int32_t FieldValue::asInt() const {
    return static_cast<int32_t>(asLong());
}

std::string FieldValue::asString() const {
    if (type == FieldType::STRING) return string_val;
    return std::to_string(asLong());
}

// ----- Field read/write -----

int fixedFieldSize(FieldType type) {
    switch (type) {
        case FieldType::BYTE:    return 1;
        case FieldType::SHORT:   return 2;
        case FieldType::INT:     return 4;
        case FieldType::LONG:    return 8;
        case FieldType::BOOLEAN: return 1;
        case FieldType::FIXED10: return 10;
        case FieldType::STRING:  return -1; // variable
        case FieldType::BINARY:  return -1; // variable
    }
    return -1;
}

int32_t readField(const uint8_t* buf, int32_t offset, FieldType type, FieldValue& out) {
    out.type = type;
    out.is_null = false;
    switch (type) {
        case FieldType::BYTE:
            out.byte_val = readSByte(buf + offset);
            return offset + 1;
        case FieldType::SHORT:
            out.short_val = readShort(buf + offset);
            return offset + 2;
        case FieldType::INT:
            out.int_val = readInt(buf + offset);
            return offset + 4;
        case FieldType::LONG:
            out.long_val = readLong(buf + offset);
            return offset + 8;
        case FieldType::BOOLEAN:
            out.bool_val = (buf[offset] != 0);
            return offset + 1;
        case FieldType::FIXED10:
            out.binary_val.assign(buf + offset, buf + offset + 10);
            return offset + 10;
        case FieldType::STRING: {
            int32_t len = readInt(buf + offset);
            offset += 4;
            if (len < 0) {
                out.string_val.clear();
                out.is_null = true;
            } else {
                out.string_val = readUTF8(buf + offset, len);
                offset += len;
            }
            return offset;
        }
        case FieldType::BINARY: {
            int32_t len = readInt(buf + offset);
            offset += 4;
            if (len < 0) {
                out.binary_val.clear();
                out.is_null = true;
            } else {
                out.binary_val.assign(buf + offset, buf + offset + len);
                offset += len;
            }
            return offset;
        }
    }
    return offset;
}

// ----- Schema -----

static FieldType fieldTypeFromByte(uint8_t b) {
    uint8_t base = b & 0x0F;
    switch (base) {
        case 0: return FieldType::BYTE;
        case 1: return FieldType::SHORT;
        case 2: return FieldType::INT;
        case 3: return FieldType::LONG;
        case 4: return FieldType::STRING;
        case 5: return FieldType::BINARY;
        case 6: return FieldType::BOOLEAN;
        case 7: return FieldType::FIXED10;
        default: return FieldType::LONG; // fallback for legacy/index types
    }
}

Schema Schema::decode(int32_t version, uint8_t key_type_byte,
                      const std::vector<uint8_t>& field_type_bytes,
                      const std::string& packed_names) {
    Schema s;
    s.version = version;
    s.key_type = fieldTypeFromByte(key_type_byte);
    s.is_variable_length = false;
    s.fixed_length = 0;

    // Parse field types. Stop at FIELD_EXTENSION_INDICATOR (-1 / 0xFF).
    size_t idx = 0;
    while (idx < field_type_bytes.size()) {
        uint8_t b = field_type_bytes[idx++];
        if (b == 0xFF) break; // extension indicator
        FieldType ft = fieldTypeFromByte(b);
        s.field_types.push_back(ft);
        int fs = fixedFieldSize(ft);
        if (fs < 0) {
            s.is_variable_length = true;
        } else {
            s.fixed_length += fs;
        }
    }

    // Parse extensions (sparse columns)
    while (idx < field_type_bytes.size()) {
        uint8_t ext_type = field_type_bytes[idx++];
        if (ext_type == 1) { // SPARSE_FIELD_LIST_EXTENSION
            while (idx < field_type_bytes.size() && field_type_bytes[idx] != 0xFF) {
                s.sparse_columns.insert(static_cast<int>(field_type_bytes[idx++]));
            }
        }
    }
    if (!s.sparse_columns.empty()) {
        s.is_variable_length = true;
    }

    if (s.is_variable_length) {
        s.fixed_length = 0;
    }

    // Parse packed names: "keyName;field0;field1;..."
    {
        std::istringstream ss(packed_names);
        std::string tok;
        bool first = true;
        while (std::getline(ss, tok, ';')) {
            if (first) {
                s.key_name = tok;
                first = false;
            } else {
                s.field_names.push_back(tok);
            }
        }
    }

    return s;
}

bool Schema::useLongKeyNodes() const {
    return key_type == FieldType::LONG;
}

bool Schema::useVariableKeyNodes() const {
    return key_type == FieldType::STRING || key_type == FieldType::BINARY;
}

// ----- Record -----

int32_t Record::read(const uint8_t* buf, int32_t offset, const Schema& schema) {
    fields.resize(schema.field_types.size());

    if (schema.sparse_columns.empty()) {
        // Non-sparse: read all fields sequentially
        for (size_t i = 0; i < schema.field_types.size(); i++) {
            offset = readField(buf, offset, schema.field_types[i], fields[i]);
        }
    } else {
        // Sparse record: read non-sparse fields, then sparse count + sparse fields
        for (size_t i = 0; i < schema.field_types.size(); i++) {
            if (schema.sparse_columns.count(static_cast<int>(i))) {
                fields[i].type = schema.field_types[i];
                fields[i].is_null = true;
            } else {
                offset = readField(buf, offset, schema.field_types[i], fields[i]);
            }
        }
        int sparse_count = static_cast<int>(readByte(buf + offset));
        offset += 1;
        for (int s = 0; s < sparse_count; s++) {
            int col_idx = static_cast<int>(readByte(buf + offset));
            offset += 1;
            if (col_idx >= 0 && col_idx < static_cast<int>(schema.field_types.size())) {
                offset = readField(buf, offset, schema.field_types[col_idx], fields[col_idx]);
            }
        }
    }
    return offset;
}

// ----- DBParms -----

// Buffer 0 layout:
//   byte[0]  = node type (should be CHAINED_BUFFER_DATA_NODE = 9)
//   int[1..4] = data_length
//   byte[5]  = version (should be 1)
//   int[6..9], int[10..13], ... = parameter values

bool DBParms::read(const std::vector<uint8_t>& buf0) {
    if (buf0.size() < 10) return false;

    uint8_t node_type = buf0[0];
    if (node_type != 9) return false; // CHAINED_BUFFER_DATA_NODE

    int32_t data_length = readInt(buf0.data() + 1);
    uint8_t version = buf0[5];
    if (version != 1) return false;

    int32_t parm_count = (data_length - 1) / 4; // subtract version byte
    if (parm_count > 0) {
        // Parameter 0 = master table root buffer ID
        master_table_root = readInt(buf0.data() + 6);
    }
    return true;
}

} // namespace ghidra_db
