// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "btree.h"
#include <algorithm>

namespace ghidra_db {

// -----------------------------------------------------------------------
// Node layout constants (from Java sources)
// -----------------------------------------------------------------------

// All nodes: byte 0 = node type
static constexpr int NODE_HEADER_SIZE = 1;

// LongKeyNode header: NodeType(1) + KeyCount(4) = 5 bytes
static constexpr int LONGKEY_NODE_HEADER_SIZE = NODE_HEADER_SIZE + 4;

// LongKeyRecordNode header adds PrevLeafId(4) + NextLeafId(4)
static constexpr int LONGKEY_LEAF_HEADER_SIZE = LONGKEY_NODE_HEADER_SIZE + 8;

// LongKey interior: entries start after header, each = Key(8) + ChildID(4) = 12 bytes
static constexpr int LK_INTERIOR_ENTRY_SIZE = 12;

// VarRecNode (type 1): entry = Key(8) + RecOffset(4) + IndFlag(1) = 13 bytes
static constexpr int VARREC_ENTRY_SIZE = 13;

// FixedRecNode (type 2): entry = Key(8) + Record(N) bytes (N = schema fixed_length)
static constexpr int FIXEDREC_KEY_SIZE = 8;

// VarKeyNode header: NodeType(1) + KeyType(1) + KeyCount(4) = 6 bytes
static constexpr int VARKEY_NODE_HEADER_SIZE = 6;

// VarKeyRecordNode header adds PrevLeafId(4) + NextLeafId(4) = 8
static constexpr int VARKEY_LEAF_HEADER_SIZE = VARKEY_NODE_HEADER_SIZE + 8;

// VarKey interior: entry = KeyOffset(4) + ChildID(4) = 8
static constexpr int VK_INTERIOR_ENTRY_SIZE = 8;

// VarKeyRecordNode: entry = KeyOffset(4) + IndFlag(1) = 5
static constexpr int VK_REC_ENTRY_SIZE = 5;

// -----------------------------------------------------------------------
// ChainedBuffer reading
// -----------------------------------------------------------------------

// Ghidra's ChainedBuffer XOR de-obfuscation mask (ChainedBuffer.java:62-80),
// exactly 128 bytes. Ghidra applies it with the offset reset to 0 at each data
// node boundary (getBytes reseeds bufferDataOffset=0 per node), so a global
// index over a concatenation of nodes is wrong when a node's data size is not a
// multiple of 128.
static const uint8_t kChainedBufferXorMask[128] = {
    0x59, 0xea, 0x67, 0x23, 0xda, 0xb8, 0x00, 0xb8,
    0xc3, 0x48, 0xdd, 0x8b, 0x21, 0xd6, 0x94, 0x78,
    0x35, 0xab, 0x2b, 0x7e, 0xb2, 0x4f, 0x82, 0x4e,
    0x0e, 0x16, 0xc4, 0x57, 0x12, 0x8e, 0x7e, 0xe6,
    0xb6, 0xbd, 0x56, 0x91, 0x57, 0x72, 0xe6, 0x91,
    0xdc, 0x52, 0x2e, 0xf2, 0x1a, 0xb7, 0xd6, 0x6f,
    0xda, 0xde, 0xe8, 0x48, 0xb1, 0xbb, 0x50, 0x6f,
    0xf4, 0xdd, 0x11, 0xee, 0xf2, 0x67, 0xfe, 0x48,
    0x8d, 0xae, 0x69, 0x1a, 0xe0, 0x26, 0x8c, 0x24,
    0x8e, 0x17, 0x76, 0x51, 0xe2, 0x60, 0xd7, 0xe6,
    0x83, 0x65, 0xd5, 0xf0, 0x7f, 0xf2, 0xa0, 0xd6,
    0x4b, 0xbd, 0x24, 0xd8, 0xab, 0xea, 0x9e, 0xa6,
    0x48, 0x94, 0x3e, 0x7b, 0x2c, 0xf4, 0xce, 0xdc,
    0x69, 0x11, 0xf8, 0x3c, 0xa7, 0x3f, 0x5d, 0x77,
    0x94, 0x3f, 0xe4, 0x8e, 0x48, 0x20, 0xdb, 0x56,
    0x32, 0xc1, 0x87, 0x01, 0x2e, 0xe3, 0x7f, 0x40,
};

bool BTreeReader::readChainedBuffer(int32_t buffer_id, std::vector<uint8_t>& out) {
    std::vector<uint8_t> buf;
    if (!bf_.readBuffer(buffer_id, buf)) {
        error_ = "Failed to read chained buffer " + std::to_string(buffer_id);
        return false;
    }

    uint8_t node_type = buf[0];

    if (node_type == CHAINED_BUFFER_DATA) {
        // Non-indexed: NodeType(1) + DataLength(4) + data...
        int32_t data_len = readInt(buf.data() + 1);
        bool obfuscated = (data_len < 0);
        if (obfuscated) {
            // Clear the obfuscation flag bit (MSB), matching Ghidra
            // ChainedBuffer.java: size &= Integer.MAX_VALUE. (Was -data_len-1, a
            // complement that yields a bogus ~2^31 length and over-reads the
            // INDEX path, which has no clamp.)
            data_len &= 0x7FFFFFFF;
        }
        int32_t data_offset = 5; // 1 + 4
        if (data_offset + data_len > static_cast<int32_t>(buf.size())) {
            data_len = static_cast<int32_t>(buf.size()) - data_offset;
        }
        out.assign(buf.begin() + data_offset, buf.begin() + data_offset + data_len);

        if (obfuscated) {
            // Single data node: the output index already equals the node offset.
            for (size_t i = 0; i < out.size(); i++) {
                out[i] ^= kChainedBufferXorMask[i % 128];
            }
        }
        return true;
    }

    if (node_type == CHAINED_BUFFER_INDEX) {
        // Indexed chained buffer:
        // NodeType(1) + DataLength(4) + NextIndexId(4) + [BufferId(4)...]
        int32_t data_len = readInt(buf.data() + 1);
        bool obfuscated = (data_len < 0);
        if (obfuscated) {
            // Clear the obfuscation flag bit (MSB), matching Ghidra
            // ChainedBuffer.java: size &= Integer.MAX_VALUE. (Was -data_len-1, a
            // complement that yields a bogus ~2^31 length and over-reads the
            // INDEX path, which has no clamp.)
            data_len &= 0x7FFFFFFF;
        }
        // int32_t next_index_id = readInt(buf.data() + 5); // for multi-index chains
        int32_t index_base = 9; // 1+4+4
        int32_t ids_per_node = (static_cast<int32_t>(buf.size()) - index_base) / 4;

        out.clear();
        out.reserve(data_len);

        int32_t remaining = data_len;
        for (int32_t i = 0; i < ids_per_node && remaining > 0; i++) {
            int32_t data_buf_id = readInt(buf.data() + index_base + i * 4);
            if (data_buf_id < 0) break;

            std::vector<uint8_t> data_buf;
            if (!bf_.readBuffer(data_buf_id, data_buf)) {
                error_ = "Failed to read indexed chain data buffer";
                return false;
            }
            // Data buffers: NodeType(1) + data...
            int32_t data_start = 1; // skip node type byte
            int32_t chunk = std::min(remaining,
                                     static_cast<int32_t>(data_buf.size()) - data_start);
            size_t chunk_begin = out.size();
            out.insert(out.end(), data_buf.begin() + data_start,
                       data_buf.begin() + data_start + chunk);
            if (obfuscated) {
                // Mask offset resets to 0 at each data-node boundary (Ghidra
                // getBytes reseeds bufferDataOffset=0 per node); a global index
                // over the concatenation is wrong when a node's data size is not
                // a multiple of 128.
                for (int32_t j = 0; j < chunk; j++) {
                    out[chunk_begin + j] ^= kChainedBufferXorMask[j % 128];
                }
            }
            remaining -= chunk;
        }
        return true;
    }

    error_ = "Unexpected chained buffer node type: " + std::to_string(node_type);
    return false;
}

// -----------------------------------------------------------------------
// LongKey traversal
// -----------------------------------------------------------------------

bool BTreeReader::traverseLongKey(int32_t buffer_id, const Schema& schema, RecordCallback& cb) {
    std::vector<uint8_t> buf;
    if (!bf_.readBuffer(buffer_id, buf)) {
        error_ = bf_.getError();
        return false;
    }
    if (buf.empty()) {
        error_ = "Empty buffer";
        return false;
    }

    uint8_t node_type = buf[0];
    switch (node_type) {
        case LONGKEY_INTERIOR_NODE: {
            // Header: NodeType(1) + KeyCount(4)
            int32_t key_count = readInt(buf.data() + 1);
            // Entries at offset 5: Key(8) + ChildID(4)
            for (int32_t i = 0; i < key_count; i++) {
                int32_t entry_off = LONGKEY_NODE_HEADER_SIZE + i * LK_INTERIOR_ENTRY_SIZE;
                // skip key at entry_off
                int32_t child_id = readInt(buf.data() + entry_off + 8);
                if (!traverseLongKey(child_id, schema, cb))
                    return false;
            }
            return true;
        }
        case LONGKEY_VAR_REC_NODE:
            return readVarRecLeaf(buf, schema, cb);
        case LONGKEY_FIXED_REC_NODE:
            return readFixedRecLeaf(buf, schema, cb);
        default:
            error_ = "Unexpected LongKey node type: " + std::to_string(node_type);
            return false;
    }
}

bool BTreeReader::readVarRecLeaf(const std::vector<uint8_t>& buf, const Schema& schema,
                                 RecordCallback& cb) {
    // Header: NodeType(1) + KeyCount(4) + PrevLeafId(4) + NextLeafId(4) = 13 bytes
    int32_t key_count = readInt(buf.data() + 1);

    for (int32_t i = 0; i < key_count; i++) {
        int32_t entry_off = LONGKEY_LEAF_HEADER_SIZE + i * VARREC_ENTRY_SIZE;
        int64_t key = readLong(buf.data() + entry_off);
        int32_t rec_offset = readInt(buf.data() + entry_off + 8);
        uint8_t ind_flag = buf[entry_off + 12];

        Record rec;
        rec.key.type = FieldType::LONG;
        rec.key.long_val = key;

        if (ind_flag != 0) {
            // Indirect: record data is in a chained buffer
            int32_t chain_buf_id = readInt(buf.data() + rec_offset);
            std::vector<uint8_t> chain_data;
            if (!readChainedBuffer(chain_buf_id, chain_data)) return false;
            rec.read(chain_data.data(), 0, schema);
        } else {
            rec.read(buf.data(), rec_offset, schema);
        }

        if (!cb(rec)) return true; // stopped by caller
    }
    return true;
}

bool BTreeReader::readFixedRecLeaf(const std::vector<uint8_t>& buf, const Schema& schema,
                                   RecordCallback& cb) {
    // Header: NodeType(1) + KeyCount(4) + PrevLeafId(4) + NextLeafId(4) = 13 bytes
    int32_t key_count = readInt(buf.data() + 1);
    int32_t entry_size = FIXEDREC_KEY_SIZE + schema.fixed_length;

    for (int32_t i = 0; i < key_count; i++) {
        int32_t entry_off = LONGKEY_LEAF_HEADER_SIZE + i * entry_size;
        int64_t key = readLong(buf.data() + entry_off);

        Record rec;
        rec.key.type = FieldType::LONG;
        rec.key.long_val = key;
        rec.read(buf.data(), entry_off + FIXEDREC_KEY_SIZE, schema);

        if (!cb(rec)) return true;
    }
    return true;
}

// -----------------------------------------------------------------------
// VarKey traversal
// -----------------------------------------------------------------------

bool BTreeReader::traverseVarKey(int32_t buffer_id, const Schema& schema, RecordCallback& cb) {
    std::vector<uint8_t> buf;
    if (!bf_.readBuffer(buffer_id, buf)) {
        error_ = bf_.getError();
        return false;
    }
    if (buf.empty()) {
        error_ = "Empty buffer";
        return false;
    }

    uint8_t node_type = buf[0];
    switch (node_type) {
        case VARKEY_INTERIOR_NODE: {
            // Header: NodeType(1) + KeyType(1) + KeyCount(4)
            int32_t key_count = readInt(buf.data() + 2);
            // Entries at offset 6: KeyOffset(4) + ChildID(4)
            for (int32_t i = 0; i < key_count; i++) {
                int32_t entry_off = VARKEY_NODE_HEADER_SIZE + i * VK_INTERIOR_ENTRY_SIZE;
                // skip key offset at entry_off
                int32_t child_id = readInt(buf.data() + entry_off + 4);
                if (!traverseVarKey(child_id, schema, cb))
                    return false;
            }
            return true;
        }
        case VARKEY_REC_NODE:
            return readVarKeyRecLeaf(buf, schema, cb);
        default:
            error_ = "Unexpected VarKey node type: " + std::to_string(node_type);
            return false;
    }
}

// Read the variable-length key from the buffer at the given offset.
// Returns: the key as a FieldValue plus the number of bytes consumed by the key.
static int32_t readVarKeyField(const uint8_t* buf, int32_t offset, FieldType key_type,
                                FieldValue& out) {
    return readField(buf, offset, key_type, out);
}

bool BTreeReader::readVarKeyRecLeaf(const std::vector<uint8_t>& buf, const Schema& schema,
                                    RecordCallback& cb) {
    // Header: NodeType(1) + KeyType(1) + KeyCount(4) + PrevLeafId(4) + NextLeafId(4) = 14
    int32_t key_count = readInt(buf.data() + 2);
    FieldType key_field_type = schema.key_type;

    for (int32_t i = 0; i < key_count; i++) {
        int32_t entry_off = VARKEY_LEAF_HEADER_SIZE + i * VK_REC_ENTRY_SIZE;
        int32_t key_offset = readInt(buf.data() + entry_off);
        uint8_t ind_flag = buf[entry_off + 4];

        // Read key at key_offset
        FieldValue key_val;
        int32_t after_key = readVarKeyField(buf.data(), key_offset, key_field_type, key_val);

        // Record data follows immediately after the key
        int32_t rec_offset = after_key;

        Record rec;
        rec.key = key_val;

        if (ind_flag != 0) {
            int32_t chain_buf_id = readInt(buf.data() + rec_offset);
            std::vector<uint8_t> chain_data;
            if (!readChainedBuffer(chain_buf_id, chain_data)) return false;
            rec.read(chain_data.data(), 0, schema);
        } else {
            rec.read(buf.data(), rec_offset, schema);
        }

        if (!cb(rec)) return true;
    }
    return true;
}

// -----------------------------------------------------------------------
// Top-level entry point
// -----------------------------------------------------------------------

bool BTreeReader::iterateRecords(int32_t root_buffer_id, const Schema& schema, RecordCallback cb) {
    if (root_buffer_id < 0) {
        // Empty table (root not yet allocated)
        return true;
    }

    // Peek at the root node type to decide LongKey vs VarKey traversal
    std::vector<uint8_t> buf;
    if (!bf_.readBuffer(root_buffer_id, buf)) {
        error_ = bf_.getError();
        return false;
    }
    if (buf.empty()) {
        error_ = "Empty root buffer";
        return false;
    }

    uint8_t node_type = buf[0];
    if (node_type <= LONGKEY_FIXED_REC_NODE) {
        return traverseLongKey(root_buffer_id, schema, cb);
    } else if (node_type == VARKEY_INTERIOR_NODE || node_type == VARKEY_REC_NODE) {
        return traverseVarKey(root_buffer_id, schema, cb);
    } else {
        error_ = "Unsupported root node type: " + std::to_string(node_type);
        return false;
    }
}

// -----------------------------------------------------------------------
// Master table reader
// -----------------------------------------------------------------------

// The master table uses LongKey nodes with a variable-length record schema:
//   Columns: TableName(String), SchemaVersion(Int), RootBufferId(Int),
//            KeyType(Byte), FieldTypes(Binary), FieldNames(String),
//            IndexColumn(Int), MaxKey(Long), RecordCount(Int)

static Schema masterTableSchema() {
    Schema s;
    s.version = 0;
    s.key_type = FieldType::LONG;
    s.field_types = {
        FieldType::STRING,  // 0: name
        FieldType::INT,     // 1: schema version
        FieldType::INT,     // 2: root buffer id
        FieldType::BYTE,    // 3: key type
        FieldType::BINARY,  // 4: field types
        FieldType::STRING,  // 5: field names (packed)
        FieldType::INT,     // 6: indexed column
        FieldType::LONG,    // 7: max key
        FieldType::INT,     // 8: record count
    };
    s.field_names = {
        "TableName", "SchemaVersion", "RootBufferId",
        "KeyType", "FieldTypes", "FieldNames",
        "IndexColumn", "MaxKey", "RecordCount"
    };
    s.is_variable_length = true;
    s.fixed_length = 0;
    return s;
}

bool readMasterTable(BufferFile& bf, int32_t master_root_id,
                     std::vector<MasterTableEntry>& entries) {
    entries.clear();
    Schema ms = masterTableSchema();
    BTreeReader reader(bf);

    bool ok = reader.iterateRecords(master_root_id, ms, [&](const Record& rec) -> bool {
        MasterTableEntry e;
        e.table_num = rec.key.long_val;
        e.name = rec.fields[0].asString();
        e.schema_version = rec.fields[1].asInt();
        e.root_buffer_id = rec.fields[2].asInt();
        uint8_t key_type_byte = static_cast<uint8_t>(rec.fields[3].byte_val);
        auto& field_types_bin = rec.fields[4].binary_val;
        std::string packed_names = rec.fields[5].asString();
        e.indexed_column = rec.fields[6].asInt();
        e.record_count = rec.fields[8].asInt();

        e.schema = Schema::decode(e.schema_version, key_type_byte, field_types_bin, packed_names);
        entries.push_back(std::move(e));
        return true;
    });

    return ok;
}

} // namespace ghidra_db
