// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once
#include "db_record.h"
#include "buffer_file.h"
#include <functional>

namespace ghidra_db {

// Node type bytes (from NodeMgr.java)
enum NodeType : uint8_t {
    LONGKEY_INTERIOR_NODE  = 0,
    LONGKEY_VAR_REC_NODE   = 1,
    LONGKEY_FIXED_REC_NODE = 2,
    VARKEY_INTERIOR_NODE   = 3,
    VARKEY_REC_NODE        = 4,
    FIXEDKEY_INTERIOR_NODE = 5,
    FIXEDKEY_VAR_REC_NODE  = 6,
    FIXEDKEY_FIXED_REC_NODE= 7,
    CHAINED_BUFFER_INDEX   = 8,
    CHAINED_BUFFER_DATA    = 9,
};

// Callback: receives each record. Return false to stop iteration.
using RecordCallback = std::function<bool(const Record& record)>;

// BTreeReader: reads tables from a .gbf buffer file.
// Supports LongKey (types 0,1,2) and VarKey (types 3,4) node traversal.
class BTreeReader {
public:
    explicit BTreeReader(BufferFile& bf) : bf_(bf) {}

    // Iterate all records in a table rooted at the given buffer ID.
    // Calls cb for each record. Returns false on error.
    bool iterateRecords(int32_t root_buffer_id, const Schema& schema, RecordCallback cb);

    std::string getError() const { return error_; }

private:
    BufferFile& bf_;
    std::string error_;

    // Recursive traversal for LongKey interior nodes -> leaf nodes
    bool traverseLongKey(int32_t buffer_id, const Schema& schema, RecordCallback& cb);

    // Read all records from a LongKey variable-record leaf (type 1)
    bool readVarRecLeaf(const std::vector<uint8_t>& buf, const Schema& schema, RecordCallback& cb);

    // Read all records from a LongKey fixed-record leaf (type 2)
    bool readFixedRecLeaf(const std::vector<uint8_t>& buf, const Schema& schema, RecordCallback& cb);

    // Recursive traversal for VarKey interior nodes -> leaf nodes
    bool traverseVarKey(int32_t buffer_id, const Schema& schema, RecordCallback& cb);

    // Read all records from a VarKey record leaf (type 4)
    bool readVarKeyRecLeaf(const std::vector<uint8_t>& buf, const Schema& schema, RecordCallback& cb);

    // Read data from a chained buffer
    bool readChainedBuffer(int32_t buffer_id, std::vector<uint8_t>& out);
};

// Read the master table from a .gbf file.
// Returns all table entries (table name, schema, root buffer, record count).
bool readMasterTable(BufferFile& bf, int32_t master_root_id,
                     std::vector<MasterTableEntry>& entries);

} // namespace ghidra_db
