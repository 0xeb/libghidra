// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once
#include "btree.h"
#include <map>

namespace ghidra_db {

// Address key encoding (from AddressMapDB.java):
//
// 64-bit key layout:  [Type:4][ID:28][Offset:32]
//
// Type codes:
//   0 = old format
//   1 = absolute
//   2 = relocatable (most common for code)
//   3 = register
//   4 = stack
//   5 = external
//   15 = no address
//
// For types 1 and 2: ID = base address index, Offset = 32-bit offset from base

// Address Map table entry (from "ADDRESS MAP" table)
struct AddrMapEntry {
    int64_t key;            // table key (= index)
    std::string space_name; // e.g. "ram", ".text"
    int32_t segment;        // segment value (V0: short, V1: int)
    bool is_deleted;        // V1 only: deleted flag
};

class AddressDecoder {
public:
    // Load the address map from the database tables.
    bool load(BufferFile& bf, const std::vector<MasterTableEntry>& tables);

    // Decode a 64-bit address key to a raw address offset.
    // Returns the address in the default (RAM) space.
    // For relocatable addresses, adds the base address.
    uint64_t decodeAddress(int64_t key) const;

    // Check if a key represents a real code/data address (types 1 or 2)
    bool isMemoryAddress(int64_t key) const;

private:
    // Base addresses indexed by their ID
    std::map<int32_t, uint64_t> base_addresses_;
    uint64_t image_base_offset_ = 0;
};

} // namespace ghidra_db
