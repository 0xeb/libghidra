// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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

    // Set the program image-base offset added to RELOCATABLE default-space keys.
    // Ghidra stores function-symbol address keys image-base-relative (AddressMapDB
    // RELOCATABLE decode adds baseImageOffset), so the offline reader must apply the
    // same offset or every decoded function address is image-base-too-low (e.g. a
    // function at 0x401000 in a 0x400000-based program decodes to 0x1000). Sourced
    // from the "Image Offset" key in the "Program" options table.
    void setImageBaseOffset(uint64_t v) { image_base_offset_ = v; }

private:
    // Base addresses indexed by their ID
    std::map<int32_t, uint64_t> base_addresses_;
    uint64_t image_base_offset_ = 0;
};

} // namespace ghidra_db
