// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "address_map.h"

namespace ghidra_db {

// Address type constants (top 4 bits of the 64-bit key)
static constexpr int ADDR_TYPE_SIZE = 4;
static constexpr int64_t ADDR_TYPE_SHIFT = 64 - ADDR_TYPE_SIZE;
static constexpr int64_t ADDR_TYPE_MASK = 0xFLL;
static constexpr int ADDR_OFFSET_SIZE = 32;
static constexpr int64_t ADDR_OFFSET_MASK = 0xFFFFFFFFLL;
static constexpr int64_t ID_MASK = 0x0FFFFFFFLL; // 28 bits

static constexpr int OLD_ADDRESS_KEY_TYPE   = 0;
static constexpr int ABSOLUTE_ADDR_TYPE     = 1;
static constexpr int RELOCATABLE_ADDR_TYPE  = 2;
static constexpr int REGISTER_ADDR_TYPE     = 3;
static constexpr int STACK_ADDR_TYPE        = 4;
static constexpr int EXTERNAL_ADDR_TYPE     = 5;
static constexpr int NO_ADDR_TYPE           = 15;

bool AddressDecoder::load(BufferFile& bf, const std::vector<MasterTableEntry>& tables) {
    // Find the "ADDRESS MAP" table
    const MasterTableEntry* map_table = nullptr;
    for (auto& t : tables) {
        if (t.name == "ADDRESS MAP" && t.indexed_column == -1) {
            map_table = &t;
            break;
        }
    }

    base_addresses_.clear();
    image_base_offset_ = 0;

    if (!map_table || map_table->root_buffer_id < 0) {
        // No address map table -- use legacy mode (type 0 keys)
        // In legacy mode, the key IS the address
        return true;
    }

    // Read all address map entries.
    // V1 schema: Key(Long), SpaceName(String), Segment(Int), Deleted(Boolean)
    // V0 schema: Key(Long), SpaceName(String), Segment(Short)
    BTreeReader reader(bf);
    reader.iterateRecords(map_table->root_buffer_id, map_table->schema,
        [&](const Record& rec) -> bool {
            int64_t base_key = rec.key.long_val;
            // The key is the index (0, 1, 2, ...)
            int32_t index = static_cast<int32_t>(base_key);

            // For the address map, the "base address" is derived from the space.
            // In the common case (RAM space), the base is 0.
            // The segment field encodes additional offset information.
            int32_t segment = 0;
            if (rec.fields.size() > 1) {
                segment = rec.fields[1].asInt();
            }

            // Base address = segment shifted to form upper 32 bits
            // For most programs, segment=0 and base=0 (single RAM space)
            base_addresses_[index] = static_cast<uint64_t>(segment) << 32;
            return true;
        });

    return true;
}

uint64_t AddressDecoder::decodeAddress(int64_t key) const {
    int type = static_cast<int>((static_cast<uint64_t>(key) >> ADDR_TYPE_SHIFT) & ADDR_TYPE_MASK);
    int32_t base_index = static_cast<int32_t>(
        (static_cast<uint64_t>(key) >> ADDR_OFFSET_SIZE) & ID_MASK);
    uint64_t offset = static_cast<uint64_t>(key) & ADDR_OFFSET_MASK;

    switch (type) {
        case OLD_ADDRESS_KEY_TYPE:
            // Legacy: key is the raw address (pre-AddressMap)
            return static_cast<uint64_t>(key);

        case ABSOLUTE_ADDR_TYPE:
        case RELOCATABLE_ADDR_TYPE: {
            auto it = base_addresses_.find(base_index);
            uint64_t base = (it != base_addresses_.end()) ? it->second : 0;
            uint64_t addr = base + offset;
            if (type == RELOCATABLE_ADDR_TYPE) {
                addr += image_base_offset_;
            }
            return addr;
        }

        case REGISTER_ADDR_TYPE:
        case STACK_ADDR_TYPE:
        case EXTERNAL_ADDR_TYPE:
            // These address types don't correspond to code/data addresses
            return offset;

        case NO_ADDR_TYPE:
        default:
            return 0;
    }
}

bool AddressDecoder::isMemoryAddress(int64_t key) const {
    int type = static_cast<int>((static_cast<uint64_t>(key) >> ADDR_TYPE_SHIFT) & ADDR_TYPE_MASK);
    return type == OLD_ADDRESS_KEY_TYPE ||
           type == ABSOLUTE_ADDR_TYPE ||
           type == RELOCATABLE_ADDR_TYPE;
}

} // namespace ghidra_db
