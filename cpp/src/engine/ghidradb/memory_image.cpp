// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_image.h"
#include "buffer_file.h"
#include "db_record.h"
#include "btree.h"

#include <algorithm>
#include <cstring>

namespace ghidra_db {

namespace {

// Ghidra SubMemoryBlock subtype byte (MemoryMapDBAdapter): only FILE_BYTES-backed
// sub-blocks carry recoverable original image bytes. Bit/byte-mapped and
// uninitialized sub-blocks have no bytes here (an uninitialized read is zero).
constexpr uint8_t kSubTypeFileBytes = 4;

// Resolve a column's index by name (robust to schema-version column drift),
// falling back to the given default index if the name is absent.
int colByName(const Schema& s, const char* name, int fallback) {
    for (size_t i = 0; i < s.field_names.size(); ++i)
        if (s.field_names[i] == name) return static_cast<int>(i);
    return fallback;
}

// Decode the head ChainedBuffer id from a "Chain Buffer IDs" binary field. Ghidra
// stores a single head-buffer id (the ChainedBuffer itself spans many data blocks
// via its own index), encoded big-endian in the trailing 4 bytes.
bool decodeHeadBufferId(const std::vector<uint8_t>& bin, int32_t& out_id) {
    if (bin.size() < 4) return false;
    out_id = readInt(bin.data() + static_cast<int32_t>(bin.size()) - 4);
    return true;
}

}  // namespace

bool MemoryImage::load(const std::string& gbf_path) {
    BufferFile bf;
    if (!bf.open(gbf_path)) {
        error_ = "Failed to open .gbf: " + bf.getError();
        return false;
    }

    std::vector<uint8_t> buf0;
    if (!bf.readBuffer(0, buf0)) {
        error_ = "Failed to read buffer 0";
        return false;
    }
    DBParms parms;
    if (!parms.read(buf0)) {
        error_ = "Failed to parse DBParms";
        return false;
    }

    std::vector<MasterTableEntry> tables;
    if (!readMasterTable(bf, parms.master_table_root, tables)) {
        error_ = "Failed to read master table";
        return false;
    }

    // Address decoder + image-base offset (same source as ghidra_project.cpp: the
    // "Image Offset" key in the "Program" options table). Block Start Addresses
    // are RELOCATABLE keys that decode image-base-relative just like symbols.
    AddressDecoder addr_dec;
    addr_dec.load(bf, tables);
    for (const auto& t : tables) {
        if (t.name != "Program" || t.indexed_column != -1) continue;
        BTreeReader reader(bf);
        reader.iterateRecords(t.root_buffer_id, t.schema, [&](const Record& rec) -> bool {
            if (rec.key.asString().find("Image Offset") != std::string::npos &&
                !rec.fields.empty()) {
                addr_dec.setImageBaseOffset(
                    std::strtoull(rec.fields[0].asString().c_str(), nullptr, 16));
            }
            return true;
        });
    }

    // --- File Bytes: recover each original-image stream ---
    for (const auto& t : tables) {
        if (t.name != "File Bytes") continue;
        const int c_size = colByName(t.schema, "Size", 2);
        const int c_chain = colByName(t.schema, "Chain Buffer IDs", 3);
        BTreeReader reader(bf);
        reader.iterateRecords(t.root_buffer_id, t.schema, [&](const Record& rec) -> bool {
            if (c_chain >= static_cast<int>(rec.fields.size())) return true;
            int32_t head_id = 0;
            if (!decodeHeadBufferId(rec.fields[c_chain].binary_val, head_id)) return true;
            std::vector<uint8_t> bytes;
            if (!reader.readDataChain(head_id, bytes)) {
                error_ = "File Bytes chain read failed (buffer " +
                         std::to_string(head_id) + "): " + reader.getError();
                return false;
            }
            // Invariant: the recovered stream length must equal the record's Size.
            // A mismatch means the buffer-id decode or chain walk is wrong — fail
            // loudly rather than serve truncated/garbage image bytes.
            if (c_size < static_cast<int>(rec.fields.size())) {
                uint64_t want = static_cast<uint64_t>(rec.fields[c_size].asLong());
                if (want != bytes.size()) {
                    error_ = "File Bytes size mismatch: record says " +
                             std::to_string(want) + ", recovered " +
                             std::to_string(bytes.size());
                    return false;
                }
            }
            file_bytes_[rec.key.asLong()] = std::move(bytes);
            return true;
        });
    }
    if (file_bytes_.empty()) {
        error_ = "project has no File Bytes (not an imported program image)";
        return false;
    }

    // --- Memory Blocks: block id -> (decoded VA, length) ---
    struct BlockVa { uint64_t va; uint64_t length; };
    std::map<int64_t, BlockVa> blocks;
    for (const auto& t : tables) {
        if (t.name != "Memory Blocks") continue;
        const int c_start = colByName(t.schema, "Start Address", 4);
        const int c_len = colByName(t.schema, "Length", 5);
        BTreeReader reader(bf);
        reader.iterateRecords(t.root_buffer_id, t.schema, [&](const Record& rec) -> bool {
            if (c_start >= static_cast<int>(rec.fields.size())) return true;
            uint64_t va = addr_dec.decodeAddress(rec.fields[c_start].asLong());
            uint64_t len = c_len < static_cast<int>(rec.fields.size())
                               ? static_cast<uint64_t>(rec.fields[c_len].asLong())
                               : 0;
            blocks[rec.key.asLong()] = {va, len};
            return true;
        });
    }

    // --- Sub Memory Blocks: build the initialized (FileBytes-backed) segments ---
    for (const auto& t : tables) {
        if (t.name != "Sub Memory Blocks") continue;
        const int c_parent = colByName(t.schema, "Parent ID", 0);
        const int c_type = colByName(t.schema, "Type", 1);
        const int c_len = colByName(t.schema, "Length", 2);
        const int c_startoff = colByName(t.schema, "Starting Offset", 3);
        const int c_srcid = colByName(t.schema, "Source ID", 4);
        const int c_srcoff = colByName(t.schema, "Source Address/Offset", 5);
        const int need = std::max({c_parent, c_type, c_len, c_startoff, c_srcid, c_srcoff});
        BTreeReader reader(bf);
        reader.iterateRecords(t.root_buffer_id, t.schema, [&](const Record& rec) -> bool {
            if (need >= static_cast<int>(rec.fields.size())) return true;
            if (static_cast<uint8_t>(rec.fields[c_type].asLong()) != kSubTypeFileBytes)
                return true;  // only FileBytes-backed sub-blocks carry bytes
            int64_t parent = rec.fields[c_parent].asLong();
            auto it = blocks.find(parent);
            if (it == blocks.end()) return true;
            int64_t src = rec.fields[c_srcid].asLong();
            if (file_bytes_.find(src) == file_bytes_.end()) return true;

            Segment seg;
            seg.va = it->second.va + static_cast<uint64_t>(rec.fields[c_startoff].asLong());
            seg.length = static_cast<uint64_t>(rec.fields[c_len].asLong());
            seg.file_bytes_id = src;
            seg.file_offset = static_cast<uint64_t>(rec.fields[c_srcoff].asLong());
            // Clamp a segment that would read past its FileBytes stream.
            uint64_t avail = file_bytes_[src].size();
            if (seg.file_offset >= avail) return true;
            seg.length = std::min(seg.length, avail - seg.file_offset);
            if (seg.length > 0) segments_.push_back(seg);
            return true;
        });
    }

    if (segments_.empty()) {
        error_ = "no FileBytes-backed memory segments reconstructed";
        return false;
    }
    std::sort(segments_.begin(), segments_.end(),
              [](const Segment& a, const Segment& b) { return a.va < b.va; });

    image_base_ = segments_.front().va;
    image_end_ = 0;
    for (const auto& s : segments_)
        image_end_ = std::max(image_end_, s.va + s.length);
    return true;
}

void MemoryImage::readBytes(uint64_t va, uint8_t* dest, uint64_t len) const {
    std::memset(dest, 0, len);
    // Saturate address arithmetic so malformed/adversarial input (a huge len or a
    // high-VA segment) can never wrap uint64 (normal images never overflow).
    const uint64_t req_end = (va + len < va) ? UINT64_MAX : va + len;
    for (const auto& s : segments_) {
        const uint64_t s_end = (s.va + s.length < s.va) ? UINT64_MAX : s.va + s.length;
        if (s_end <= va || s.va >= req_end) continue;  // no overlap
        uint64_t ov_start = std::max(va, s.va);
        uint64_t ov_end = std::min(req_end, s_end);
        const auto& bytes = file_bytes_.at(s.file_bytes_id);
        uint64_t src_off = s.file_offset + (ov_start - s.va);
        uint64_t n = ov_end - ov_start;
        // Clamp without forming src_off + n (which could wrap): drop the segment
        // if src_off is past the buffer, else cap n to what remains.
        if (src_off >= bytes.size()) continue;
        if (n > bytes.size() - src_off) n = bytes.size() - src_off;
        std::memcpy(dest + (ov_start - va), bytes.data() + src_off, n);
    }
}

} // namespace ghidra_db
