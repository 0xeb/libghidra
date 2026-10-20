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
#include <set>

namespace ghidra_db {

namespace {

// Ghidra SubMemoryBlock subtype byte (MemoryMapDBAdapter): only FILE_BYTES-backed
// sub-blocks carry recoverable original image bytes. Bit/byte-mapped and
// uninitialized sub-blocks have no bytes here (an uninitialized read is zero).
constexpr uint8_t kSubTypeFileBytes = 4;
constexpr uint8_t kSubTypeUninitialized = 3;
constexpr uint8_t kSubTypeBuffer = 2;

// Segment source keys of BUFFER sub-blocks: below every File Bytes key (those are
// record keys, never negative), so the two never collide.
constexpr int64_t kBufferSource = -1;

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

    // --- Memory Blocks: the program's memory map (block id -> row) ---
    std::map<int64_t, Block> blocks;
    for (const auto& t : tables) {
        if (t.name != "Memory Blocks") continue;
        const int c_name = colByName(t.schema, "Name", 0);
        const int c_comment = colByName(t.schema, "Comments", 1);
        const int c_source = colByName(t.schema, "Source Name", 2);
        const int c_flags = colByName(t.schema, "Flags", 3);
        const int c_start = colByName(t.schema, "Start Address", 4);
        const int c_len = colByName(t.schema, "Length", 5);
        BTreeReader reader(bf);
        reader.iterateRecords(t.root_buffer_id, t.schema, [&](const Record& rec) -> bool {
            const int n = static_cast<int>(rec.fields.size());
            if (c_start >= n) return true;
            Block b;
            const int64_t key = rec.fields[c_start].asLong();
            b.start = addr_dec.decodeAddress(key);
            b.space = addr_dec.spaceName(key);
            b.length = c_len < n ? static_cast<uint64_t>(rec.fields[c_len].asLong()) : 0;
            if (c_name < n) b.name = rec.fields[c_name].asString();
            if (c_comment < n && !rec.fields[c_comment].is_null) b.comment = rec.fields[c_comment].asString();
            if (c_source < n && !rec.fields[c_source].is_null) b.source_name = rec.fields[c_source].asString();
            if (c_flags < n) b.flags = static_cast<uint8_t>(rec.fields[c_flags].asLong() & 0xff);
            blocks[rec.key.asLong()] = std::move(b);
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
            const uint8_t type = static_cast<uint8_t>(rec.fields[c_type].asLong());
            int64_t parent = rec.fields[c_parent].asLong();
            auto it = blocks.find(parent);
            if (it == blocks.end()) return true;
            // Every sub-block but an UNINITIALIZED one holds bytes.
            if (type != kSubTypeUninitialized) it->second.initialized = true;
            if (type == kSubTypeBuffer) {
                // BufferSubMemoryBlock: the bytes are a DBBuffer (a chained
                // buffer) whose id is the Source ID column, offset 0.
                const int32_t buffer_id = static_cast<int32_t>(rec.fields[c_srcid].asLong());
                std::vector<uint8_t> bytes;
                if (!reader.readDataChain(buffer_id, bytes)) {
                    error_ = "BUFFER sub-block chain read failed (buffer " +
                             std::to_string(buffer_id) + "): " + reader.getError();
                    return false;
                }
                Segment seg;
                seg.va = it->second.start + static_cast<uint64_t>(rec.fields[c_startoff].asLong());
                seg.length = std::min<uint64_t>(static_cast<uint64_t>(rec.fields[c_len].asLong()),
                                                bytes.size());
                seg.file_bytes_id = kBufferSource - buffer_id;
                seg.block_id = parent;
                file_bytes_[seg.file_bytes_id] = std::move(bytes);
                if (seg.length > 0) segments_.push_back(seg);
                return true;
            }
            if (type != kSubTypeFileBytes)
                return true;  // bit/byte-mapped sub-blocks carry no bytes of their own
            int64_t src = rec.fields[c_srcid].asLong();
            if (file_bytes_.find(src) == file_bytes_.end()) return true;

            Segment seg;
            seg.va = it->second.start + static_cast<uint64_t>(rec.fields[c_startoff].asLong());
            seg.length = static_cast<uint64_t>(rec.fields[c_len].asLong());
            seg.file_bytes_id = src;
            seg.file_offset = static_cast<uint64_t>(rec.fields[c_srcoff].asLong());
            seg.block_id = parent;
            // Clamp a segment that would read past its FileBytes stream.
            uint64_t avail = file_bytes_[src].size();
            if (seg.file_offset >= avail) return true;
            seg.length = std::min(seg.length, avail - seg.file_offset);
            if (seg.length > 0) segments_.push_back(seg);
            return true;
        });
    }

    // The block list stands even when the db carries no image bytes.
    for (auto& [id, b] : blocks) blocks_.push_back(std::move(b));
    std::sort(blocks_.begin(), blocks_.end(),
              [](const Block& a, const Block& b) { return a.start < b.start; });

    if (file_bytes_.empty()) {
        error_ = "project has no File Bytes (not an imported program image)";
        return false;
    }
    std::sort(segments_.begin(), segments_.end(),
              [](const Segment& a, const Segment& b) { return a.va < b.va; });

    // The image proper: the blocks that hold file bytes (a section's BUFFER
    // tail belongs to it); a BUFFER-only block such as `tdb` stays outside.
    std::set<int64_t> image_blocks;
    for (const auto& s : segments_)
        if (s.file_bytes_id > kBufferSource) image_blocks.insert(s.block_id);
    if (image_blocks.empty()) {
        error_ = "no FileBytes-backed memory segments reconstructed";
        return false;
    }
    image_base_ = UINT64_MAX;
    image_end_ = 0;
    for (const auto& s : segments_) {
        if (image_blocks.count(s.block_id) == 0) continue;
        image_base_ = std::min(image_base_, s.va);
        image_end_ = std::max(image_end_, s.va + s.length);
    }
    return true;
}

std::vector<MemoryImage::Run> MemoryImage::outsideImage() const {
    std::vector<Run> out;
    for (const auto& s : segments_) {
        if (s.va >= image_base_ && s.va + s.length <= image_end_) continue;
        // Adjacent segments (two sub-blocks of one block) make one run.
        if (out.empty() || out.back().va + out.back().bytes.size() != s.va)
            out.push_back(Run{s.va, {}});
        Run& r = out.back();
        const size_t at = r.bytes.size();
        r.bytes.resize(at + s.length);
        readBytes(s.va, r.bytes.data() + at, s.length);
    }
    return out;
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
