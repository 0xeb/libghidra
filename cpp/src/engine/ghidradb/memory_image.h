// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// MemoryImage: reconstructs a program's loaded memory image from the Ghidra
// project database, so the offline decompiler can read bytes at their real
// (image-base-relative) virtual addresses WITHOUT the original binary file.
//
// Why this exists: the C++ engine has no PE/ELF loader. Given only the project,
// it used to raw-load the external .exe at base 0 while functions live at the
// image base (e.g. 0x140001000) — so every offline decompile read past-EOF zero
// fill and produced garbage. Ghidra, however, stores the ORIGINAL image bytes
// INSIDE the project db (the "File Bytes" table, as ChainedBuffer streams) and a
// virtual-address -> file-offset map (the "Memory Blocks" / "Sub Memory Blocks"
// tables). This reader decodes all three and serves bytes at real VAs.
//
// Mapping (verified against a real x64 PE fixture):
//   Memory Blocks[k]       -> { encoded Start Address (decoded via AddressDecoder,
//                                image-base applied), Length }
//   Sub Memory Blocks[j]   -> { Parent block id, Type, Length, Starting Offset,
//                                Source ID (= File Bytes key), Source Offset }
//                             (Type==4 == FileBytes-backed; others carry no bytes)
//   File Bytes[id]         -> original bytes, recovered from the "Chain Buffer IDs"
//                             ChainedBuffer (de-obfuscated), length == its Size col
//
// A Type-4 sub-block therefore covers VA range
//   [ block_start_VA + starting_offset, + length )
// and maps byte k of that range to File Bytes[source_id][source_offset + k].

#pragma once
#include "address_map.h"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ghidra_db {

class MemoryImage {
public:
    // One contiguous initialized region: [va, va+length) reads from
    // file_bytes_[file_bytes_id] starting at file_offset.
    struct Segment {
        uint64_t va = 0;
        uint64_t length = 0;
        int64_t file_bytes_id = 0;
        uint64_t file_offset = 0;
    };

    // Load the memory image from a project .gbf. Returns false (with getError())
    // if the db has no File Bytes / Memory Blocks (e.g. a non-imported project) or
    // a decode invariant fails.
    bool load(const std::string& gbf_path);

    // True once load() reconstructed at least one initialized segment.
    bool valid() const { return !segments_.empty(); }

    // Lowest / highest+1 virtual address covered by any block (initialized OR not).
    uint64_t imageBase() const { return image_base_; }
    uint64_t imageEnd() const { return image_end_; }

    // Copy len bytes of the loaded image starting at virtual address `va` into
    // dest. Bytes outside any initialized segment are zero-filled (matching an
    // uninitialized .bss read). Always writes exactly len bytes.
    void readBytes(uint64_t va, uint8_t* dest, uint64_t len) const;

    const std::vector<Segment>& segments() const { return segments_; }
    std::string getError() const { return error_; }

private:
    std::vector<Segment> segments_;                    // sorted by va
    std::map<int64_t, std::vector<uint8_t>> file_bytes_;  // File Bytes key -> bytes
    uint64_t image_base_ = 0;
    uint64_t image_end_ = 0;
    std::string error_;
};

} // namespace ghidra_db
