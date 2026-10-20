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
//                             (Type==4 == FileBytes-backed; Type==2 == BUFFER,
//                              Source ID naming its own chained buffer; others
//                              carry no bytes)
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
        int64_t file_bytes_id = 0;  // a File Bytes key, or kBufferSource - buffer id
        uint64_t file_offset = 0;
        int64_t block_id = 0;       // the "Memory Blocks" key it belongs to
    };

    // One run of bytes outside the flattened image span (see outsideImage()).
    struct Run {
        uint64_t va = 0;
        std::vector<uint8_t> bytes;
    };

    // MemoryBlock permission bits as the "Memory Blocks" Flags column stores them.
    static constexpr uint8_t kExecute = 0x01;
    static constexpr uint8_t kWrite = 0x02;
    static constexpr uint8_t kRead = 0x04;
    static constexpr uint8_t kVolatile = 0x08;
    static constexpr uint8_t kArtificial = 0x10;

    // One row of the program's memory map, the block list the live host reports
    // (Program.getMemory().getBlocks()). An address is mapped exactly when a
    // block contains it.
    struct Block {
        std::string name;
        std::string comment;
        std::string source_name;
        std::string space;          // ADDRESS MAP space of the start ("ram", an overlay)
        uint64_t start = 0;
        uint64_t length = 0;
        uint8_t flags = 0;          // kRead / kWrite / kExecute / kVolatile / kArtificial
        bool initialized = false;   // some sub-block holds bytes (not UNINITIALIZED)
    };

    // Load the memory image from a project .gbf. Returns false (with getError())
    // if the db has no File Bytes / Memory Blocks (e.g. a non-imported project) or
    // a decode invariant fails. The block list (blocks()) is kept whenever the
    // "Memory Blocks" table was read, even if no image bytes are.
    bool load(const std::string& gbf_path);

    // The program's memory blocks, in address order.
    const std::vector<Block>& blocks() const { return blocks_; }

    // True once load() reconstructed at least one initialized segment.
    bool valid() const { return !segments_.empty(); }

    // Lowest / highest+1 virtual address of the image proper: every segment of a
    // block that holds file bytes. A block whose bytes all live in BUFFER
    // sub-blocks (a PE's `tdb`, far above the image) is outside it.
    uint64_t imageBase() const { return image_base_; }
    uint64_t imageEnd() const { return image_end_; }

    // Copy len bytes of the loaded image starting at virtual address `va` into
    // dest. Bytes outside any initialized segment are zero-filled (matching an
    // uninitialized .bss read). Always writes exactly len bytes.
    void readBytes(uint64_t va, uint8_t* dest, uint64_t len) const;

    // The initialized bytes outside [imageBase(), imageEnd()), one run per
    // contiguous stretch of segments, in address order.
    std::vector<Run> outsideImage() const;

    const std::vector<Segment>& segments() const { return segments_; }
    std::string getError() const { return error_; }

private:
    std::vector<Segment> segments_;                    // sorted by va
    std::vector<Block> blocks_;                        // sorted by start
    std::map<int64_t, std::vector<uint8_t>> file_bytes_;  // File Bytes key -> bytes
    uint64_t image_base_ = 0;
    uint64_t image_end_ = 0;
    std::string error_;
};

} // namespace ghidra_db
