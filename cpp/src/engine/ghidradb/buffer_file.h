// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <memory>
#include <unordered_map>

namespace ghidra_db {

// A read-only view of a Ghidra .gbf (BufferFile) on disk.
// Provides block-level I/O: read any buffer by its index.
class BufferFile {
public:
    bool open(const std::string& path);
    std::string getError() const { return error_; }

    // Header fields
    int32_t bufferSize() const { return buffer_size_; }
    int32_t blockSize() const { return block_size_; }
    int32_t bufferCount() const { return buffer_count_; }

    // Named integer parameters from the .gbf header
    int32_t getParameter(const std::string& name) const;
    bool hasParameter(const std::string& name) const;

    // Read a buffer by its index (0-based). Returns buffer_size_ bytes.
    // The returned data excludes the 5-byte block prefix (flags + buffer ID).
    bool readBuffer(int32_t index, std::vector<uint8_t>& out);

private:
    std::ifstream file_;
    int32_t block_size_ = 0;
    int32_t buffer_size_ = 0;
    int32_t buffer_count_ = 0;
    std::unordered_map<std::string, int32_t> params_;
    std::string error_;
};

// Big-endian helpers for reading from a byte buffer.
inline uint8_t  readByte(const uint8_t* p) { return p[0]; }
inline int8_t   readSByte(const uint8_t* p) { return static_cast<int8_t>(p[0]); }
inline int16_t  readShort(const uint8_t* p) { return static_cast<int16_t>((p[0] << 8) | p[1]); }
inline int32_t  readInt(const uint8_t* p) {
    return static_cast<int32_t>(
        (static_cast<uint32_t>(p[0]) << 24) |
        (static_cast<uint32_t>(p[1]) << 16) |
        (static_cast<uint32_t>(p[2]) << 8) |
        static_cast<uint32_t>(p[3]));
}
inline int64_t readLong(const uint8_t* p) {
    return static_cast<int64_t>(
        (static_cast<uint64_t>(p[0]) << 56) |
        (static_cast<uint64_t>(p[1]) << 48) |
        (static_cast<uint64_t>(p[2]) << 40) |
        (static_cast<uint64_t>(p[3]) << 32) |
        (static_cast<uint64_t>(p[4]) << 24) |
        (static_cast<uint64_t>(p[5]) << 16) |
        (static_cast<uint64_t>(p[6]) << 8) |
        static_cast<uint64_t>(p[7]));
}

inline std::string readUTF8(const uint8_t* p, int32_t len) {
    return std::string(reinterpret_cast<const char*>(p), static_cast<size_t>(len));
}

} // namespace ghidra_db
