// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "buffer_file.h"

namespace ghidra_db {

static constexpr int64_t MAGIC_NUMBER = 0x2f30312c34292c2aLL;
static constexpr int32_t HEADER_FORMAT_VERSION = 1;
static constexpr int32_t BUFFER_PREFIX_SIZE = 5; // 1 byte flags + 4 byte buffer ID
static constexpr int32_t VER1_FIXED_HEADER_LENGTH = 32;

bool BufferFile::open(const std::string& path) {
    file_.open(path, std::ios::binary);
    if (!file_.is_open()) {
        error_ = "Cannot open file: " + path;
        return false;
    }

    // Read the file header from block 0
    // Header layout (all big-endian):
    //   0: magic(8) | fileID(8) | formatVersion(4) | blockSize(4) | freeListHead(4) | paramCount(4) | params...
    file_.seekg(0, std::ios::end);
    auto file_size = file_.tellg();
    file_.seekg(0);

    // Read fixed header (32 bytes minimum)
    uint8_t hdr[VER1_FIXED_HEADER_LENGTH];
    file_.read(reinterpret_cast<char*>(hdr), VER1_FIXED_HEADER_LENGTH);
    if (!file_ || file_.gcount() < VER1_FIXED_HEADER_LENGTH) {
        error_ = "File too small for header";
        return false;
    }

    int64_t magic = readLong(hdr);
    if (magic != MAGIC_NUMBER) {
        error_ = "Bad magic number";
        return false;
    }

    // fileId at offset 8 (skip)
    int32_t fmt_version = readInt(hdr + 16);
    if (fmt_version != HEADER_FORMAT_VERSION) {
        error_ = "Unsupported header format version: " + std::to_string(fmt_version);
        return false;
    }

    block_size_ = readInt(hdr + 20);
    buffer_size_ = block_size_ - BUFFER_PREFIX_SIZE;
    // freeListHead at offset 24 (skip)
    int32_t param_count = readInt(hdr + 28);

    if (block_size_ <= 0 || buffer_size_ <= 0) {
        error_ = "Invalid block size: " + std::to_string(block_size_);
        return false;
    }

    if (static_cast<int64_t>(file_size) % block_size_ != 0) {
        error_ = "File size not a multiple of block size";
        return false;
    }
    buffer_count_ = static_cast<int32_t>(static_cast<int64_t>(file_size) / block_size_) - 1;

    // Read named integer parameters
    params_.clear();
    for (int32_t i = 0; i < param_count; i++) {
        uint8_t len_buf[4];
        file_.read(reinterpret_cast<char*>(len_buf), 4);
        if (!file_) { error_ = "Truncated parameter header"; return false; }
        int32_t name_len = readInt(len_buf);
        if (name_len < 0 || name_len > buffer_size_) {
            error_ = "Invalid parameter name length";
            return false;
        }
        std::vector<uint8_t> name_bytes(name_len);
        file_.read(reinterpret_cast<char*>(name_bytes.data()), name_len);
        uint8_t val_buf[4];
        file_.read(reinterpret_cast<char*>(val_buf), 4);
        if (!file_) { error_ = "Truncated parameter data"; return false; }
        std::string name(name_bytes.begin(), name_bytes.end());
        params_[name] = readInt(val_buf);
    }

    error_.clear();
    return true;
}

int32_t BufferFile::getParameter(const std::string& name) const {
    auto it = params_.find(name);
    return (it != params_.end()) ? it->second : -1;
}

bool BufferFile::hasParameter(const std::string& name) const {
    return params_.find(name) != params_.end();
}

bool BufferFile::readBuffer(int32_t index, std::vector<uint8_t>& out) {
    if (index < 0 || index >= buffer_count_) {
        error_ = "Buffer index out of range: " + std::to_string(index);
        return false;
    }
    // Buffer N is in block (N+1). Block 0 is the file header.
    int64_t offset = static_cast<int64_t>(index + 1) * static_cast<int64_t>(block_size_);
    file_.seekg(offset);

    // Read the full block (prefix + data)
    std::vector<uint8_t> block(block_size_);
    file_.read(reinterpret_cast<char*>(block.data()), block_size_);
    if (!file_) {
        error_ = "Failed to read buffer " + std::to_string(index);
        return false;
    }

    // Skip 5-byte prefix (flags byte + buffer ID int)
    out.assign(block.begin() + BUFFER_PREFIX_SIZE, block.end());
    return true;
}

} // namespace ghidra_db
