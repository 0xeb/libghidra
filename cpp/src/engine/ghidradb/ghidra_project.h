// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once
#include <string>
#include <vector>
#include <cstdint>

#ifndef GHIDRA_API
#define GHIDRA_API
#endif

namespace ghidra_db {

struct ProjectInfo {
    std::string program_name;    // e.g. "nasm.exe"
    std::string exe_path;        // original binary path
    std::string language_id;     // e.g. "x86:LE:64:default"
    std::string compiler_spec;   // e.g. "windows"
};

struct FunctionEntry {
    std::string name;
    uint64_t address;
};

struct ProjectData {
    ProjectInfo info;
    std::vector<FunctionEntry> functions;
};

class MemoryImage;  // ghidradb/memory_image.h

class GHIDRA_API GhidraProject {
public:
    bool open(const std::string& gpr_path);
    ProjectData extract();

    // Reconstruct the program's loaded memory image (File Bytes + Memory Blocks)
    // from this project's db, so the offline decompiler can read bytes at their
    // real virtual addresses without the original binary. Returns false if the
    // project carries no image bytes (getError() explains).
    bool loadMemoryImage(MemoryImage& out);

    std::string getError() const { return error_; }

private:
    std::string gbf_path_;
    std::string project_dir_;
    std::string error_;

    // Locate the .gbf database file for the first program in the project
    bool locateGbf(const std::string& gpr_path);
};

} // namespace ghidra_db
