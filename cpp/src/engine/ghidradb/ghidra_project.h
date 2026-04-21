// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

class GHIDRA_API GhidraProject {
public:
    bool open(const std::string& gpr_path);
    ProjectData extract();
    std::string getError() const { return error_; }

private:
    std::string gbf_path_;
    std::string project_dir_;
    std::string error_;

    // Locate the .gbf database file for the first program in the project
    bool locateGbf(const std::string& gpr_path);
};

} // namespace ghidra_db
