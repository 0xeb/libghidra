// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once
#include <string>
#include <cstdint>
#include <memory>
#include <vector>

#ifndef GHIDRA_API
#define GHIDRA_API
#endif

namespace ghidra_standalone {

struct FunctionInfo {
    std::string name;
    uint64_t address;
    uint64_t size;
};

/// Definition of a single field within a struct type.
struct FieldDef {
    std::string name;
    std::string type_name;   // C-style: "int", "char*", "uint4", etc.
    int offset;              // byte offset within struct
};

/// Definition of a single named value within an enum type.
struct EnumValue {
    std::string name;
    uint64_t value;
};

/// Definition of a function parameter (name + type).
struct ParamDef {
    std::string name;
    std::string type_name;
};

class GHIDRA_API Decompiler {
public:
    /// Initialize using embedded spec files (no Ghidra source tree needed).
    /// Extracts bundled .sla/.pspec/.cspec files to a temp directory automatically.
    /// Only available when linked with ghidra_cpp (which includes embedded specs).
    Decompiler();

    /// Initialize with path to Ghidra root (for .sla/.pspec/.cspec files).
    /// This is typically the ghidra/ submodule directory.
    explicit Decompiler(const std::string& ghidra_root);
    ~Decompiler();

    Decompiler(const Decompiler&) = delete;
    Decompiler& operator=(const Decompiler&) = delete;

    /// Load a binary file. arch is a language id like "x86:LE:64:default".
    /// If empty, the format/architecture will be auto-detected.
    bool loadBinary(const std::string& filepath, const std::string& arch = "");

    /// Decompile the function at the given address, returning C source.
    std::string decompileAt(uint64_t address);

    /// Get the last error message.
    std::string getError() const;

    // ----- Type Creation -----

    /// Define a struct type. Fields specify name, C type string, and byte offset.
    bool defineStruct(const std::string& name, const std::vector<FieldDef>& fields);

    /// Define an enum type (4-byte by default).
    bool defineEnum(const std::string& name, const std::vector<EnumValue>& values);

    // ----- Symbol Management -----

    /// Name a function at the given address.
    bool nameFunction(uint64_t address, const std::string& name);

    /// Name a global variable at the given address with a C type string.
    bool nameGlobal(uint64_t address, const std::string& name, const std::string& type_name);

    /// Rename any symbol (function, global, local).
    bool renameSymbol(const std::string& old_name, const std::string& new_name);

    /// Retype any symbol with a C type string.
    bool retypeSymbol(const std::string& symbol_name, const std::string& type_name);

    /// Mark an address range as containing global variables.
    bool addGlobalRange(uint64_t address, uint64_t size);

    // ----- Function Prototypes -----

    /// Set a function's full prototype using a C-style declaration string.
    /// e.g. "int process_packet(char* data, int length)"
    bool setPrototype(uint64_t address, const std::string& prototype);

    // ----- Project Loading -----

    /// Load a Ghidra project (.gpr file) directly.
    /// Opens the project database, extracts the binary path and architecture,
    /// calls loadBinary(), then applies all function names from the project.
    /// If binary_override is non-empty, it is used instead of the stored path.
    bool loadProject(const std::string& gpr_path, const std::string& binary_override = "");

    // ----- State Persistence -----

    /// Save the full decompiler state (types, symbols, overrides) to XML.
    bool saveState(const std::string& filepath);

    /// Load a previously saved state from XML. Restores all types, symbols, overrides.
    bool loadState(const std::string& filepath);

    // ----- Output Control -----

    /// Set the output language: "c-language" (default) or "java-language".
    bool setPrintLanguage(const std::string& language);

    // ----- Enumeration -----

    /// List all functions currently known to the decompiler.
    /// Includes loader symbols (PE/ELF exports/imports), manually named functions,
    /// and functions discovered via project loading.
    std::vector<FunctionInfo> listFunctions();

    // ----- Memory Writes -----

    /// Write bytes at the given address using a copy-on-write overlay.
    /// The original image is never modified; reads through the overlay
    /// return patched bytes where written.
    void writeBytes(uint64_t address, const std::vector<uint8_t>& data);

    // ----- Advanced -----

    /// Get a raw pointer to the Architecture object for advanced users
    /// who want to use the Ghidra C++ API directly.
    void* getArchitecturePointer();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ghidra_standalone
