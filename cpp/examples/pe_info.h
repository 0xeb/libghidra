// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once
// pe_info.h — Header-only PE parser for ghidra_cli
//
// Extracts: image base, sections, entry point, machine type, and PE exports.
// No external dependencies beyond the C++ standard library.

#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace pe {

struct Section {
    char     name[9];
    uint32_t virtualSize;
    uint32_t virtualAddress;   // RVA
    uint32_t rawDataSize;
    uint32_t rawDataOffset;    // file offset
};

struct Export {
    std::string name;
    uint64_t    rva;
    uint64_t    fileOffset;
};

struct PEInfo {
    bool     valid = false;
    uint16_t machine = 0;        // COFF Machine field
    uint16_t magic = 0;          // 0x10B = PE32, 0x20B = PE32+
    uint64_t imageBase = 0;
    uint64_t entryPointRVA = 0;
    uint64_t entryPointFileOffset = 0;
    uint16_t numSections = 0;

    std::vector<Section> sections;
    std::vector<Export>  exports;
};

// ---------------------------------------------------------------------------
// Little-endian readers
// ---------------------------------------------------------------------------

inline bool readLE16(std::ifstream &f, uint16_t &v) {
    return !!f.read(reinterpret_cast<char*>(&v), 2);
}
inline bool readLE32(std::ifstream &f, uint32_t &v) {
    return !!f.read(reinterpret_cast<char*>(&v), 4);
}
inline bool readLE64(std::ifstream &f, uint64_t &v) {
    return !!f.read(reinterpret_cast<char*>(&v), 8);
}

// ---------------------------------------------------------------------------
// RVA -> file offset conversion
// ---------------------------------------------------------------------------

inline uint64_t rvaToFileOffset(const PEInfo &info, uint64_t rva) {
    for (const auto &sec : info.sections) {
        if (rva >= sec.virtualAddress &&
            rva <  sec.virtualAddress + sec.rawDataSize) {
            return (rva - sec.virtualAddress) + sec.rawDataOffset;
        }
    }
    return 0;
}

// VA -> file offset (subtracts imageBase first)
inline uint64_t vaToFileOffset(const PEInfo &info, uint64_t va) {
    if (va < info.imageBase) return 0;
    return rvaToFileOffset(info, va - info.imageBase);
}

// File offset -> RVA
inline uint64_t fileOffsetToRVA(const PEInfo &info, uint64_t offset) {
    for (const auto &sec : info.sections) {
        if (offset >= sec.rawDataOffset &&
            offset <  sec.rawDataOffset + sec.rawDataSize) {
            return (offset - sec.rawDataOffset) + sec.virtualAddress;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Export table parser
// ---------------------------------------------------------------------------

inline void parseExports(std::ifstream &f, PEInfo &info,
                         uint32_t exportDirRVA, uint32_t exportDirSize) {
    if (exportDirRVA == 0 || exportDirSize == 0) return;

    uint64_t exportDirOff = rvaToFileOffset(info, exportDirRVA);
    if (exportDirOff == 0) return;

    // IMAGE_EXPORT_DIRECTORY (40 bytes):
    //   +0   Characteristics (4)
    //   +4   TimeDateStamp (4)
    //   +8   MajorVersion (2)
    //  +10   MinorVersion (2)
    //  +12   Name RVA (4)
    //  +16   Base (4)
    //  +20   NumberOfFunctions (4)
    //  +24   NumberOfNames (4)
    //  +28   AddressOfFunctions RVA (4)
    //  +32   AddressOfNames RVA (4)
    //  +36   AddressOfNameOrdinals RVA (4)

    f.seekg(static_cast<std::streamoff>(exportDirOff + 20));
    uint32_t numFunctions, numNames;
    readLE32(f, numFunctions);
    readLE32(f, numNames);

    uint32_t functionsRVA, namesRVA, ordinalsRVA;
    readLE32(f, functionsRVA);
    readLE32(f, namesRVA);
    readLE32(f, ordinalsRVA);

    if (numNames == 0) return;

    uint64_t functionsOff = rvaToFileOffset(info, functionsRVA);
    uint64_t namesOff     = rvaToFileOffset(info, namesRVA);
    uint64_t ordinalsOff  = rvaToFileOffset(info, ordinalsRVA);
    if (functionsOff == 0 || namesOff == 0 || ordinalsOff == 0) return;

    for (uint32_t i = 0; i < numNames; i++) {
        // Read name RVA
        f.seekg(static_cast<std::streamoff>(namesOff + i * 4));
        uint32_t nameRVA;
        if (!readLE32(f, nameRVA)) break;

        uint64_t nameOff = rvaToFileOffset(info, nameRVA);
        if (nameOff == 0) continue;

        // Read the name string
        f.seekg(static_cast<std::streamoff>(nameOff));
        char buf[256] = {};
        f.read(buf, 255);
        std::string name(buf);

        // Read the ordinal index for this name
        f.seekg(static_cast<std::streamoff>(ordinalsOff + i * 2));
        uint16_t ordinalIndex;
        if (!readLE16(f, ordinalIndex)) break;

        // Read the function RVA using the ordinal index
        if (ordinalIndex >= numFunctions) continue;
        f.seekg(static_cast<std::streamoff>(functionsOff + ordinalIndex * 4));
        uint32_t funcRVA;
        if (!readLE32(f, funcRVA)) break;

        // Skip forwarded exports (RVA points inside the export directory)
        if (funcRVA >= exportDirRVA && funcRVA < exportDirRVA + exportDirSize)
            continue;

        Export exp;
        exp.name       = name;
        exp.rva        = funcRVA;
        exp.fileOffset = rvaToFileOffset(info, funcRVA);
        if (exp.fileOffset != 0) {
            info.exports.push_back(exp);
        }
    }
}

// ---------------------------------------------------------------------------
// Main PE parser
// ---------------------------------------------------------------------------

inline bool parsePE(const std::string &path, PEInfo &info) {
    info = PEInfo{};

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    // DOS header — check MZ signature
    uint16_t mz;
    if (!readLE16(f, mz) || mz != 0x5A4D) return false;

    // e_lfanew at offset 0x3C
    f.seekg(0x3C);
    uint32_t peOffset;
    if (!readLE32(f, peOffset)) return false;

    // PE signature "PE\0\0"
    f.seekg(peOffset);
    uint32_t sig;
    if (!readLE32(f, sig) || sig != 0x00004550) return false;

    // COFF header (20 bytes)
    readLE16(f, info.machine);
    readLE16(f, info.numSections);
    f.seekg(12, std::ios::cur);  // timestamp, symtable ptr, symcount
    uint16_t optHdrSize, characteristics;
    readLE16(f, optHdrSize);
    readLE16(f, characteristics);

    // Optional header
    std::streampos optStart = f.tellg();
    readLE16(f, info.magic);

    uint32_t entryPointRVA32 = 0;
    uint32_t exportDirRVA = 0, exportDirSize = 0;

    if (info.magic == 0x20B) {
        // PE32+ (64-bit)
        // +2: MajorLinkerVersion(1) + MinorLinkerVersion(1) = skip 2
        // +4: SizeOfCode(4) + SizeOfInitializedData(4) + SizeOfUninitializedData(4) = skip 12
        // +16: AddressOfEntryPoint(4)
        f.seekg(14, std::ios::cur);
        readLE32(f, entryPointRVA32);
        // +20: BaseOfCode(4) = skip 4
        // +24: ImageBase(8)
        f.seekg(4, std::ios::cur);
        readLE64(f, info.imageBase);

        // Data directories start at optStart + 112 for PE32+
        // (24 bytes standard + 88 bytes Windows-specific = 112)
        // Export table is the first data directory entry
        f.seekg(static_cast<std::streamoff>(optStart) + 112);
        readLE32(f, exportDirRVA);
        readLE32(f, exportDirSize);

    } else if (info.magic == 0x10B) {
        // PE32 (32-bit)
        // +2: skip 14 bytes to get to AddressOfEntryPoint at opt+16
        f.seekg(14, std::ios::cur);
        readLE32(f, entryPointRVA32);
        // +20: BaseOfCode(4), BaseOfData(4) = skip 8
        // +28: ImageBase(4)
        f.seekg(8, std::ios::cur);
        uint32_t base32;
        readLE32(f, base32);
        info.imageBase = base32;

        // Data directories start at optStart + 96 for PE32
        f.seekg(static_cast<std::streamoff>(optStart) + 96);
        readLE32(f, exportDirRVA);
        readLE32(f, exportDirSize);

    } else {
        return false;
    }

    info.entryPointRVA = entryPointRVA32;

    // Section headers start right after the optional header
    f.seekg(static_cast<std::streamoff>(optStart) + optHdrSize);

    for (uint16_t i = 0; i < info.numSections; i++) {
        Section sec = {};
        f.read(sec.name, 8);
        sec.name[8] = '\0';
        readLE32(f, sec.virtualSize);
        readLE32(f, sec.virtualAddress);
        readLE32(f, sec.rawDataSize);
        readLE32(f, sec.rawDataOffset);
        f.seekg(16, std::ios::cur);  // relocs, linenums, characteristics
        info.sections.push_back(sec);
    }

    // Compute entry point file offset
    info.entryPointFileOffset = rvaToFileOffset(info, info.entryPointRVA);

    // Parse export table
    parseExports(f, info, exportDirRVA, exportDirSize);

    info.valid = true;
    return true;
}

// ---------------------------------------------------------------------------
// Machine type -> Ghidra language ID
// ---------------------------------------------------------------------------

inline std::string machineToGhidraArch(uint16_t machine) {
    switch (machine) {
        case 0x8664: return "x86:LE:64:default";        // AMD64
        case 0x014C: return "x86:LE:32:default";        // i386
        case 0xAA64: return "AARCH64:LE:64:default";    // ARM64
        case 0x01C0: return "ARM:LE:32:v7";             // ARM
        case 0x01C4: return "ARM:LE:32:v7";             // ARMv7 Thumb
        default:     return "";
    }
}

inline std::string machineToString(uint16_t machine) {
    switch (machine) {
        case 0x8664: return "x86-64 (AMD64)";
        case 0x014C: return "x86 (i386)";
        case 0xAA64: return "ARM64 (AArch64)";
        case 0x01C0: return "ARM";
        case 0x01C4: return "ARM (Thumb)";
        default:     return "unknown";
    }
}

} // namespace pe
