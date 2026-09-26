// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "ghidra_project.h"
#include "buffer_file.h"
#include "db_record.h"
#include "btree.h"
#include "address_map.h"
#include "memory_image.h"

#include <cstdio>   // std::snprintf (big ref-list table name)
#include <cstdlib>  // std::strtoull (image-base parse)
#include <map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

namespace ghidra_db {

// Symbol type codes (from SymbolType.java)
static constexpr int SYMBOL_TYPE_FUNCTION = 5;

// Symbol table column indices (from SymbolDatabaseAdapter.java)
static constexpr int SYMBOL_NAME_COL      = 0;
static constexpr int SYMBOL_ADDR_COL      = 1;
static constexpr int SYMBOL_TYPE_COL      = 3;

// Reference index (ReferenceDBManager / FromAdapterV0). "FROM REFS" is keyed by
// the from-address key; column 0 is the ref count and column 1 a packed RefListV0
// blob, or null when the list overflowed into "FromBigRefList_<hex key>" (one row
// per ref: To, Flags, Type, OpIndex, SymbolID, Offset -- BigRefListV0).
static constexpr int FROM_REFS_COUNT_COL = 0;
static constexpr int FROM_REFS_DATA_COL  = 1;
static constexpr int BIG_REFS_TO_COL     = 0;
static constexpr int BIG_REFS_TYPE_COL   = 2;

// Namespace bodies (NamespaceManager's AddressRangeMapDB "SCOPE ADDRESSES"):
// key = range start key, column 0 = range end key, column 1 = namespace id.
// A function's namespace id is its symbol id (the Symbols record key).
static constexpr int SCOPE_TO_COL    = 0;
static constexpr int SCOPE_VALUE_COL = 1;

// RefListFlagsV0 bits that add optional fields to a packed ref.
static constexpr uint8_t REF_IS_OFFSET     = 0x04;
static constexpr uint8_t REF_HAS_SYMBOL_ID = 0x08;
static constexpr uint8_t REF_IS_SHIFT      = 0x10;

// RefType bytes whose FlowType sets isCall() (RefType.java).
static bool isCallRefType(int8_t t) {
    switch (t) {
        case 3:   // UNCONDITIONAL_CALL
        case 4:   // CONDITIONAL_CALL
        case 8:   // COMPUTED_CALL
        case 10:  // CALL_TERMINATOR
        case 13:  // CONDITIONAL_COMPUTED_CALL
        case 14:  // CONDITIONAL_CALL_TERMINATOR
        case 15:  // COMPUTED_CALL_TERMINATOR
        case 16:  // CALL_OVERRIDE_UNCONDITIONAL
        case 18:  // CALLOTHER_OVERRIDE_CALL
            return true;
        default:
            return false;
    }
}

struct PackedRef {
    int64_t to_key;
    int8_t type;
};

// Decode a RefListV0 blob (RefListV0.decode): per ref an 8-byte big-endian
// to-address key, flags, type, operand index, then an 8-byte symbol id and an
// 8-byte offset/shift when the flags say so. False on a malformed blob.
static bool decodeRefList(const std::vector<uint8_t>& d, int count,
                          std::vector<PackedRef>& out) {
    size_t at = 0;
    for (int i = 0; i < count; ++i) {
        if (at + 11 > d.size()) return false;
        uint64_t key = 0;
        for (int b = 0; b < 8; ++b) key = (key << 8) | d[at + b];
        at += 8;
        const uint8_t flags = d[at++];
        const int8_t type = static_cast<int8_t>(d[at++]);
        ++at;  // operand index
        if (flags & REF_HAS_SYMBOL_ID) at += 8;
        if (flags & (REF_IS_OFFSET | REF_IS_SHIFT)) at += 8;
        if (at > d.size()) return false;
        out.push_back({static_cast<int64_t>(key), type});
    }
    return at == d.size();
}

// Set FunctionEntry::makes_call from Ghidra's own reference index, so offline
// leaf listing matches the live host (FunctionsRuntime.hasOutgoingCall): a
// function calls iff a reference FROM its body has a call RefType and a
// destination offset != 0. AddressDecoder::decodeAddress returns the raw offset
// for external/stack/register keys, which is the same offset Ghidra compares.
// Leaves has_reference_index false (and every makes_call false) when either
// table is absent, so the caller can refuse instead of guessing.
static void markCallingFunctions(BufferFile& bf, const std::vector<MasterTableEntry>& tables,
                                 const AddressDecoder& addr_dec,
                                 const std::map<int64_t, size_t>& function_by_id,
                                 ProjectData& data) {
    auto table = [&](const std::string& name) -> const MasterTableEntry* {
        for (auto& t : tables)
            if (t.name == name && t.indexed_column == -1) return &t;
        return nullptr;
    };
    const MasterTableEntry* scope = table("Range Map - SCOPE ADDRESSES");
    const MasterTableEntry* from = table("FROM REFS");
    if (scope == nullptr || from == nullptr) return;

    // Body ranges -> owning function. Function bodies never overlap in Ghidra.
    std::map<uint64_t, std::pair<uint64_t, size_t>> body_by_start;
    BTreeReader(bf).iterateRecords(scope->root_buffer_id, scope->schema,
        [&](const Record& rec) -> bool {
            if (rec.fields.size() <= SCOPE_VALUE_COL) return true;
            auto it = function_by_id.find(rec.fields[SCOPE_VALUE_COL].asLong());
            if (it == function_by_id.end()) return true;
            body_by_start[addr_dec.decodeAddress(rec.key.asLong())] = {
                addr_dec.decodeAddress(rec.fields[SCOPE_TO_COL].asLong()), it->second};
            return true;
        });
    auto owner = [&](uint64_t addr) -> FunctionEntry* {
        auto it = body_by_start.upper_bound(addr);
        if (it == body_by_start.begin()) return nullptr;
        --it;
        return addr <= it->second.first ? &data.functions[it->second.second] : nullptr;
    };

    std::vector<PackedRef> refs;
    BTreeReader(bf).iterateRecords(from->root_buffer_id, from->schema,
        [&](const Record& rec) -> bool {
            if (rec.fields.size() <= FROM_REFS_DATA_COL) return true;
            const int64_t from_key = rec.key.asLong();
            if (!addr_dec.isMemoryAddress(from_key)) return true;
            FunctionEntry* fn = owner(addr_dec.decodeAddress(from_key));
            if (fn == nullptr || fn->makes_call) return true;

            refs.clear();
            const FieldValue& blob = rec.fields[FROM_REFS_DATA_COL];
            if (blob.is_null) {
                char name[48];
                std::snprintf(name, sizeof name, "FromBigRefList_%llx",
                              static_cast<unsigned long long>(from_key));
                if (const MasterTableEntry* big = table(name)) {
                    BTreeReader(bf).iterateRecords(big->root_buffer_id, big->schema,
                        [&](const Record& row) -> bool {
                            if (row.fields.size() > BIG_REFS_TYPE_COL)
                                refs.push_back({row.fields[BIG_REFS_TO_COL].asLong(),
                                                row.fields[BIG_REFS_TYPE_COL].byte_val});
                            return true;
                        });
                }
            } else if (!decodeRefList(blob.binary_val,
                                      rec.fields[FROM_REFS_COUNT_COL].asInt(), refs)) {
                return true;
            }
            for (const PackedRef& ref : refs) {
                if (isCallRefType(ref.type) && addr_dec.decodeAddress(ref.to_key) != 0) {
                    fn->makes_call = true;
                    break;
                }
            }
            return true;
        });
    data.has_reference_index = true;
}

// -----------------------------------------------------------------------
// .gpr / index parsing
// -----------------------------------------------------------------------

// Parse an XML-like property value from a simple text file.
// Looks for a line containing: <tag>...<property NAME="key" ... VALUE="value" ...
static std::string parseProperty(const std::string& content, const std::string& key) {
    // Find the key in a NAME="key" pattern
    std::string search = "NAME=\"" + key + "\"";
    size_t pos = content.find(search);
    if (pos == std::string::npos) return "";

    // Find VALUE="..." after this
    std::string val_search = "VALUE=\"";
    size_t vpos = content.find(val_search, pos);
    if (vpos == std::string::npos) return "";
    vpos += val_search.size();
    size_t end = content.find('"', vpos);
    if (end == std::string::npos) return "";
    return content.substr(vpos, end - vpos);
}

// Read the entire contents of a small text file.
static std::string readTextFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool GhidraProject::locateGbf(const std::string& gpr_path) {
    // A .gpr file sits next to a .rep directory with the same stem.
    // E.g. demo1.gpr -> demo1.rep/
    fs::path gpr(gpr_path);
    if (!fs::exists(gpr)) {
        error_ = "Project file not found: " + gpr_path;
        return false;
    }

    fs::path rep_dir = gpr;
    rep_dir.replace_extension(".rep");
    if (!fs::is_directory(rep_dir)) {
        error_ = "Repository directory not found: " + rep_dir.string();
        return false;
    }
    project_dir_ = rep_dir.string();

    // Read the index: ~index.dat or idata/~index.dat
    // The index lists programs as: /folderID:programName:fileID
    fs::path index_path = rep_dir / "idata" / "~index.dat";
    if (!fs::exists(index_path)) {
        // Try old-style location
        index_path = rep_dir / "~index.dat";
    }

    std::string index_content = readTextFile(index_path.string());
    if (index_content.empty()) {
        error_ = "Cannot read index file: " + index_path.string();
        return false;
    }

    // Parse lines looking for the first program entry.
    // Format is XML property-like:
    //   <FILE NAME="programName" FILE_ID="fileID" .../>
    // Or it may be a properties file with lines like:
    //   NEXT-ID:2
    //   /00000000:nasm.exe:12345678
    // The actual Ghidra index format uses PropertyFile XML.

    // Try to find the file ID and name from the index.
    // Ghidra stores program databases at:
    //   idata/<folder>/<url-encoded-name>.prp  (the property file)
    //   idata/<folder>/~<file-id>.db/db.<version>.gbf

    // Strategy: look for any .prp files in idata/ subdirectories,
    // then find the corresponding .db directory with a .gbf file.
    std::string best_gbf;
    std::string best_name;

    for (auto& entry : fs::recursive_directory_iterator(rep_dir / "idata")) {
        if (entry.path().extension() == ".prp") {
            // Parse the .prp file to get the program name
            std::string prp_content = readTextFile(entry.path().string());
            std::string prog_name = parseProperty(prp_content, "PROGRAM_NAME");
            if (prog_name.empty()) {
                // Try the file stem as a fallback
                prog_name = entry.path().stem().string();
            }

            // Look for the .db directory next to the .prp file
            // The .db directory name is ~<fileID>.db
            fs::path prp_dir = entry.path().parent_path();
            for (auto& sibling : fs::directory_iterator(prp_dir)) {
                if (sibling.is_directory() &&
                    sibling.path().filename().string().front() == '~' &&
                    sibling.path().extension() == ".db") {

                    // Find the latest .gbf file in this directory
                    int max_version = -1;
                    fs::path latest_gbf;
                    for (auto& dbfile : fs::directory_iterator(sibling.path())) {
                        if (dbfile.path().extension() == ".gbf") {
                            // Parse version from "db.N.gbf"
                            std::string fname = dbfile.path().filename().string();
                            if (fname.substr(0, 3) == "db.") {
                                std::string ver_str = fname.substr(3,
                                    fname.size() - 3 - 4); // strip "db." and ".gbf"
                                int ver = 0;
                                try { ver = std::stoi(ver_str); } catch (...) {}
                                if (ver > max_version) {
                                    max_version = ver;
                                    latest_gbf = dbfile.path();
                                }
                            }
                        }
                    }

                    if (max_version >= 0) {
                        best_gbf = latest_gbf.string();
                        best_name = prog_name;
                    }
                }
            }
        }
    }

    if (best_gbf.empty()) {
        error_ = "No program database (.gbf) found in project";
        return false;
    }

    gbf_path_ = best_gbf;
    return true;
}

bool GhidraProject::open(const std::string& gpr_path) {
    return locateGbf(gpr_path);
}

ProjectData GhidraProject::extract() {
    ProjectData data;

    // Open the .gbf file
    BufferFile bf;
    if (!bf.open(gbf_path_)) {
        error_ = "Failed to open .gbf: " + bf.getError();
        return data;
    }

    // Read buffer 0 to get DBParms (master table root)
    std::vector<uint8_t> buf0;
    if (!bf.readBuffer(0, buf0)) {
        error_ = "Failed to read buffer 0: " + bf.getError();
        return data;
    }

    DBParms parms;
    if (!parms.read(buf0)) {
        error_ = "Failed to parse DBParms from buffer 0";
        return data;
    }

    // Read the master table
    std::vector<MasterTableEntry> tables;
    if (!readMasterTable(bf, parms.master_table_root, tables)) {
        error_ = "Failed to read master table";
        return data;
    }

    // Load the address map
    AddressDecoder addr_dec;
    addr_dec.load(bf, tables);

    // Find program metadata from the "Program" options table.
    // This is typically a VarKey (string-keyed) table.
    for (auto& t : tables) {
        if (t.name == "Program" && t.indexed_column == -1) {
            BTreeReader reader(bf);
            reader.iterateRecords(t.root_buffer_id, t.schema,
                [&](const Record& rec) -> bool {
                    // The Program table stores option key-value pairs.
                    // Key is a string, values are in the record fields.
                    std::string option_key = rec.key.asString();

                    // Common options:
                    // "Executable Location" -> exe path
                    // "Language ID" -> language id
                    // "Compiler Spec ID" -> compiler spec
                    // "Program Name" -> program name
                    if (option_key.find("Executable Location") != std::string::npos) {
                        if (!rec.fields.empty())
                            data.info.exe_path = rec.fields[0].asString();
                    } else if (option_key.find("Language ID") != std::string::npos) {
                        if (!rec.fields.empty())
                            data.info.language_id = rec.fields[0].asString();
                    } else if (option_key.find("Compiler Spec ID") != std::string::npos) {
                        if (!rec.fields.empty())
                            data.info.compiler_spec = rec.fields[0].asString();
                    } else if (option_key.find("Program Name") != std::string::npos) {
                        if (!rec.fields.empty())
                            data.info.program_name = rec.fields[0].asString();
                    } else if (option_key.find("Image Offset") != std::string::npos) {
                        // Ghidra stores function-symbol address keys image-base-
                        // relative; the RELOCATABLE decode adds this base offset
                        // (AddressMapDB baseImageOffset). Without it every offline
                        // function address is image-base-too-low. The value is a
                        // bare hex string (ProgramDB persists Long.toHexString and
                        // parses it with radix 16), so parse base-16. This runs
                        // BEFORE the "Symbols" loop decodes address keys with
                        // addr_dec, so the image base is applied.
                        if (!rec.fields.empty())
                            addr_dec.setImageBaseOffset(std::strtoull(
                                rec.fields[0].asString().c_str(), nullptr, 16));
                    }
                    return true;
                });
        }
    }

    // Read symbols (the "Symbols" table). The record key is the symbol id, which
    // is also the function's namespace id in the body range map below.
    std::map<int64_t, size_t> function_by_id;
    for (auto& t : tables) {
        if (t.name == "Symbols" && t.indexed_column == -1) {
            BTreeReader reader(bf);
            reader.iterateRecords(t.root_buffer_id, t.schema,
                [&](const Record& rec) -> bool {
                    // V4 Symbol schema columns:
                    //   0: Name(String), 1: Address(Long), 2: Namespace(Long),
                    //   3: Symbol Type(Byte), 4: Flags(Byte), ...
                    if (rec.fields.size() < 5) return true;

                    int sym_type = rec.fields[SYMBOL_TYPE_COL].asInt();
                    if (sym_type != SYMBOL_TYPE_FUNCTION) return true;

                    std::string name = rec.fields[SYMBOL_NAME_COL].asString();
                    int64_t addr_key = rec.fields[SYMBOL_ADDR_COL].asLong();

                    if (!addr_dec.isMemoryAddress(addr_key)) return true;
                    uint64_t addr = addr_dec.decodeAddress(addr_key);

                    function_by_id[rec.key.asLong()] = data.functions.size();
                    data.functions.push_back({name, addr, false});
                    return true;
                });
        }
    }

    markCallingFunctions(bf, tables, addr_dec, function_by_id, data);

    // Sort functions by address
    std::sort(data.functions.begin(), data.functions.end(),
              [](const FunctionEntry& a, const FunctionEntry& b) {
                  return a.address < b.address;
              });

    return data;
}

bool GhidraProject::loadMemoryImage(MemoryImage& out) {
    if (gbf_path_.empty()) {
        error_ = "project not opened (no .gbf located)";
        return false;
    }
    if (!out.load(gbf_path_)) {
        error_ = out.getError();
        return false;
    }
    return true;
}

} // namespace ghidra_db
