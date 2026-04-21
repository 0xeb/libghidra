// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "ghidra_project.h"
#include "buffer_file.h"
#include "db_record.h"
#include "btree.h"
#include "address_map.h"

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
                    }
                    return true;
                });
        }
    }

    // Read symbols (the "Symbols" table)
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

                    data.functions.push_back({name, addr});
                    return true;
                });
        }
    }

    // Sort functions by address
    std::sort(data.functions.begin(), data.functions.end(),
              [](const FunctionEntry& a, const FunctionEntry& b) {
                  return a.address < b.address;
              });

    return data;
}

} // namespace ghidra_db
