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
#include <functional>
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

namespace ghidra_db {

// Symbol type codes (from SymbolType.java)
static constexpr int SYMBOL_TYPE_LABEL     = 0;
static constexpr int SYMBOL_TYPE_LIBRARY   = 1;
static constexpr int SYMBOL_TYPE_NAMESPACE = 3;
static constexpr int SYMBOL_TYPE_CLASS     = 4;
static constexpr int SYMBOL_TYPE_FUNCTION  = 5;
static constexpr int SYMBOL_TYPE_PARAMETER = 6;
static constexpr int SYMBOL_TYPE_LOCAL_VAR = 7;

// AddressMapDB: a variable symbol's address is a VARIABLE-space key whose
// offset is the "Variable Storage" record key.
static constexpr int ADDR_TYPE_SHIFT = 60;
static constexpr int64_t VARIABLE_ADDR_TYPE = 0x6;
static constexpr int64_t EXTERNAL_ADDR_TYPE = 0x5;
static constexpr int64_t ADDR_OFFSET_MASK = 0xFFFFFFFFLL;
// VariableStorageDBAdapter: column 1 is the serialized storage.
static constexpr int STORAGE_STRING_COL = 1;

// Symbol table column indices (from SymbolDatabaseAdapter.java)
static constexpr int SYMBOL_NAME_COL      = 0;
static constexpr int SYMBOL_ADDR_COL      = 1;
static constexpr int SYMBOL_PARENT_COL    = 2;
static constexpr int SYMBOL_TYPE_COL      = 3;
static constexpr int SYMBOL_FLAGS_COL     = 4;
static constexpr int SYMBOL_PRIMARY_COL   = 6;   // sparse; set on a primary label
static constexpr int SYMBOL_DATATYPE_COL  = 7;   // sparse
static constexpr int SYMBOL_VAROFFSET_COL = 8;   // sparse; a parameter's ordinal

// "Function Data" (FunctionAdapter.java), keyed by the function symbol id.
static constexpr int FUNCTION_RETURN_TYPE_COL = 0;
static constexpr int FUNCTION_FLAGS_COL       = 4;
static constexpr int FUNCTION_CC_COL          = 5;
static constexpr int FUNCTION_RETURN_STORAGE_COL = 6;  // serialized VariableStorage
static constexpr uint8_t FUNCTION_VARARG_FLAG = 0x01;
static constexpr uint8_t FUNCTION_INLINE_FLAG = 0x02;
static constexpr uint8_t FUNCTION_NO_RETURN_FLAG = 0x04;
static constexpr uint8_t FUNCTION_CUSTOM_STORAGE_FLAG = 0x08;
static constexpr uint8_t FUNCTION_SIGNATURE_SOURCE_MASK = 0x70;
static constexpr int FUNCTION_SIGNATURE_SOURCE_SHIFT = 4;

// "Thunk Functions" (ThunkFunctionAdapterV0.java): key = thunk id, col 0 = thunked id.
static constexpr int THUNK_LINKED_COL = 0;

// SourceType storage ids (SourceType.java); symbol flags hold bits 0-1 plus bit 3.
static constexpr int SOURCE_DEFAULT = 2;
static int symbolSource(int flags) { return (flags & 0x3) | ((flags & 0x8) >> 1); }

// CallingConventionDBAdapter: 0 unknown, 1 default, >= 2 "Calling Conventions" key.
static constexpr int CC_UNKNOWN = 0;
static constexpr int CC_DEFAULT = 1;

// VariableStorage.getVarnodes over its serialization: comma-separated
// "<address>:<size>" pieces, the address either "Stack[-0x10]" or
// "<space>:<hex offset>". Empty for <UNASSIGNED>, <VOID>, <BAD> or anything
// unparsable.
static std::vector<VarnodeEntry> parseStorage(const std::string& text) {
    std::vector<VarnodeEntry> out;
    size_t start = 0;
    while (start < text.size()) {
        size_t comma = text.find(',', start);
        const std::string piece = text.substr(start, comma == std::string::npos ? std::string::npos
                                                                               : comma - start);
        start = comma == std::string::npos ? text.size() : comma + 1;
        const size_t colon = piece.rfind(':');
        if (colon == std::string::npos || colon == 0) return {};
        const std::string addr = piece.substr(0, colon);
        VarnodeEntry v;
        try {
            v.size = std::stoi(piece.substr(colon + 1));
            if (addr.rfind("Stack[", 0) == 0 && addr.back() == ']') {
                std::string off = addr.substr(6, addr.size() - 7);
                const bool neg = !off.empty() && off[0] == '-';
                if (neg) off = off.substr(1);
                if (off.rfind("0x", 0) == 0) off = off.substr(2);
                v.space = "stack";
                v.offset = static_cast<int64_t>(std::stoull(off, nullptr, 16));
                if (neg) v.offset = -v.offset;
            } else {
                const size_t sep = addr.find(':');
                if (sep == std::string::npos) return {};
                v.space = addr.substr(0, sep);
                v.offset = static_cast<int64_t>(std::stoull(addr.substr(sep + 1), nullptr, 16));
            }
        } catch (...) {
            return {};
        }
        out.push_back(v);
    }
    return out;
}

// SymbolUtilities.getDefaultLocalName for a stack local (the stack grows
// toward lower addresses on every target this reader serves): local_<hex>
// below the entry stack pointer, local_res<hex> in the caller's area, then
// _<first use> when the variable is not live from the entry.
static std::string defaultLocalName(const std::vector<VarnodeEntry>& storage, int first_use) {
    std::string name;
    if (storage.size() == 1 && storage[0].space == "stack") {
        const int64_t off = storage[0].offset;
        char hex[32];
        std::snprintf(hex, sizeof hex, "%llx",
                      static_cast<unsigned long long>(off < 0 ? -off : off));
        name = std::string(off >= 0 ? "local_res" : "local_") + hex;
    } else {
        name = "local_" + std::to_string(storage.size());  // register storage: not produced here
    }
    if (first_use != 0) name += "_" + std::to_string(first_use);
    return name;
}

// SymbolUtilities.getDefaultParamName / isDefaultParameterName.
static std::string defaultParamName(int ordinal) { return "param_" + std::to_string(ordinal + 1); }
static bool isDefaultParamName(const std::string& n) {
    if (n.size() <= 6 || n.compare(0, 6, "param_") != 0) return false;
    return std::all_of(n.begin() + 6, n.end(), [](char c) { return c >= '0' && c <= '9'; });
}

struct StoredFunction {
    int64_t return_type = DEFAULT_DATATYPE_ID;
    std::string return_storage;
    uint8_t flags = 0;
    int cc_id = CC_UNKNOWN;
    int64_t thunk_of = -1;
    std::vector<ParameterEntry> parameters;
};

// Build every function's SignatureEntry from "Function Data", "Thunk Functions",
// "Calling Conventions" and the PARAMETER symbols collected by the caller. A
// thunk reports the signature of the function it (transitively) thunks, under
// its own name and entry point -- FunctionDB.getSignature() does the same.
static void buildSignatures(BufferFile& bf, const std::vector<MasterTableEntry>& tables,
                            std::map<int64_t, StoredFunction>& stored,
                            const std::map<int64_t, size_t>& function_by_id,
                            const std::vector<std::pair<ExternalRefEntry*, int64_t>>& external_ids,
                            ProjectData& data) {
    auto each = [&](const char* name, size_t min_cols,
                    const std::function<void(const Record&)>& fn) {
        for (const auto& t : tables) {
            if (t.name != name || t.indexed_column != -1) continue;
            BTreeReader(bf).iterateRecords(t.root_buffer_id, t.schema,
                [&](const Record& r) -> bool {
                    if (r.fields.size() >= min_cols) fn(r);
                    return true;
                });
            return;
        }
    };

    each("Function Data", FUNCTION_CC_COL + 1, [&](const Record& r) {
        StoredFunction& f = stored[r.key.asLong()];
        f.return_type = r.fields[FUNCTION_RETURN_TYPE_COL].is_null
                            ? DEFAULT_DATATYPE_ID
                            : r.fields[FUNCTION_RETURN_TYPE_COL].asLong();
        f.flags = static_cast<uint8_t>(r.fields[FUNCTION_FLAGS_COL].asInt());
        f.cc_id = static_cast<uint8_t>(r.fields[FUNCTION_CC_COL].asInt());
        if (r.fields.size() > FUNCTION_RETURN_STORAGE_COL &&
            !r.fields[FUNCTION_RETURN_STORAGE_COL].is_null)
            f.return_storage = r.fields[FUNCTION_RETURN_STORAGE_COL].asString();
    });
    each("Thunk Functions", THUNK_LINKED_COL + 1, [&](const Record& r) {
        stored[r.key.asLong()].thunk_of = r.fields[THUNK_LINKED_COL].asLong();
    });
    // Keyed by a ByteField: a FixedKey b-tree.
    std::map<int, std::string> conventions;
    each("Calling Conventions", 1, [&](const Record& r) {
        conventions[static_cast<int>(r.key.asLong())] = r.fields[0].asString();
    });
    auto ccName = [&](int id) -> std::string {
        if (id == CC_DEFAULT) return "default";
        auto it = conventions.find(id);
        return (id == CC_UNKNOWN || it == conventions.end()) ? "unknown" : it->second;
    };

    auto make = [&](int64_t id, const std::string& name, uint64_t address) {
        const StoredFunction* s = nullptr;
        int64_t cur = id;
        for (int depth = 0; depth < 32; ++depth) {  // thunk chains are short
            auto it = stored.find(cur);
            if (it == stored.end()) break;
            s = &it->second;
            if (s->thunk_of < 0) break;
            cur = s->thunk_of;
        }
        SignatureEntry sig;
        sig.address = address;
        sig.name = name;
        if (s != nullptr) {
            sig.return_type = s->return_type;
            sig.calling_convention = ccName(s->cc_id);
            sig.has_var_args = (s->flags & FUNCTION_VARARG_FLAG) != 0;
            sig.is_inline = (s->flags & FUNCTION_INLINE_FLAG) != 0;
            sig.no_return = (s->flags & FUNCTION_NO_RETURN_FLAG) != 0;
            sig.custom_storage = (s->flags & FUNCTION_CUSTOM_STORAGE_FLAG) != 0;
            if (sig.custom_storage) sig.return_storage = parseStorage(s->return_storage);
            sig.locked = ((s->flags & FUNCTION_SIGNATURE_SOURCE_MASK) >>
                          FUNCTION_SIGNATURE_SOURCE_SHIFT) != SOURCE_DEFAULT;
            sig.parameters = s->parameters;
            if (!sig.custom_storage)
                for (ParameterEntry& p : sig.parameters) p.storage.clear();
            std::sort(sig.parameters.begin(), sig.parameters.end(),
                      [](const ParameterEntry& a, const ParameterEntry& b) {
                          return a.ordinal < b.ordinal;
                      });
        } else {
            sig.calling_convention = ccName(CC_UNKNOWN);
        }
        return sig;
    };

    data.signatures.reserve(function_by_id.size());
    for (const auto& [id, index] : function_by_id) {
        FunctionEntry& fn = data.functions[index];
        auto own = stored.find(id);
        fn.is_thunk = own != stored.end() && own->second.thunk_of >= 0;
        data.signatures.push_back(make(id, fn.name, fn.address));
    }
    for (auto& [ext, id] : external_ids)
        ext->signature = make(id, ext->name, ext->address);
    std::sort(data.signatures.begin(), data.signatures.end(),
              [](const SignatureEntry& a, const SignatureEntry& b) { return a.address < b.address; });
}

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

// Fill FunctionEntry::body from the namespace body map (NamespaceManager's
// "SCOPE ADDRESSES"): key = range start key, column 0 = range end key, column 1
// = namespace id, which for a function is its symbol id.
static void readFunctionBodies(BufferFile& bf, const std::vector<MasterTableEntry>& tables,
                               const AddressDecoder& addr_dec,
                               const std::map<int64_t, size_t>& function_by_id,
                               ProjectData& data) {
    for (const auto& t : tables) {
        if (t.name != "Range Map - SCOPE ADDRESSES" || t.indexed_column != -1) continue;
        BTreeReader(bf).iterateRecords(t.root_buffer_id, t.schema,
            [&](const Record& rec) -> bool {
                if (rec.fields.size() <= SCOPE_VALUE_COL) return true;
                auto it = function_by_id.find(rec.fields[SCOPE_VALUE_COL].asLong());
                if (it == function_by_id.end()) return true;
                data.functions[it->second].body.emplace_back(
                    addr_dec.decodeAddress(rec.key.asLong()),
                    addr_dec.decodeAddress(rec.fields[SCOPE_TO_COL].asLong()));
                return true;
            });
        return;
    }
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
    for (const auto& [id, index] : function_by_id)
        for (const auto& [first, last] : data.functions[index].body)
            body_by_start[first] = {last, index};
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

// External function pointers (DecompileCallback.getExternalReference): a
// defined data item ("Data" table) whose reference goes to an EXTERNAL-space
// address that is an external function's symbol address. `external_ids`
// pairs each entry with the external function's symbol id, for its signature.
static void readExternalRefs(
    BufferFile& bf, const std::vector<MasterTableEntry>& tables, const AddressDecoder& addr_dec,
    const std::map<int64_t, std::pair<int64_t, std::string>>& external_fn_by_key,
    ProjectData& data, std::vector<std::pair<ExternalRefEntry*, int64_t>>& external_ids) {
    if (external_fn_by_key.empty()) return;
    auto table = [&](const std::string& name) -> const MasterTableEntry* {
        for (auto& t : tables)
            if (t.name == name && t.indexed_column == -1) return &t;
        return nullptr;
    };
    const MasterTableEntry* defined = table("Data");
    const MasterTableEntry* from = table("FROM REFS");
    if (defined == nullptr || from == nullptr) return;
    std::set<int64_t> data_keys;
    BTreeReader(bf).iterateRecords(defined->root_buffer_id, defined->schema,
        [&](const Record& rec) -> bool {
            data_keys.insert(rec.key.asLong());
            return true;
        });
    std::vector<std::pair<uint64_t, int64_t>> found;  // (address, external key)
    std::vector<PackedRef> refs;
    BTreeReader(bf).iterateRecords(from->root_buffer_id, from->schema,
        [&](const Record& rec) -> bool {
            const int64_t from_key = rec.key.asLong();
            if (rec.fields.size() <= FROM_REFS_DATA_COL || !data_keys.count(from_key) ||
                !addr_dec.isMemoryAddress(from_key))
                return true;
            refs.clear();
            const FieldValue& blob = rec.fields[FROM_REFS_DATA_COL];
            if (blob.is_null ||
                !decodeRefList(blob.binary_val, rec.fields[FROM_REFS_COUNT_COL].asInt(), refs))
                return true;
            for (const PackedRef& ref : refs) {
                if ((ref.to_key >> ADDR_TYPE_SHIFT) != EXTERNAL_ADDR_TYPE) continue;
                if (external_fn_by_key.count(ref.to_key)) {
                    found.emplace_back(addr_dec.decodeAddress(from_key), ref.to_key);
                    break;
                }
            }
            return true;
        });
    data.external_refs.reserve(found.size());
    for (const auto& [address, key] : found) {
        const auto& [id, name] = external_fn_by_key.at(key);
        ExternalRefEntry e;
        e.address = address;
        e.name = name;
        data.external_refs.push_back(std::move(e));
    }
    for (size_t i = 0; i < found.size(); ++i)
        external_ids.emplace_back(&data.external_refs[i], external_fn_by_key.at(found[i].second).first);
}

// The listing beyond functions (measured against a live host):
//   "Data"                     key = address, column 0 = data type id
//   "Property Map - Lengths"   key = address, column 0 = the length of an item
//                              whose type has none (strings, dynamic types)
//   "Instance Settings"        column 0 = association (the data's address key),
//                              1 = setting name index, 2 = long value; the
//                              "mutability" setting is 0 normal, 1 volatile, 2 constant
//   "Comments"                 key = address, columns EOL, PRE, POST, PLATE, REPEATABLE
//   "Bookmark Types"           key = type id, column 0 = name; "Bookmarks<type id>"
//                              key = bookmark id, Address, Category, Comment
//   "Function Tags"            key = tag id, Name, Comment; "Function Tag Map"
//                              column 0 = function symbol id, 1 = tag id
//   "TO REFS"                  key = to address, packed ref list (WRITE ref types)
static void readListing(BufferFile& bf, const std::vector<MasterTableEntry>& tables,
                        const AddressDecoder& addr_dec,
                        const std::map<int64_t, size_t>& function_by_id, ProjectData& data) {
    auto table = [&](const std::string& name) -> const MasterTableEntry* {
        for (auto& t : tables)
            if (t.name == name && t.indexed_column == -1) return &t;
        return nullptr;
    };
    auto each = [&](const std::string& name, const std::function<void(const Record&)>& fn) {
        if (const MasterTableEntry* t = table(name))
            BTreeReader(bf).iterateRecords(t->root_buffer_id, t->schema,
                                           [&](const Record& r) -> bool {
                                               fn(r);
                                               return true;
                                           });
    };

    std::map<uint64_t, int> lengths;
    each("Property Map - Lengths", [&](const Record& r) {
        if (!r.fields.empty() && addr_dec.isMemoryAddress(r.key.asLong()))
            lengths[addr_dec.decodeAddress(r.key.asLong())] = r.fields[0].asInt();
    });
    std::map<int, std::string> setting_names;
    each("Instance Settings Names", [&](const Record& r) {
        if (!r.fields.empty()) setting_names[static_cast<int>(r.key.asLong())] = r.fields[0].asString();
    });
    std::map<int64_t, int> mutability;  // by the data's address key
    each("Instance Settings", [&](const Record& r) {
        if (r.fields.size() < 3) return;
        auto name = setting_names.find(r.fields[1].asInt());
        if (name != setting_names.end() && name->second == "mutability")
            mutability[r.fields[0].asLong()] = r.fields[2].asInt();
    });
    each("Data", [&](const Record& r) {
        const int64_t key = r.key.asLong();
        if (r.fields.empty() || !addr_dec.isMemoryAddress(key)) return;
        DataEntry d;
        d.address = addr_dec.decodeAddress(key);
        d.type_id = r.fields[0].asLong();
        auto len = lengths.find(d.address);
        if (len != lengths.end()) d.length = len->second;
        auto mut = mutability.find(key);
        if (mut != mutability.end()) d.mutability = mut->second;
        data.data.push_back(d);
    });
    std::sort(data.data.begin(), data.data.end(),
              [](const DataEntry& a, const DataEntry& b) { return a.address < b.address; });

    each("Comments", [&](const Record& r) {
        if (!addr_dec.isMemoryAddress(r.key.asLong())) return;
        const uint64_t address = addr_dec.decodeAddress(r.key.asLong());
        for (size_t i = 0; i < r.fields.size() && i < 5; ++i) {
            if (r.fields[i].is_null) continue;
            const std::string text = r.fields[i].asString();
            if (!text.empty()) data.comments.push_back({address, static_cast<int>(i), text});
        }
    });
    std::stable_sort(data.comments.begin(), data.comments.end(),
                     [](const CommentEntry& a, const CommentEntry& b) { return a.address < b.address; });

    std::map<int64_t, std::string> bookmark_types;
    each("Bookmark Types", [&](const Record& r) {
        if (!r.fields.empty()) bookmark_types[r.key.asLong()] = r.fields[0].asString();
    });
    for (const auto& [type_id, type_name] : bookmark_types) {
        each("Bookmarks" + std::to_string(type_id), [&](const Record& r) {
            if (r.fields.size() < 3 || !addr_dec.isMemoryAddress(r.fields[0].asLong())) return;
            BookmarkEntry b;
            b.id = r.key.asLong();
            b.address = addr_dec.decodeAddress(r.fields[0].asLong());
            b.type = type_name;
            b.category = r.fields[1].is_null ? "" : r.fields[1].asString();
            b.comment = r.fields[2].is_null ? "" : r.fields[2].asString();
            data.bookmarks.push_back(std::move(b));
        });
    }

    std::map<int64_t, size_t> tag_by_id;
    each("Function Tags", [&](const Record& r) {
        if (r.fields.empty()) return;
        FunctionTagEntry t;
        t.id = r.key.asLong();
        t.name = r.fields[0].asString();
        t.comment = r.fields.size() > 1 && !r.fields[1].is_null ? r.fields[1].asString() : "";
        tag_by_id[t.id] = data.function_tags.size();
        data.function_tags.push_back(std::move(t));
    });
    each("Function Tag Map", [&](const Record& r) {
        if (r.fields.size() < 2) return;
        auto fn = function_by_id.find(r.fields[0].asLong());
        auto tag = tag_by_id.find(r.fields[1].asLong());
        if (fn == function_by_id.end() || tag == tag_by_id.end()) return;
        data.function_tags[tag->second].functions.push_back(data.functions[fn->second].address);
    });

    // Every referenced address and its reference level; and every address a
    // WRITE (READ_WRITE, WRITE_IND, READ_WRITE_IND) reference targets.
    std::vector<PackedRef> refs;
    each("TO REFS", [&](const Record& r) {
        const int64_t key = r.key.asLong();
        if (!addr_dec.isMemoryAddress(key)) return;
        if (r.fields.size() > 2 && !r.fields[2].is_null)
            data.references[addr_dec.decodeAddress(key)] = r.fields[2].byte_val;
        if (r.fields.size() <= FROM_REFS_DATA_COL || r.fields[FROM_REFS_DATA_COL].is_null)
            return;
        refs.clear();
        if (!decodeRefList(r.fields[FROM_REFS_DATA_COL].binary_val,
                           r.fields[FROM_REFS_COUNT_COL].asInt(), refs))
            return;
        for (const PackedRef& ref : refs) {
            if (ref.type == 102 || ref.type == 103 || ref.type == 105 || ref.type == 106) {
                data.written.insert(addr_dec.decodeAddress(key));
                break;
            }
        }
    });

    // External entry points: ReferenceDBManager.addExternalEntryPointRef adds a
    // reference from Address.EXT_FROM_ADDRESS, which AddressMapDB encodes as -2.
    static constexpr int64_t kExtFromAddressKey = -2;
    each("FROM REFS", [&](const Record& r) {
        if (r.key.asLong() != kExtFromAddressKey || r.fields.size() <= FROM_REFS_DATA_COL) return;
        std::vector<PackedRef> list;
        const FieldValue& blob = r.fields[FROM_REFS_DATA_COL];
        if (blob.is_null) {
            char name[48];
            std::snprintf(name, sizeof name, "FromBigRefList_%llx",
                          static_cast<unsigned long long>(kExtFromAddressKey));
            each(name, [&](const Record& row) {
                if (row.fields.size() > BIG_REFS_TYPE_COL)
                    list.push_back({row.fields[BIG_REFS_TO_COL].asLong(),
                                    row.fields[BIG_REFS_TYPE_COL].byte_val});
            });
        } else if (!decodeRefList(blob.binary_val, r.fields[FROM_REFS_COUNT_COL].asInt(), list)) {
            return;
        }
        for (const PackedRef& ref : list)
            if (addr_dec.isMemoryAddress(ref.to_key))
                data.entry_points.insert(addr_dec.decodeAddress(ref.to_key));
    });

    // Register values (ProgramContext; RegisterValue bytes are the mask, then
    // the value, both big-endian). A value whose mask does not cover the whole
    // register is left out.
    static const std::string kRegisterMap = "Range Map - Register_";
    for (const auto& t : tables) {
        if (t.indexed_column != -1 || t.name.rfind(kRegisterMap, 0) != 0) continue;
        const std::string reg = t.name.substr(kRegisterMap.size());
        BTreeReader(bf).iterateRecords(t.root_buffer_id, t.schema, [&](const Record& r) -> bool {
            if (r.fields.size() < 2 || r.fields[1].is_null) return true;
            const std::vector<uint8_t>& bytes = r.fields[1].binary_val;
            const size_t n = bytes.size() / 2;
            if (n == 0 || n > 8 || bytes.size() != 2 * n) return true;
            for (size_t i = 0; i < n; ++i)
                if (bytes[i] != 0xff) return true;
            RegisterValueEntry v;
            v.reg = reg;
            v.first = addr_dec.decodeAddress(r.key.asLong());
            v.last = addr_dec.decodeAddress(r.fields[0].asLong());
            for (size_t i = 0; i < n; ++i) v.value = (v.value << 8) | bytes[n + i];
            data.register_values.push_back(std::move(v));
            return true;
        });
    }
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

bool GhidraProject::locateGbf(const std::string& gpr_path, const std::string& program) {
    not_found_ = false;
    // A .gpr file sits next to a .rep directory with the same stem.
    // E.g. demo1.gpr -> demo1.rep/
    fs::path gpr(gpr_path);
    if (!fs::exists(gpr)) {
        not_found_ = true;
        error_ = "Project file not found: " + gpr_path;
        return false;
    }

    fs::path rep_dir = gpr;
    rep_dir.replace_extension(".rep");
    if (!fs::is_directory(rep_dir)) {
        not_found_ = true;
        error_ = "Repository directory not found: " + rep_dir.string();
        return false;
    }
    project_dir_ = rep_dir.string();
    if (!fs::is_directory(rep_dir / "idata")) {
        not_found_ = true;
        error_ = "No program in project: " + gpr_path;
        return false;
    }

    // Each program has a property file idata/<folder>/<fileID>.prp naming it
    // (NAME, PARENT folder, CONTENT_TYPE) next to its database directory
    // ~<fileID>.db holding db.<version>.gbf; the latest version is current.
    struct Program {
        std::string path;   // "/folder/name", as the host's ListProjectFiles reports it
        std::string name;
        std::string gbf;
    };
    std::vector<Program> programs;
    for (auto& entry : fs::recursive_directory_iterator(rep_dir / "idata")) {
        if (entry.path().extension() != ".prp") continue;
        const std::string prp_content = readTextFile(entry.path().string());
        const std::string content_type = parseProperty(prp_content, "CONTENT_TYPE");
        if (!content_type.empty() && content_type != "Program") continue;
        Program prog;
        prog.name = parseProperty(prp_content, "NAME");
        if (prog.name.empty()) prog.name = entry.path().stem().string();
        std::string parent = parseProperty(prp_content, "PARENT");
        if (parent.empty()) parent = "/";
        prog.path = (parent == "/" ? "/" : parent + "/") + prog.name;

        fs::path db_dir = entry.path().parent_path() / ("~" + entry.path().stem().string() + ".db");
        if (!fs::is_directory(db_dir)) continue;
        int max_version = -1;
        for (auto& dbfile : fs::directory_iterator(db_dir)) {
            if (dbfile.path().extension() != ".gbf") continue;
            // Parse version from "db.N.gbf"
            const std::string fname = dbfile.path().filename().string();
            if (fname.substr(0, 3) != "db.") continue;
            int ver = 0;
            try { ver = std::stoi(fname.substr(3, fname.size() - 3 - 4)); } catch (...) {}
            if (ver > max_version) {
                max_version = ver;
                prog.gbf = dbfile.path().string();
            }
        }
        if (max_version >= 0) programs.push_back(std::move(prog));
    }

    if (programs.empty()) {
        not_found_ = true;
        error_ = "No program database (.gbf) found in project";
        return false;
    }

    // The program the caller names: its project path ("/folder/name", with or
    // without the leading '/'), or its bare name when that is unambiguous. No
    // name selects the project's only program.
    std::vector<const Program*> matches;
    for (const auto& p : programs) {
        if (program.empty() || p.path == program || p.path == "/" + program ||
            (program.find('/') == std::string::npos && p.name == program))
            matches.push_back(&p);
    }
    if (matches.empty()) {
        not_found_ = true;
        error_ = "No program '" + program + "' in project " + gpr_path;
        return false;
    }
    if (matches.size() > 1) {
        error_ = program.empty()
                     ? "The project holds " + std::to_string(programs.size()) +
                           " programs; name the one to open"
                     : "More than one program in the project is named '" + program + "'";
        return false;
    }

    gbf_path_ = matches.front()->gbf;
    program_path_ = matches.front()->path;
    return true;
}

bool GhidraProject::open(const std::string& gpr_path, const std::string& program) {
    return locateGbf(gpr_path, program);
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
    std::map<int64_t, StoredFunction> stored;  // by function symbol id, externals too
    struct RawLocal {
        int64_t function_id;
        LocalVariableEntry entry;
        bool default_source;
        int64_t storage_key;
    };
    std::vector<RawLocal> raw_locals;
    struct ParamStorage {
        int64_t function_id;
        size_t index;
        int64_t storage_key;
    };
    std::vector<ParamStorage> param_storage;
    std::map<int64_t, std::pair<int64_t, std::string>> external_fn_by_key;  // key -> (id, name)
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
                    if (sym_type == SYMBOL_TYPE_PARAMETER &&
                        rec.fields.size() > SYMBOL_VAROFFSET_COL) {
                        // Parameter of the function whose symbol id is the parent
                        // namespace. VariableSymbolDB.doGetName: a DEFAULT-source
                        // or default-looking name reads back as param_<ordinal+1>.
                        ParameterEntry p;
                        const FieldValue& ord = rec.fields[SYMBOL_VAROFFSET_COL];
                        const FieldValue& dt = rec.fields[SYMBOL_DATATYPE_COL];
                        p.ordinal = ord.is_null ? 0 : ord.asInt();
                        p.type_id = (dt.is_null || dt.asLong() == NULL_DATATYPE_ID)
                                        ? DEFAULT_DATATYPE_ID : dt.asLong();
                        p.name = rec.fields[SYMBOL_NAME_COL].asString();
                        if (symbolSource(rec.fields[SYMBOL_FLAGS_COL].asInt()) == SOURCE_DEFAULT ||
                            p.name.empty() || isDefaultParamName(p.name))
                            p.name = defaultParamName(p.ordinal);
                        const int64_t owner = rec.fields[SYMBOL_PARENT_COL].asLong();
                        const int64_t addr_key = rec.fields[SYMBOL_ADDR_COL].asLong();
                        auto& params = stored[owner].parameters;
                        if ((addr_key >> ADDR_TYPE_SHIFT) == VARIABLE_ADDR_TYPE)
                            param_storage.push_back({owner, params.size(), addr_key & ADDR_OFFSET_MASK});
                        params.push_back(std::move(p));
                        return true;
                    }
                    if (sym_type == SYMBOL_TYPE_LOCAL_VAR &&
                        rec.fields.size() > SYMBOL_VAROFFSET_COL) {
                        const int64_t addr_key = rec.fields[SYMBOL_ADDR_COL].asLong();
                        if ((addr_key >> ADDR_TYPE_SHIFT) != VARIABLE_ADDR_TYPE) return true;
                        RawLocal l;
                        l.function_id = rec.fields[SYMBOL_PARENT_COL].asLong();
                        l.entry.name = rec.fields[SYMBOL_NAME_COL].asString();
                        const FieldValue& dt = rec.fields[SYMBOL_DATATYPE_COL];
                        l.entry.type_id = dt.is_null ? NULL_DATATYPE_ID : dt.asLong();  // null: undefined of the storage size
                        const FieldValue& fu = rec.fields[SYMBOL_VAROFFSET_COL];
                        l.entry.first_use = fu.is_null ? 0 : fu.asInt();
                        l.default_source =
                            symbolSource(rec.fields[SYMBOL_FLAGS_COL].asInt()) == SOURCE_DEFAULT;
                        l.storage_key = addr_key & ADDR_OFFSET_MASK;
                        raw_locals.push_back(std::move(l));
                        return true;
                    }
                    if (sym_type == SYMBOL_TYPE_LABEL || sym_type == SYMBOL_TYPE_FUNCTION) {
                        const int64_t addr_key = rec.fields[SYMBOL_ADDR_COL].asLong();
                        if ((addr_key >> ADDR_TYPE_SHIFT) == EXTERNAL_ADDR_TYPE) {
                            ExternalSymbolEntry e;
                            e.id = rec.key.asLong();
                            e.offset = static_cast<uint64_t>(addr_key & ADDR_OFFSET_MASK);
                            e.name = rec.fields[SYMBOL_NAME_COL].asString();
                            e.namespace_id = rec.fields[SYMBOL_PARENT_COL].asLong();
                            e.function = sym_type == SYMBOL_TYPE_FUNCTION;
                            e.source = symbolSource(rec.fields[SYMBOL_FLAGS_COL].asInt());
                            data.external_symbols.push_back(std::move(e));
                        }
                    }
                    if (sym_type == SYMBOL_TYPE_LABEL) {
                        const int64_t addr_key = rec.fields[SYMBOL_ADDR_COL].asLong();
                        if (!addr_dec.isMemoryAddress(addr_key)) return true;
                        LabelEntry l;
                        l.id = rec.key.asLong();
                        l.address = addr_dec.decodeAddress(addr_key);
                        l.name = rec.fields[SYMBOL_NAME_COL].asString();
                        l.namespace_id = rec.fields[SYMBOL_PARENT_COL].asLong();
                        l.primary = rec.fields.size() > SYMBOL_PRIMARY_COL &&
                                    !rec.fields[SYMBOL_PRIMARY_COL].is_null;
                        l.source = symbolSource(rec.fields[SYMBOL_FLAGS_COL].asInt());
                        data.labels.push_back(std::move(l));
                        return true;
                    }
                    if (sym_type == SYMBOL_TYPE_LIBRARY || sym_type == SYMBOL_TYPE_NAMESPACE ||
                        sym_type == SYMBOL_TYPE_CLASS || sym_type == SYMBOL_TYPE_FUNCTION) {
                        data.namespaces[rec.key.asLong()] = {
                            rec.fields[SYMBOL_NAME_COL].asString(),
                            rec.fields[SYMBOL_PARENT_COL].asLong(), sym_type};
                    }
                    if (sym_type != SYMBOL_TYPE_FUNCTION) return true;

                    std::string name = rec.fields[SYMBOL_NAME_COL].asString();
                    int64_t addr_key = rec.fields[SYMBOL_ADDR_COL].asLong();

                    if ((addr_key >> ADDR_TYPE_SHIFT) == EXTERNAL_ADDR_TYPE) {
                        external_fn_by_key[addr_key] = {rec.key.asLong(), name};
                        return true;
                    }
                    if (!addr_dec.isMemoryAddress(addr_key)) return true;
                    uint64_t addr = addr_dec.decodeAddress(addr_key);

                    function_by_id[rec.key.asLong()] = data.functions.size();
                    FunctionEntry fn;
                    fn.name = name;
                    fn.address = addr;
                    fn.namespace_id = rec.fields[SYMBOL_PARENT_COL].asLong();
                    fn.symbol_id = rec.key.asLong();
                    fn.source = symbolSource(rec.fields[SYMBOL_FLAGS_COL].asInt());
                    data.functions.push_back(std::move(fn));
                    return true;
                });
        }
    }

    // Saved locals: resolve each one's storage and default name, then hand it
    // to its function (the parent namespace is the function symbol id).
    std::map<int64_t, std::string> storage_text;
    for (auto& t : tables) {
        if (t.name != "Variable Storage" || t.indexed_column != -1) continue;
        BTreeReader(bf).iterateRecords(t.root_buffer_id, t.schema,
            [&](const Record& rec) -> bool {
                if (rec.fields.size() > STORAGE_STRING_COL)
                    storage_text[rec.key.asLong()] = rec.fields[STORAGE_STRING_COL].asString();
                return true;
            });
    }
    for (const ParamStorage& ps : param_storage) {
        auto st = storage_text.find(ps.storage_key);
        if (st != storage_text.end())
            stored[ps.function_id].parameters[ps.index].storage = parseStorage(st->second);
    }
    for (RawLocal& l : raw_locals) {
        auto fn = function_by_id.find(l.function_id);
        if (fn == function_by_id.end()) continue;
        auto st = storage_text.find(l.storage_key);
        l.entry.storage = st == storage_text.end() ? std::vector<VarnodeEntry>{}
                                                   : parseStorage(st->second);
        if (l.default_source || l.entry.name.empty())
            l.entry.name = defaultLocalName(l.entry.storage, l.entry.first_use);
        data.functions[fn->second].locals.push_back(std::move(l.entry));
    }

    // Analysis state the host's decompiler sees through the listing: call
    // fixups (FunctionDB.getCallFixup) and instruction flow overrides
    // (InstructionDB: flags & 0x0e >> 1), e.g. a tail-call JMP made CALL_RETURN.
    for (auto& t : tables) {
        if (t.indexed_column != -1) continue;
        if (t.name == "Property Map - CallFixup") {
            BTreeReader(bf).iterateRecords(t.root_buffer_id, t.schema,
                [&](const Record& rec) -> bool {
                    const int64_t key = rec.key.asLong();
                    if (!rec.fields.empty() && addr_dec.isMemoryAddress(key))
                        data.call_fixups[addr_dec.decodeAddress(key)] = rec.fields[0].asString();
                    return true;
                });
        } else if (t.name == "Instructions") {
            data.has_instruction_index = true;
            BTreeReader(bf).iterateRecords(t.root_buffer_id, t.schema,
                [&](const Record& rec) -> bool {
                    const int64_t key = rec.key.asLong();
                    if (!addr_dec.isMemoryAddress(key)) return true;
                    const uint64_t address = addr_dec.decodeAddress(key);
                    data.instruction_starts.push_back(address);
                    if (rec.fields.size() < 2) return true;
                    const int flow = (rec.fields[1].asInt() & 0x0e) >> 1;
                    if (flow != 0) data.flow_overrides[address] = flow;
                    return true;
                });
            std::sort(data.instruction_starts.begin(), data.instruction_starts.end());
        }
    }

    readFunctionBodies(bf, tables, addr_dec, function_by_id, data);
    markCallingFunctions(bf, tables, addr_dec, function_by_id, data);
    std::vector<std::pair<ExternalRefEntry*, int64_t>> external_ids;
    readExternalRefs(bf, tables, addr_dec, external_fn_by_key, data, external_ids);
    buildSignatures(bf, tables, stored, function_by_id, external_ids, data);
    readProgramTypes(bf, tables, data.types);
    readListing(bf, tables, addr_dec, function_by_id, data);
    std::sort(data.labels.begin(), data.labels.end(),
              [](const LabelEntry& a, const LabelEntry& b) {
                  return a.address != b.address ? a.address < b.address : a.id < b.id;
              });

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
