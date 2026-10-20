// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "program_listing.h"

#include "ghidra_project.h"
#include "libdecomp.hh"
#include "../symbol_entry.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>

using namespace ghidra;

namespace ghidra_standalone {
namespace {

// SourceType.name() by its storage id (SourceType.java).
constexpr int kUserDefined = 1;
std::string sourceName(int source) {
    switch (source) {
        case 0: return "ANALYSIS";
        case 1: return "USER_DEFINED";
        case 2: return "DEFAULT";
        case 3: return "IMPORTED";
        case 4: return "AI";
        default: return "UNKNOWN";
    }
}

std::string hexAddress(uint64_t address) {
    char buf[40];
    std::snprintf(buf, sizeof buf, "%08llx", static_cast<unsigned long long>(address));
    return buf;
}

int typeSize(Datatype* type) {
    return type != nullptr && type->getSize() > 0 ? type->getSize() : 1;
}

// The global scope: ScopeInternal, plus the host's lazy answers.
class ListingScope : public ScopeInternal {
 public:
    ListingScope(Architecture* arch) : ScopeInternal(0, "", arch) {}
    ProgramListing* listing = nullptr;

    LabSymbol* findCodeLabel(const Address& addr) const override {
        LabSymbol* sym = ScopeInternal::findCodeLabel(addr);
        if (sym == nullptr && listing != nullptr) sym = listing->codeLabel(addr);
        return sym;
    }
    MapEntry* findContainer(const Address& addr, int4 size, const Address& usepoint) const override {
        MapEntry* entry = ScopeInternal::findContainer(addr, size, usepoint);
        if (entry == nullptr && listing != nullptr && size <= 1)
            entry = dynamic_cast<MapEntry*>(listing->undefinedConstant(addr));
        return entry;
    }
};

}  // namespace

Scope* newListingScope(Architecture* arch) { return new ListingScope(arch); }

ProgramListing::ProgramListing() = default;
ProgramListing::~ProgramListing() = default;

void ProgramListing::reset(Architecture* arch, Hooks hooks) {
    if (arch_ != nullptr && arch_->symboltab != nullptr) {
        // Detach from the scope of the previous architecture (still alive here).
        if (auto* scope = dynamic_cast<ListingScope*>(arch_->symboltab->getGlobalScope()))
            scope->listing = nullptr;
    }
    hidden_labels_.clear();
    hidden_.reset();
    undefined_constants_.clear();
    arch_ = arch;
    hooks_ = std::move(hooks);
    if (arch_ != nullptr) {
        if (auto* scope = dynamic_cast<ListingScope*>(arch_->symboltab->getGlobalScope()))
            scope->listing = this;
        hidden_ = std::make_unique<ScopeInternal>(0, "", arch_);
    }
    labels_.clear();
    data_.clear();
    data_mutability_.clear();
    data_prefix_.clear();
    comments_.clear();
    bookmarks_.clear();
    bookmark_types_.clear();
    tags_.clear();
    blocks_.clear();
    written_.clear();
    function_ids_.clear();
    function_sources_.clear();
    externals_.clear();
    entry_points_.clear();
    references_.clear();
    dynamic_.clear();
    next_id_ = 1;
}

void ProgramListing::setMemory(const std::vector<MemoryBlockInfo>& blocks,
                               const std::set<uint64_t>& written) {
    blocks_ = blocks;
    written_ = written;
}

void ProgramListing::load(const ghidra_db::ProjectData& data,
                          const std::map<uint64_t, Datatype*>& data_types,
                          const std::vector<MemoryBlockInfo>& blocks,
                          const std::function<Scope*(int64_t)>& scope_of) {
    setMemory(blocks, data.written);
    references_ = data.references;

    // Symbol ids continue past every id the db holds, as Ghidra's would.
    uint64_t max_id = 0;
    for (const auto& [id, ns] : data.namespaces) max_id = std::max<uint64_t>(max_id, id);
    for (const ghidra_db::LabelEntry& l : data.labels) {
        Label label;
        label.id = static_cast<uint64_t>(l.id);
        label.address = l.address;
        label.name = l.name;
        label.scope = scope_of(l.namespace_id);
        label.primary = l.primary;
        label.source = l.source;
        labels_.push_back(std::move(label));
        max_id = std::max<uint64_t>(max_id, l.id);
    }
    next_id_ = max_id + 1;
    for (const ghidra_db::FunctionEntry& f : data.functions) {
        if (f.symbol_id > 0) function_ids_[f.address] = static_cast<uint64_t>(f.symbol_id);
        function_sources_[f.address] = f.source;
    }

    // External symbols: Namespace.getName(true) of the parent is the path, an
    // external symbol is always primary (SymbolDB.isPrimary).
    auto ns_path = [&](int64_t id) {
        std::string path;
        for (int guard = 0; id != 0 && guard < 64; ++guard) {
            auto it = data.namespaces.find(id);
            if (it == data.namespaces.end()) break;
            path = path.empty() ? it->second.name : it->second.name + "::" + path;
            id = it->second.parent_id;
        }
        return path.empty() ? std::string("Global") : path;
    };
    for (const ghidra_db::ExternalSymbolEntry& e : data.external_symbols) {
        LabelInfo info;
        info.id = static_cast<uint64_t>(e.id);
        info.address = e.offset;
        info.name = e.name;
        info.namespace_path = ns_path(e.namespace_id);
        info.primary = true;
        info.source = sourceName(e.source);
        externals_.emplace_back(std::move(info), e.function);
        max_id = std::max<uint64_t>(max_id, e.id);
    }
    next_id_ = max_id + 1;
    std::sort(externals_.begin(), externals_.end(), [](const auto& a, const auto& b) {
        return a.first.address != b.first.address ? a.first.address < b.first.address
                                                  : a.first.id < b.first.id;
    });
    entry_points_ = data.entry_points;

    // Defined data: a global symbol of its type where the host's
    // DecompileCallback.lookupSymbol would answer with the data (no function
    // covers it, no external reference stands on it).
    Scope* global = arch_->symboltab->getGlobalScope();
    for (const ghidra_db::DataEntry& d : data.data) {
        auto type = data_types.find(d.address);
        if (type == data_types.end() || type->second == nullptr) continue;
        Data item;
        item.type = type->second;
        item.length = typeSize(item.type);
        data_mutability_[d.address] = d.mutability;
        auto entry = data.types.types.find(d.type_id);
        if (entry != data.types.types.end() &&
            entry->second.kind == ghidra_db::DataTypeKind::BUILT_IN) {
            const std::string& cls = entry->second.class_name;
            // Built-ins that name their data their own way (measured against
            // the host's dynamic names on the rich fixture).
            if (cls.find("UnwindInfo") != std::string::npos) data_prefix_[d.address] = "UNWIND_INFO";
            else if (cls.find("ImageBaseOffset") != std::string::npos ||
                     cls.find("IBO") != std::string::npos)
                data_prefix_[d.address] = "";
        }
        const Label* primary = nullptr;
        for (const Label& l : labels_)
            if (l.address == d.address && l.primary) primary = &l;
        const uint32_t flags = dataFlags(d.address, d.mutability);
        // encodeData: undefined data with no symbol and normal mutability is a hole.
        const bool hole = primary == nullptr && d.type_id == ghidra_db::DEFAULT_DATATYPE_ID &&
                          (flags & (Varnode::readonly | Varnode::volatil)) == 0;
        if (!hole && dataVisible(d.address)) {
            item.named_by_label = primary != nullptr;
            item.symbol = addDataSymbol(d.address, item.type,
                                        primary != nullptr ? primary->name
                                                           : dynamicName(d.address, item.type),
                                        primary != nullptr ? primary->scope : global, flags);
        }
        data_[d.address] = item;
    }

    std::set<uint64_t> label_addresses;
    for (const Label& l : labels_) label_addresses.insert(l.address);
    for (const auto& [address, level] : references_) label_addresses.insert(address);
    for (uint64_t address : label_addresses) refreshCodeLabel(address);

    std::set<uint64_t> commented_functions;
    for (const ghidra_db::CommentEntry& c : data.comments) {
        // The host lists the comments of the program's memory only.
        bool mapped = blocks_.empty();
        for (const MemoryBlockInfo& b : blocks_) mapped = mapped || (c.address >= b.start && c.address <= b.end);
        if (!mapped) continue;
        comments_[{c.address, c.type}] = c.text;
        if (auto entry = hooks_.function_containing(c.address)) commented_functions.insert(*entry);
    }
    for (uint64_t entry : commented_functions) refreshFunctionComments(entry);

    for (const ghidra_db::BookmarkEntry& b : data.bookmarks) {
        if (std::find(bookmark_types_.begin(), bookmark_types_.end(), b.type) == bookmark_types_.end())
            bookmark_types_.push_back(b.type);
        bookmarks_.push_back({b.id, b.address, b.type, b.category, b.comment});
    }

    for (const ghidra_db::FunctionTagEntry& t : data.function_tags) {
        Tag& tag = tags_[t.name];
        tag.comment = t.comment;
        tag.functions.insert(t.functions.begin(), t.functions.end());
    }
}

// -- labels ------------------------------------------------------------------

LabelInfo ProgramListing::info(const Label& l) const {
    LabelInfo out;
    out.id = l.id;
    out.address = l.address;
    out.name = l.name;
    out.namespace_path = libghidra::detail::namespace_path(l.scope);
    out.primary = l.primary;
    out.source = sourceName(l.source);
    return out;
}

std::vector<LabelInfo> ProgramListing::labels(uint64_t first, uint64_t last) const {
    std::vector<LabelInfo> out;
    for (const Label& l : labels_)
        if (l.address >= first && l.address <= last) out.push_back(info(l));
    return out;
}

std::vector<std::pair<LabelInfo, bool>> ProgramListing::externalSymbols(uint64_t first,
                                                                       uint64_t last) const {
    std::vector<std::pair<LabelInfo, bool>> out;
    for (const auto& e : externals_)
        if (e.first.address >= first && e.first.address <= last) out.push_back(e);
    return out;
}

std::vector<LabelInfo> ProgramListing::labelsAt(uint64_t address) const {
    return labels(address, address);
}

std::optional<LabelInfo> ProgramListing::primaryLabel(uint64_t address) const {
    for (const Label& l : labels_)
        if (l.address == address && l.primary) return info(l);
    return std::nullopt;
}

std::optional<LabelInfo> ProgramListing::dynamicSymbol(uint64_t address) const {
    // SymbolManager.getPrimarySymbol: a referenced address with no symbol of
    // its own answers with a dynamic one (SymbolUtilities.getDynamicName).
    auto ref = references_.find(address);
    if (ref == references_.end() || hooks_.function_at(address)) return std::nullopt;
    for (const Label& l : labels_)
        if (l.address == address) return std::nullopt;
    static const char* const kLevel[] = {"UNK", "DAT", "LAB", "SUB", "UNK", "EXT", "FUN"};
    const int level = ref->second >= 0 && ref->second <= 6 ? ref->second : 0;
    LabelInfo out;
    out.address = address;
    out.namespace_path = "Global";
    out.primary = true;
    out.source = sourceName(2);
    auto data = data_.find(address);
    if (data != data_.end()) {
        out.name = dynamicName(address, data->second.type);
    } else if (dataCovers(address)) {
        // An offcut: the item's own name (or dynamic name) plus the offset.
        auto it = std::prev(data_.upper_bound(address));
        const Label* base = nullptr;
        for (const Label& l : labels_)
            if (l.address == it->first && l.primary) base = &l;
        char off[24];
        std::snprintf(off, sizeof off, "+%llu", static_cast<unsigned long long>(address - it->first));
        out.name = (base != nullptr ? base->name : dynamicName(it->first, it->second.type)) + off;
    } else if (hooks_.instruction_at(address)) {
        out.name = std::string(level == 3 ? "SUB" : level == 5 ? "EXT" : "LAB") + "_" + hexAddress(address);
    } else {
        out.name = std::string(kLevel[level]) + "_" + hexAddress(address);
    }
    return out;
}

ProgramListing::Label* ProgramListing::primaryOf(uint64_t address) {
    for (Label& l : labels_)
        if (l.address == address && l.primary) return &l;
    return nullptr;
}

std::vector<ProgramListing::Label*> ProgramListing::at(uint64_t address) {
    std::vector<Label*> out;
    for (Label& l : labels_)
        if (l.address == address) out.push_back(&l);
    return out;
}

bool ProgramListing::renameLabel(uint64_t address, const std::string& name,
                                 const std::string& new_name) {
    for (Label* l : at(address)) {
        const std::string ns = libghidra::detail::namespace_path(l->scope);
        if (l->name != name && (ns == "Global" || ns + "::" + l->name != name)) continue;
        l->name = new_name;
        l->source = kUserDefined;  // as setName(.., USER_DEFINED) leaves it
        if (l->code_label != nullptr) l->code_label->getScope()->renameSymbol(l->code_label, new_name);
        if (l->primary) refreshDataName(address);
        return true;
    }
    return false;
}

void ProgramListing::renameOrCreatePrimary(uint64_t address, const std::string& new_name) {
    if (Label* p = primaryOf(address)) {
        p->name = new_name;
        p->source = kUserDefined;
        if (p->code_label != nullptr) p->code_label->getScope()->renameSymbol(p->code_label, new_name);
        refreshDataName(address);
        return;
    }
    addLabel(address, new_name);
}

void ProgramListing::addLabel(uint64_t address, const std::string& name) {
    Label label;
    label.id = nextSymbolId();
    label.address = address;
    label.name = name;
    label.scope = arch_->symboltab->getGlobalScope();
    label.primary = primaryOf(address) == nullptr && !hooks_.function_at(address);
    label.source = kUserDefined;
    auto pos = std::upper_bound(labels_.begin(), labels_.end(), label,
                                [](const Label& a, const Label& b) {
                                    return a.address != b.address ? a.address < b.address : a.id < b.id;
                                });
    labels_.insert(pos, std::move(label));
    refreshDataName(address);
    refreshCodeLabel(address);
}

uint32_t ProgramListing::removeLabels(uint64_t address, const std::string& name) {
    uint32_t removed = 0;
    for (auto it = labels_.begin(); it != labels_.end();) {
        const std::string ns = libghidra::detail::namespace_path(it->scope);
        const bool match = it->address == address &&
                           (name.empty() || it->name == name ||
                            (ns != "Global" && ns + "::" + it->name == name));
        if (!match) {
            ++it;
            continue;
        }
        if (it->code_label != nullptr) it->code_label->getScope()->removeSymbol(it->code_label);
        it = labels_.erase(it);
        ++removed;
    }
    if (removed == 0) return 0;
    // Ghidra promotes another label at the address when the primary one goes.
    if (primaryOf(address) == nullptr && !hooks_.function_at(address)) {
        for (Label* l : at(address)) {
            l->primary = true;
            break;
        }
    }
    refreshDataName(address);
    refreshCodeLabel(address);
    return removed;
}

void ProgramListing::functionCreated(uint64_t address) {
    for (Label* l : at(address)) {
        l->primary = false;
        if (l->code_label != nullptr) {
            l->code_label->getScope()->removeSymbol(l->code_label);
            l->code_label = nullptr;
        }
    }
}

bool ProgramListing::dataVisible(uint64_t address) const {
    return !hooks_.function_containing(address) && !hooks_.function_at(address) &&
           !hooks_.external_ref(address);
}

bool ProgramListing::dataCovers(uint64_t address) const {
    auto it = data_.upper_bound(address);
    if (it == data_.begin()) return false;
    --it;
    return address < it->first + static_cast<uint64_t>(dataLength(it->second));
}

int ProgramListing::dataLength(const Data& item) const {
    return item.length > 0 ? item.length : typeSize(item.type);
}


void ProgramListing::refreshDataSizes() {
    for (auto it = data_.begin(); it != data_.end(); ++it) {
        Data& item = it->second;
        const int want = typeSize(item.type);
        if (item.length == want) continue;
        if (want > item.length) {
            // It grows only over free bytes: up to the next data item.
            auto next = std::next(it);
            if (next != data_.end() && next->first < it->first + static_cast<uint64_t>(want)) continue;
        }
        item.length = want;
        if (item.symbol == nullptr) continue;
        const std::string name = item.symbol->getName();
        Scope* scope = item.symbol->getScope();
        const uint32_t flags = item.symbol->getFlags() & (Varnode::readonly | Varnode::volatil);
        scope->removeSymbol(item.symbol);
        item.symbol = addDataSymbol(it->first, item.type, name, scope, flags);
    }
}

void ProgramListing::refreshCodeLabel(uint64_t address) {
    Label* primary = nullptr;
    bool any = false;
    for (Label* l : at(address)) {
        any = true;
        if (l->code_label != nullptr) {
            l->code_label->getScope()->removeSymbol(l->code_label);
            l->code_label = nullptr;
        }
        if (l->primary) primary = l;
    }
    auto dyn = dynamic_.find(address);
    if (dyn != dynamic_.end()) {
        dyn->second->getScope()->removeSymbol(dyn->second);
        dynamic_.erase(dyn);
    }
    Scope* global = arch_->symboltab->getGlobalScope();
    const Address addr(arch_->getDefaultCodeSpace(), static_cast<uintb>(address));
    if (hooks_.function_at(address) || hooks_.external_ref(address) || dataCovers(address)) return;
    if (primary != nullptr) {
        // encodeLabel: only a primary label of the global namespace that no
        // function or data item covers reaches the decompiler as a label.
        if (primary->scope != global || hooks_.function_containing(address)) return;
        primary->code_label = global->addCodeLabel(addr, primary->name);
        return;
    }
    auto ref = references_.find(address);
    if (any || ref == references_.end()) return;
    // A referenced address with no symbol of its own has a dynamic one
    // (SymbolManager.getPrimarySymbol): an instruction a label the printer
    // names gotos by (getCodeLabel), undefined bytes outside every function
    // an undefined global (encodeData of a DEFAULT item).
    static const char* const kLevel[] = {"UNK", "DAT", "LAB", "SUB", "UNK", "EXT", "FUN"};
    const int level = ref->second >= 0 && ref->second <= 6 ? ref->second : 0;
    if (hooks_.instruction_at(address)) {
        if (hooks_.function_containing(address)) return;  // codeLabel answers the printer
        const std::string name = std::string(level == 3 ? "SUB" : level == 5 ? "EXT" : "LAB") + "_" +
                                 hexAddress(address);
        dynamic_[address] = global->addCodeLabel(addr, name);
        return;
    }
    if (hooks_.function_containing(address)) return;
    Datatype* undefined = arch_->types->getBase(1, TYPE_UNKNOWN, "undefined");
    dynamic_[address] = addDataSymbol(address, undefined,
                                      std::string(kLevel[level]) + "_" + hexAddress(address), global,
                                      dataFlags(address, -1));
}

LabSymbol* ProgramListing::codeLabel(const Address& addr) {
    if (arch_ == nullptr || hidden_ == nullptr || addr.getSpace() != arch_->getDefaultCodeSpace())
        return nullptr;
    const uint64_t address = addr.getOffset();
    if (!hooks_.function_containing(address) || hooks_.function_at(address)) return nullptr;
    std::string name;
    if (Label* primary = primaryOf(address)) {
        name = primary->name;
    } else {
        auto ref = references_.find(address);
        if (ref == references_.end() || !hooks_.instruction_at(address)) return nullptr;
        name = std::string(ref->second == 3 ? "SUB" : ref->second == 5 ? "EXT" : "LAB") + "_" +
               hexAddress(address);
    }
    auto it = hidden_labels_.find(address);
    if (it != hidden_labels_.end()) {
        if (it->second->getName() != name) hidden_->renameSymbol(it->second, name);
        return it->second;
    }
    LabSymbol* sym = hidden_->addCodeLabel(addr, name);
    hidden_labels_[address] = sym;
    return sym;
}

SymbolEntry* ProgramListing::undefinedConstant(const Address& addr) {
    if (arch_ == nullptr || addr.getSpace() != arch_->getDefaultCodeSpace()) return nullptr;
    const uint64_t address = addr.getOffset();
    if (undefined_constants_.count(address) != 0) return nullptr;  // already answered
    bool mapped = false;
    for (const MemoryBlockInfo& b : blocks_)
        if (address >= b.start && address <= b.end && b.initialized) mapped = true;
    if (!mapped || (dataFlags(address, -1) & Varnode::readonly) == 0) return nullptr;
    if (hooks_.function_containing(address) || hooks_.function_at(address) ||
        hooks_.external_ref(address) || hooks_.instruction_at(address) || dataCovers(address))
        return nullptr;
    for (const Label& l : labels_)
        if (l.address == address) return nullptr;
    undefined_constants_.insert(address);
    auto ref = references_.find(address);
    static const char* const kLevel[] = {"UNK", "DAT", "LAB", "SUB", "UNK", "EXT", "FUN"};
    const int level = ref != references_.end() && ref->second >= 0 && ref->second <= 6 ? ref->second : 0;
    Symbol* sym = addDataSymbol(address, arch_->types->getBase(1, TYPE_UNKNOWN, "undefined"),
                                std::string(kLevel[level]) + "_" + hexAddress(address),
                                arch_->symboltab->getGlobalScope(), Varnode::readonly);
    return sym->getFirstWholeMap();
}

// -- data ----------------------------------------------------------------------

std::string ProgramListing::dynamicName(uint64_t address, Datatype* type) const {
    // SymbolUtilities.getDynamicName, by the data type's default label prefix.
    auto own = data_prefix_.find(address);
    if (own != data_prefix_.end()) {
        if (!own->second.empty()) return own->second + "_" + hexAddress(address);
        static const char* const kLevel[] = {"UNK", "DAT", "LAB", "SUB", "UNK", "EXT", "FUN"};
        auto ref = references_.find(address);
        const int level = ref != references_.end() && ref->second >= 0 && ref->second <= 6 ? ref->second : 0;
        return std::string(kLevel[level]) + "_" + hexAddress(address);
    }
    std::string prefix = "DAT";
    if (type != nullptr) {
        const type_metatype meta = type->getMetatype();
        if (meta == TYPE_PTR) {
            prefix = "PTR";
        } else if (meta == TYPE_ARRAY && type->getName().empty() &&
                   static_cast<TypeArray*>(type)->getBase()->isCharPrint()) {
            // A string: StringDataInstance.makeStringLabel over its characters.
            Datatype* base = static_cast<TypeArray*>(type)->getBase();
            const int unit = std::max(1, base->getSize());
            const int count = static_cast<TypeArray*>(type)->numElements();
            std::string label = unit == 1 ? "s_" : unit == 2 ? "u_" : "U_";
            std::vector<uint1> bytes(static_cast<size_t>(count) * unit);
            try {
                arch_->loader->loadFill(bytes.data(), static_cast<int4>(bytes.size()),
                                        Address(arch_->getDefaultCodeSpace(), static_cast<uintb>(address)));
            } catch (...) {
                return "DAT_" + hexAddress(address);
            }
            std::string text;
            bool underscore = false;
            for (int i = 0; i < count && text.size() < 32; ++i) {
                uint32_t c = 0;
                for (int b = unit - 1; b >= 0; --b) c = (c << 8) | bytes[static_cast<size_t>(i) * unit + b];
                if (c == 0) break;
                if (c >= 0x21 && c < 0x7f) {
                    if (underscore && !text.empty()) text += '_';
                    underscore = false;
                    text += static_cast<char>(c);
                } else {
                    underscore = true;
                }
            }
            return label + text + "_" + hexAddress(address);
        } else if (meta == TYPE_ARRAY && type->getName().empty()) {
            Datatype* base = static_cast<TypeArray*>(type)->getBase();
            prefix = "";
            if (prefix.empty()) {
                prefix = base->getName();
                std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                               [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
                if (prefix.empty()) prefix = "DAT";
            }
        } else if (meta == TYPE_UNKNOWN && type->isCoreType()) {
            prefix = "DAT";
        } else if (meta == TYPE_STRUCT || meta == TYPE_UNION || type->getTypedef() != nullptr ||
                   type->isEnumType()) {
            prefix = type->getName();
        } else if (!type->getName().empty()) {
            prefix = type->getName();
            std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                           [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        }
    }
    return prefix + "_" + hexAddress(address);
}

uint32_t ProgramListing::dataFlags(uint64_t address, int mutability) const {
    // MappedDataEntry.getMutability: the data's own setting, else its block's
    // (MappedEntry.getMutabilityOfAddress: a read-only block is constant
    // unless the program writes there).
    if (mutability == 1) return Varnode::volatil;
    if (mutability == 2) return Varnode::readonly;
    if (mutability == 0) return 0;
    for (const MemoryBlockInfo& b : blocks_) {
        if (address < b.start || address > b.end) continue;
        if (b.is_volatile) return Varnode::volatil;
        if (!b.write && written_.count(address) == 0) return Varnode::readonly;
        return 0;
    }
    return 0;
}

Symbol* ProgramListing::addDataSymbol(uint64_t address, Datatype* type, const std::string& name,
                                      Scope* scope, uint32_t flags) {
    AddrSpace* code = arch_->getDefaultCodeSpace();
    const Address addr(code, static_cast<uintb>(address));
    Symbol* sym = scope->addSymbol(name, type, addr, Address())->getSymbol();
    scope->setAttribute(sym, Varnode::namelock | Varnode::typelock | flags);
    sym->setIsolated(true);  // a type-locked symbol, as the host sends it (merge="false")
    if (scope != arch_->symboltab->getGlobalScope())
        arch_->symboltab->addRange(scope, code, static_cast<uintb>(address),
                                   static_cast<uintb>(address + typeSize(type) - 1));
    return sym;
}

void ProgramListing::refreshDataName(uint64_t address) {
    auto it = data_.find(address);
    if (it == data_.end() || it->second.symbol == nullptr) return;
    Data& item = it->second;
    const Label* primary = primaryOf(address);
    Scope* want = primary != nullptr ? primary->scope : arch_->symboltab->getGlobalScope();
    const std::string name = primary != nullptr ? primary->name : dynamicName(address, item.type);
    item.named_by_label = primary != nullptr;
    if (item.symbol->getScope() == want) {
        if (item.symbol->getName() != name) want->renameSymbol(item.symbol, name);
        return;
    }
    const uint32_t flags = item.symbol->getFlags() & (Varnode::readonly | Varnode::volatil);
    item.symbol->getScope()->removeSymbol(item.symbol);
    item.symbol = addDataSymbol(address, item.type, name, want, flags);
}

bool ProgramListing::hasDataAt(uint64_t address) const { return data_.count(address) != 0; }

std::vector<DataItemInfo> ProgramListing::dataItems(uint64_t first, uint64_t last) const {
    std::vector<DataItemInfo> out;
    for (auto it = data_.lower_bound(first); it != data_.end() && it->first <= last; ++it) {
        DataItemInfo d;
        d.address = it->first;
        d.type = it->second.type;
        d.length = dataLength(it->second);
        for (const Label& l : labels_)
            if (l.address == it->first && l.primary) d.name = l.name;
        out.push_back(std::move(d));
    }
    return out;
}

std::string ProgramListing::functionSource(uint64_t entry) const {
    auto it = function_sources_.find(entry);
    return it != function_sources_.end() ? sourceName(it->second) : std::string();
}

uint64_t ProgramListing::functionId(uint64_t entry) const {
    auto it = function_ids_.find(entry);
    return it != function_ids_.end() ? it->second : 0;
}

void ProgramListing::defineData(uint64_t address, Datatype* type) {
    auto it = data_.find(address);
    if (it != data_.end()) {
        it->second.type = type;
        it->second.length = typeSize(type);
        if (it->second.symbol != nullptr) {
            it->second.symbol->getScope()->retypeSymbol(it->second.symbol, type);
            it->second.symbol->getScope()->setAttribute(it->second.symbol, Varnode::typelock);
            it->second.symbol->setIsolated(true);
        }
        refreshCodeLabel(address);
        return;
    }
    Data item;
    item.type = type;
    item.length = typeSize(type);
    data_mutability_[address] = -1;
    if (dataVisible(address)) {
        const Label* primary = primaryOf(address);
        item.named_by_label = primary != nullptr;
        item.symbol = addDataSymbol(
            address, type, primary != nullptr ? primary->name : dynamicName(address, type),
            primary != nullptr ? primary->scope : arch_->symboltab->getGlobalScope(),
            dataFlags(address, -1));
    }
    data_[address] = item;
    refreshCodeLabel(address);
}

bool ProgramListing::clearData(uint64_t address) {
    auto it = data_.find(address);
    if (it == data_.end()) return false;
    if (it->second.symbol != nullptr) it->second.symbol->getScope()->removeSymbol(it->second.symbol);
    data_.erase(it);
    data_mutability_.erase(address);
    refreshCodeLabel(address);
    return true;
}

// -- comments ------------------------------------------------------------------

std::vector<ListingComment> ProgramListing::comments(uint64_t first, uint64_t last) const {
    std::vector<ListingComment> out;
    for (auto it = comments_.lower_bound({first, -1}); it != comments_.end() && it->first.first <= last;
         ++it)
        out.push_back({it->first.first, it->first.second, it->second});
    return out;
}

void ProgramListing::setComment(uint64_t address, int type, const std::string& text) {
    comments_[{address, type}] = text;
    if (auto entry = hooks_.function_containing(address)) refreshFunctionComments(*entry);
}

bool ProgramListing::deleteComment(uint64_t address, int type) {
    if (comments_.erase({address, type}) == 0) return false;
    if (auto entry = hooks_.function_containing(address)) refreshFunctionComments(*entry);
    return true;
}

void ProgramListing::refreshFunctionComments(uint64_t entry) {
    AddrSpace* code = arch_->getDefaultCodeSpace();
    const Address fad(code, static_cast<uintb>(entry));
    arch_->commentdb->clearType(fad, Comment::user1 | Comment::user2 | Comment::user3 |
                                         Comment::header);
    std::vector<std::pair<uint64_t, uint64_t>> body = hooks_.function_body(entry);
    if (body.empty()) body.push_back({entry, entry});
    for (const auto& [first, last] : body) {
        for (auto it = comments_.lower_bound({first, -1});
             it != comments_.end() && it->first.first <= last; ++it) {
            uint4 type = 0;
            switch (it->first.second) {
                case 0: type = Comment::user1; break;   // EOL
                case 1: type = Comment::user2; break;   // PRE
                case 2: type = Comment::user3; break;   // POST
                case 3: type = Comment::header; break;  // PLATE
                default: continue;                      // REPEATABLE is not sent
            }
            arch_->commentdb->addComment(type, fad, Address(code, static_cast<uintb>(it->first.first)),
                                         it->second);
        }
    }
}

// -- bookmarks -------------------------------------------------------------------

std::vector<BookmarkInfo> ProgramListing::bookmarks() const {
    std::vector<BookmarkInfo> out;
    for (const std::string& type : bookmark_types_)
        for (const Bookmark& b : bookmarks_)
            if (b.type == type) out.push_back({b.address, b.type, b.category, b.comment});
    return out;
}

void ProgramListing::setBookmark(uint64_t address, const std::string& type,
                                 const std::string& category, const std::string& comment) {
    for (Bookmark& b : bookmarks_) {
        if (b.address == address && b.type == type && b.category == category) {
            b.comment = comment;
            return;
        }
    }
    auto t = std::find(bookmark_types_.begin(), bookmark_types_.end(), type);
    if (t == bookmark_types_.end()) t = bookmark_types_.insert(bookmark_types_.end(), type);
    const int64_t type_id = t - bookmark_types_.begin();
    int64_t id = type_id << 48;
    for (const Bookmark& b : bookmarks_)
        if (b.type == type) id = std::max(id, b.id);
    bookmarks_.push_back({id + 1, address, type, category, comment});
}

bool ProgramListing::removeBookmark(uint64_t address, const std::string& type,
                                    const std::string& category) {
    for (auto it = bookmarks_.begin(); it != bookmarks_.end(); ++it) {
        if (it->address == address && it->type == type && it->category == category) {
            bookmarks_.erase(it);
            return true;
        }
    }
    return false;
}

bool ProgramListing::removeBookmarks(uint64_t address, const std::string& type) {
    const auto before = bookmarks_.size();
    bookmarks_.erase(std::remove_if(bookmarks_.begin(), bookmarks_.end(),
                                    [&](const Bookmark& b) {
                                        return b.address == address && b.type == type;
                                    }),
                     bookmarks_.end());
    return bookmarks_.size() != before;
}

// -- function tags -----------------------------------------------------------------

std::vector<FunctionTagInfo> ProgramListing::functionTags() const {
    std::vector<FunctionTagInfo> out;
    for (const auto& [name, tag] : tags_) out.push_back({name, tag.comment});
    return out;
}

bool ProgramListing::hasFunctionTag(const std::string& name) const { return tags_.count(name) != 0; }

std::vector<std::pair<uint64_t, std::string>> ProgramListing::tagMappings(uint64_t entry) const {
    std::vector<std::pair<uint64_t, std::string>> out;
    for (const auto& [name, tag] : tags_)
        for (uint64_t fn : tag.functions)
            if (entry == 0 || fn == entry) out.emplace_back(fn, name);
    std::stable_sort(out.begin(), out.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    return out;
}

bool ProgramListing::functionHasTag(uint64_t entry, const std::string& name) const {
    auto it = tags_.find(name);
    return it != tags_.end() && it->second.functions.count(entry) != 0;
}

void ProgramListing::createFunctionTag(const std::string& name, const std::string& comment) {
    tags_[name].comment = comment;
}

bool ProgramListing::deleteFunctionTag(const std::string& name) { return tags_.erase(name) != 0; }

void ProgramListing::tagFunction(uint64_t entry, const std::string& name) {
    tags_[name].functions.insert(entry);
}

bool ProgramListing::untagFunction(uint64_t entry, const std::string& name) {
    auto it = tags_.find(name);
    return it != tags_.end() && it->second.functions.erase(entry) != 0;
}

}  // namespace ghidra_standalone
