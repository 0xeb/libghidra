// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

// The program's listing beyond functions, kept the way the live host keeps it
// (measured against a live host): labels, defined data, comments,
// bookmarks and function tags. Loaded from a project db, edited by the write
// RPCs, and handed to the decompiler as the host's DecompileCallback hands it:
//   - a defined data item becomes a global symbol of its data type, named by
//     the primary label at its address (or Ghidra's dynamic name), read-only
//     or volatile as its block and settings say (encodeData);
//   - a primary label of the global namespace that no function or data item
//     covers becomes a code label (encodeLabel);
//   - every comment in a function's body becomes a comment of that function
//     (encodeComments: EOL user1, PRE user2, POST user3, PLATE header).

#include <cstdint>
#include <functional>
#include <memory>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "ghidra_decompiler.h"

namespace ghidra {
class Architecture;
class Datatype;
class LabSymbol;
class Scope;
class ScopeInternal;
class Symbol;
class SymbolEntry;
class Address;
}  // namespace ghidra

namespace ghidra_db {
struct ProjectData;
}

namespace ghidra_standalone {

/// The global scope the offline architecture is built with (an override of
/// Architecture::buildDatabase): a plain ScopeInternal that also answers what
/// the host's scope answers lazily, through its listing (see
/// ProgramListing::codeLabel and ProgramListing::undefinedConstant).
ghidra::Scope* newListingScope(ghidra::Architecture* arch);

class ProgramListing {
public:
    ProgramListing();
    ~ProgramListing();

    /// What the listing needs from its Decompiler.
    struct Hooks {
        /// The entry of the function whose body holds `address` (or starts there).
        std::function<std::optional<uint64_t>(uint64_t)> function_containing;
        /// The body ranges [first, last] of the function at `entry`.
        std::function<std::vector<std::pair<uint64_t, uint64_t>>(uint64_t)> function_body;
        /// A function symbol starts at `address`.
        std::function<bool(uint64_t)> function_at;
        /// An external reference stands at `address` (an import slot), which the
        /// host's lookupSymbol answers before any data or label.
        std::function<bool(uint64_t)> external_ref;
        /// An instruction of the listing starts at `address`.
        std::function<bool(uint64_t)> instruction_at;
    };

    void reset(ghidra::Architecture* arch, Hooks hooks);

    /// Load a project's listing: `data_types` holds the decompiler type of each
    /// data item (by address; missing = left out), `blocks` the memory map.
    /// `scope_of` gives the decompiler scope of a project namespace id (0 = global).
    void load(const ghidra_db::ProjectData& data,
              const std::map<uint64_t, ghidra::Datatype*>& data_types,
              const std::vector<MemoryBlockInfo>& blocks,
              const std::function<ghidra::Scope*(int64_t)>& scope_of);

    /// The memory map whose blocks decide a data item's mutability, and the
    /// addresses the program writes (bare binaries: no listing to load).
    void setMemory(const std::vector<MemoryBlockInfo>& blocks, const std::set<uint64_t>& written);

    // -- labels -------------------------------------------------------------
    std::vector<LabelInfo> labels(uint64_t first, uint64_t last) const;
    std::vector<LabelInfo> labelsAt(uint64_t address) const;
    std::optional<LabelInfo> primaryLabel(uint64_t address) const;
    /// The program's symbols in the EXTERNAL space whose offset is in [first, last]
    /// (namespace_path is the library; `function` says a function symbol).
    std::vector<std::pair<LabelInfo, bool>> externalSymbols(uint64_t first, uint64_t last) const;
    /// `address` is an external entry point (an export, the program entry).
    bool isEntryPoint(uint64_t address) const { return entry_points_.count(address) != 0; }
    /// The dynamic symbol of a referenced address with no symbol of its own.
    std::optional<LabelInfo> dynamicSymbol(uint64_t address) const;
    /// The label named `name` (or namespace-qualified `name`) at `address` is
    /// renamed; false when there is none.
    bool renameLabel(uint64_t address, const std::string& name, const std::string& new_name);
    /// The primary label at `address` is renamed, or a primary label of the
    /// global namespace is created there when it has none (the host's upsert).
    void renameOrCreatePrimary(uint64_t address, const std::string& new_name);
    /// Add the label `name` of the global namespace at `address`, beside any it
    /// has: primary only when the address has no symbol (SymbolTable.createLabel).
    void addLabel(uint64_t address, const std::string& name);
    /// Remove the labels at `address` named `name` (or all with `name` empty).
    /// Returns how many went.
    uint32_t removeLabels(uint64_t address, const std::string& name);
    /// A function now starts at `address`: its labels stop being primary and
    /// no code label stands in the decompiler's way.
    void functionCreated(uint64_t address);
    /// The symbol id the next created symbol takes (above every db id).
    uint64_t nextSymbolId() { return next_id_++; }

    /// The label the printer names a goto target inside a function by
    /// (DecompileCallback.getCodeLabel: the primary symbol there, a dynamic
    /// LAB_ for a referenced instruction). The host's address lookups never
    /// answer with it (a function's body is a hole to them), so it lives
    /// outside the global scope's address map. nullptr when there is none.
    ghidra::LabSymbol* codeLabel(const ghidra::Address& addr);
    /// Undefined bytes the host answers with a symbol although nothing names
    /// them: in a read-only block, outside every function, an undefined
    /// constant (encodeData of DEFAULT data with CONSTANT mutability), named
    /// UNK_<address>. Created in the global scope on first lookup, as the
    /// host's scope caches its answers. nullptr when the host answers a hole.
    ghidra::SymbolEntry* undefinedConstant(const ghidra::Address& addr);

    // -- data ----------------------------------------------------------------
    /// A defined data item starts at `address`.
    bool hasDataAt(uint64_t address) const;
    std::vector<DataItemInfo> dataItems(uint64_t first, uint64_t last) const;
    /// The symbol id of the function at `entry`; a function created offline
    /// takes the next id.
    uint64_t functionId(uint64_t entry) const;
    void setFunctionId(uint64_t entry, uint64_t id) { function_ids_[entry] = id; }
    /// The SourceType name of the function symbol at `entry` (USER_DEFINED,
    /// IMPORTED, ...); "" when the program never said.
    std::string functionSource(uint64_t entry) const;
    /// A write named the function (USER_DEFINED) or reset its name (DEFAULT).
    void setFunctionSource(uint64_t entry, bool user_defined) {
        function_sources_[entry] = user_defined ? 1 : 2;
    }
    /// Give `address` a data item of `type`: an existing one is retyped and
    /// keeps its name, a new one is named by the primary label there or DAT_.
    void defineData(uint64_t address, ghidra::Datatype* type);
    /// A data type changed size in place: each data item of it follows, as the
    /// host's code manager does. An item shrinks with its type; it grows only
    /// over bytes no other data item uses, and otherwise keeps its length.
    void refreshDataSizes();
    /// Clear the data item at `address` (its labels stay). False when none.
    bool clearData(uint64_t address);

    // -- comments ------------------------------------------------------------
    std::vector<ListingComment> comments(uint64_t first, uint64_t last) const;
    void setComment(uint64_t address, int type, const std::string& text);
    bool deleteComment(uint64_t address, int type);

    // -- bookmarks -----------------------------------------------------------
    std::vector<BookmarkInfo> bookmarks() const;
    /// Add a bookmark, or replace the comment of the one of that type and
    /// category at `address` (BookmarkManager.setBookmark).
    void setBookmark(uint64_t address, const std::string& type, const std::string& category,
                     const std::string& comment);
    bool removeBookmark(uint64_t address, const std::string& type, const std::string& category);
    /// Every bookmark of `type` at `address` goes; false when there was none.
    bool removeBookmarks(uint64_t address, const std::string& type);

    // -- function tags -------------------------------------------------------
    std::vector<FunctionTagInfo> functionTags() const;
    bool hasFunctionTag(const std::string& name) const;
    /// (entry, tag) pairs, in entry order; `entry` 0 = every function.
    std::vector<std::pair<uint64_t, std::string>> tagMappings(uint64_t entry) const;
    bool functionHasTag(uint64_t entry, const std::string& name) const;
    void createFunctionTag(const std::string& name, const std::string& comment);
    bool deleteFunctionTag(const std::string& name);
    void tagFunction(uint64_t entry, const std::string& name);
    bool untagFunction(uint64_t entry, const std::string& name);

private:
    struct Label {
        uint64_t id = 0;
        uint64_t address = 0;
        std::string name;
        ghidra::Scope* scope = nullptr;   // its namespace's decompiler scope
        bool primary = false;
        int source = 0;
        ghidra::Symbol* code_label = nullptr;   // the decompiler's view, if any
    };
    struct Data {
        ghidra::Symbol* symbol = nullptr;
        ghidra::Datatype* type = nullptr;
        bool named_by_label = false;
        // Data.getLength(): the type's size, unless the type grew after the item
        // was defined and the bytes after it were not free.
        int length = 0;
    };
    int dataLength(const Data& item) const;
    struct Bookmark {
        int64_t id = 0;
        uint64_t address = 0;
        std::string type;
        std::string category;
        std::string comment;
    };
    struct Tag {
        std::string comment;
        std::set<uint64_t> functions;
    };

    LabelInfo info(const Label& l) const;
    Label* primaryOf(uint64_t address);
    std::vector<Label*> at(uint64_t address);
    // Name the data item at `address` after its primary label (or DAT_...).
    void refreshDataName(uint64_t address);
    // Give or take a code label for the primary label at `address`.
    void refreshCodeLabel(uint64_t address);
    // Put the comments of the function at `entry` into the decompiler's
    // comment database, as the host's encodeComments does.
    void refreshFunctionComments(uint64_t entry);
    // The flags the host's data symbol carries (readonly / volatile).
    uint32_t dataFlags(uint64_t address, int mutability) const;
    bool dataCovers(uint64_t address) const;
    std::string dynamicName(uint64_t address, ghidra::Datatype* type) const;
    // The decompiler may see a data item at `address` (no function or external
    // reference takes precedence there).
    bool dataVisible(uint64_t address) const;
    ghidra::Symbol* addDataSymbol(uint64_t address, ghidra::Datatype* type, const std::string& name,
                                  ghidra::Scope* scope, uint32_t flags);

    ghidra::Architecture* arch_ = nullptr;
    Hooks hooks_;
    std::vector<Label> labels_;           // address, then id order
    std::vector<std::pair<LabelInfo, bool>> externals_;  // offset, then id order
    std::set<uint64_t> entry_points_;
    std::map<uint64_t, Data> data_;
    std::map<uint64_t, int> data_mutability_;
    // A data item's default label prefix where its built-in type has its own
    // (DataType.getDefaultLabelPrefix); "" = none (the reference level names it).
    std::map<uint64_t, std::string> data_prefix_;
    std::map<std::pair<uint64_t, int>, std::string> comments_;
    std::vector<Bookmark> bookmarks_;     // type order, then id
    std::vector<std::string> bookmark_types_;
    std::map<std::string, Tag> tags_;
    std::vector<MemoryBlockInfo> blocks_;
    std::set<uint64_t> written_;
    std::map<uint64_t, uint64_t> function_ids_;
    std::map<uint64_t, int> function_sources_;
    // Referenced addresses (reference level), and the dynamic symbol the
    // decompiler sees at one that has no symbol of its own.
    std::map<uint64_t, int> references_;
    std::map<uint64_t, ghidra::Symbol*> dynamic_;
    // In-function code labels, kept out of the global scope's address map.
    std::unique_ptr<ghidra::ScopeInternal> hidden_;
    std::map<uint64_t, ghidra::LabSymbol*> hidden_labels_;
    std::set<uint64_t> undefined_constants_;
    uint64_t next_id_ = 1;
};

}  // namespace ghidra_standalone
