// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "local_arch_adapter.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>
#include <ostream>
#include <set>
#include <sstream>
#include <streambuf>
#include <utility>

#include "libdecomp.hh"
#include "print_stream_guard.hpp"

#ifdef LIBGHIDRA_LOCAL_TEST_HOOKS
#include "local_test_hooks.hpp"
#endif

using namespace ghidra;

namespace libghidra::client::detail {

#ifdef LIBGHIDRA_LOCAL_TEST_HOOKS
namespace testhooks {
void (*post_decompile_fault)() = nullptr;
int analysis_clear_count = 0;
}  // namespace testhooks
#endif

// -- AssemblyEmit helper for disassembly -------------------------------------

namespace {

// "List all" range convention, unified with the RPC host and the C++/Python
// clients: range_end is an exclusive upper bound and range_end == 0 is the
// "all addresses" sentinel, normalized to the full 64-bit space. A real
// range_end filters; (0, 0) and (0, UINT64_MAX) both mean "everything".
constexpr std::uint64_t kAllRangeEnd = UINT64_MAX;

std::uint64_t normalize_range_end(std::uint64_t range_end) {
  return range_end == 0 ? kAllRangeEnd : range_end;
}

// Absolute safety cap for an unbounded (limit <= 0) linear instruction sweep,
// so a (0, UINT64_MAX) "all" range can never run away across the address space.
// Far larger than any real contiguous instruction run; callers that need more
// paginate with a positive limit.
constexpr int kMaxUnboundedInstructions = 1000000;

// Classify the in-flight exception into a human-readable message. MUST be called
// from within a catch block (it re-throws with `throw;`). Ghidra's RecovError /
// LowlevelError do not derive from std::exception, so they are named explicitly
// and their `.explain` is used, mirroring Decompiler::decompileAt.
std::string describe_current_exception() {
  try {
    throw;
  } catch (const RecovError& e) {
    return e.explain;
  } catch (const LowlevelError& e) {
    return e.explain;
  } catch (const std::exception& e) {
    return e.what();
  } catch (const char* msg) {
    return msg;
  } catch (...) {
    return "unknown exception";
  }
}

void log_caught_exception(const char* context) {
  fprintf(stderr, "[libghidra] %s: %s\n", context,
          describe_current_exception().c_str());
}

using libghidra::detail::ScopedPrintStream;

// Parse the signed stack offset out of a canonical "local:Stack[<off>]" id.
// Tolerates leading/trailing whitespace and any trailing suffix after ']' (e.g. a
// retired ":size:firstUse"), mirroring the live host's parseStackOffsetFromLocalId.
std::optional<long long> parse_stack_offset_from_local_id(const std::string& id) {
  size_t start = id.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return std::nullopt;
  static const std::string kPrefix = "local:Stack[";
  if (id.compare(start, kPrefix.size(), kPrefix) != 0) return std::nullopt;
  size_t lb = id.find('[', start);
  size_t rb = id.find(']', lb);
  if (lb == std::string::npos || rb == std::string::npos || rb <= lb + 1)
    return std::nullopt;
  std::string off = id.substr(lb + 1, rb - lb - 1);
  size_t a = off.find_first_not_of(" \t");
  size_t b = off.find_last_not_of(" \t");
  if (a == std::string::npos) return std::nullopt;
  off = off.substr(a, b - a + 1);
  try {
    bool neg = false;
    std::string digits = off;
    if (!digits.empty() && (digits[0] == '+' || digits[0] == '-')) {
      neg = digits[0] == '-';
      digits = digits.substr(1);
    }
    long long v = 0;
    if (digits.rfind("0x", 0) == 0 || digits.rfind("0X", 0) == 0)
      v = std::stoll(digits.substr(2), nullptr, 16);
    else
      v = std::stoll(digits, nullptr, 10);
    return neg ? -v : v;
  } catch (...) {
    return std::nullopt;
  }
}

// Tolerant resolve of a requested local_id against an enumerated local record.
// Order mirrors the Java host: exact id, then numeric stack-offset equality
// (suffix/whitespace tolerant), then the variable's plain name.
bool local_id_resolves(const DecompileLocalRecord& rec,
                       const std::string& requested) {
  if (rec.local_id == requested) return true;
  size_t a = requested.find_first_not_of(" \t\r\n");
  size_t b = requested.find_last_not_of(" \t\r\n");
  const std::string req =
      (a == std::string::npos) ? std::string() : requested.substr(a, b - a + 1);
  if (!req.empty() && rec.local_id == req) return true;
  auto off_rec = parse_stack_offset_from_local_id(rec.local_id);
  auto off_req = parse_stack_offset_from_local_id(requested);
  if (off_rec.has_value() && off_req.has_value() && *off_rec == *off_req)
    return true;
  if (!rec.name.empty() && rec.name == req) return true;
  return false;
}

class StringAssemblyEmit : public AssemblyEmit {
 public:
  std::string mnemonic;
  std::string body;

  void dump(const Address& /*addr*/, const string& mnem,
            const string& bod) override {
    mnemonic = mnem;
    body = bod;
  }
};

std::string metatype_to_kind(type_metatype mt) {
  switch (mt) {
    case TYPE_INT:
    case TYPE_UINT:
      return "int";
    case TYPE_FLOAT:
      return "float";
    case TYPE_BOOL:
      return "bool";
    case TYPE_CODE:
      return "code";
    case TYPE_VOID:
      return "void";
    case TYPE_STRUCT:
      return "struct";
    case TYPE_UNION:
      return "union";
    case TYPE_ARRAY:
      return "array";
    case TYPE_PTR:
      return "pointer";
    case TYPE_PTRREL:
      return "pointer";
    case TYPE_UNKNOWN:
      return "undefined";
    default:
      return "other";
  }
}

}  // namespace

// -- ArchAdapter implementation ----------------------------------------------

ArchAdapter::ArchAdapter(void* arch_ptr)
    : arch_(static_cast<Architecture*>(arch_ptr)) {}

std::vector<FunctionRecord> ArchAdapter::listFunctions(std::uint64_t range_start,
                                                       std::uint64_t range_end) {
  std::vector<FunctionRecord> result;
  if (!arch_) return result;
  range_end = normalize_range_end(range_end);

  try {
    Scope* global = arch_->symboltab->getGlobalScope();

    // Collect ALL functions in address order (the symbol map iterates sorted) so a
    // function's size can be the gap to the NEXT function. FunctionSymbol::
    // getBytesConsumed() is only the symbol's alignment footprint (~1-8 bytes),
    // never the body extent (so end_address degenerated to ~start); the next-entry
    // gap is a cheap, close upper bound that makes address-containment work. (The
    // truly faithful extent needs the program-DB body range or a followFlow — a
    // further refinement.)
    struct Fn {
      std::uint64_t addr;
      std::string name;
      std::uint64_t footprint;
    };
    std::vector<Fn> fns;
    MapIterator it = global->begin();
    MapIterator end = global->end();
    for (; it != end; ++it) {
      const SymbolEntry* entry = *it;
      const FunctionSymbol* fsym =
          dynamic_cast<const FunctionSymbol*>(entry->getSymbol());
      if (fsym == nullptr) continue;
      int4 sz = fsym->getBytesConsumed();
      fns.push_back({entry->getAddr().getOffset(), fsym->getName(),
                     sz > 0 ? static_cast<std::uint64_t>(sz) : 0});
    }

    for (std::size_t i = 0; i < fns.size(); i++) {
      // Apply range filter; range_end is normalized so (0,0) == all.
      if (fns[i].addr < range_start || fns[i].addr >= range_end) continue;

      FunctionRecord rec;
      rec.entry_address = fns[i].addr;
      rec.start_address = fns[i].addr;
      rec.name = fns[i].name;
      // Size = gap to the next function (address order); fall back to the footprint
      // for the last function (no successor).
      std::uint64_t size = fns[i].footprint;
      if (i + 1 < fns.size() && fns[i + 1].addr > fns[i].addr) {
        size = fns[i + 1].addr - fns[i].addr;
      }
      rec.size = size;
      // end_address is INCLUSIVE (last byte), matching the live Java host's Ghidra
      // maxAddress semantics. A zero-size record degenerates to end == start.
      rec.end_address = size > 0 ? rec.start_address + size - 1 : rec.start_address;
      result.push_back(std::move(rec));
    }
  } catch (...) {
    log_caught_exception("listFunctions");
  }

  return result;
}

std::optional<FunctionRecord> ArchAdapter::getFunction(std::uint64_t address) {
  if (!arch_) return std::nullopt;

  try {
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(address));
    Scope* global = arch_->symboltab->getGlobalScope();
    Funcdata* fd = global->queryFunction(addr);

    if (!fd) {
      // Check if there's a function symbol at this address
      SymbolEntry* entry = global->findAddr(addr, Address());
      if (!entry) return std::nullopt;
      const FunctionSymbol* fsym = dynamic_cast<const FunctionSymbol*>(entry->getSymbol());
      if (!fsym) return std::nullopt;

      FunctionRecord rec;
      rec.entry_address = address;
      rec.start_address = address;
      rec.name = fsym->getName();
      int4 sz = fsym->getBytesConsumed();
      rec.size = (sz > 0) ? static_cast<std::uint64_t>(sz) : 0;
      // INCLUSIVE end (see listFunctions above).
      rec.end_address =
          rec.size > 0 ? rec.start_address + rec.size - 1 : rec.start_address;
      return rec;
    }

    FunctionRecord rec;
    rec.entry_address = fd->getAddress().getOffset();
    rec.start_address = rec.entry_address;
    rec.name = fd->getName();
    rec.size = fd->getSize();
    // INCLUSIVE end (see listFunctions above).
    rec.end_address =
        rec.size > 0 ? rec.start_address + rec.size - 1 : rec.start_address;
    return rec;
  } catch (...) {
    log_caught_exception("getFunction");
    return std::nullopt;
  }
}

std::vector<SymbolRecord> ArchAdapter::listSymbols(std::uint64_t range_start,
                                                   std::uint64_t range_end) {
  std::vector<SymbolRecord> result;
  if (!arch_) return result;
  range_end = normalize_range_end(range_end);

  try {
    Scope* global = arch_->symboltab->getGlobalScope();
    MapIterator it = global->begin();
    MapIterator end = global->end();
    std::uint64_t id_counter = 0;

    while (it != end) {
      const SymbolEntry* entry = *it;
      const Symbol* sym = entry->getSymbol();
      std::uint64_t addr = entry->getAddr().getOffset();

      if (addr < range_start || addr >= range_end) {
        ++it;
        continue;
      }

      SymbolRecord rec;
      rec.symbol_id = id_counter++;
      rec.address = addr;
      rec.name = sym->getName();
      rec.full_name = sym->getName();
      rec.is_primary = true;

      const FunctionSymbol* fsym = dynamic_cast<const FunctionSymbol*>(sym);
      rec.type = fsym ? "function" : "label";

      result.push_back(std::move(rec));
      ++it;
    }
  } catch (...) {
    log_caught_exception("listSymbols");
  }

  return result;
}

std::optional<SymbolRecord> ArchAdapter::getSymbol(std::uint64_t address) {
  if (!arch_) return std::nullopt;

  try {
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(address));
    Scope* global = arch_->symboltab->getGlobalScope();
    SymbolEntry* entry = global->findAddr(addr, Address());
    if (!entry) return std::nullopt;

    const Symbol* sym = entry->getSymbol();

    SymbolRecord rec;
    rec.address = address;
    rec.name = sym->getName();
    rec.full_name = sym->getName();
    rec.is_primary = true;
    const FunctionSymbol* fsym = dynamic_cast<const FunctionSymbol*>(sym);
    rec.type = fsym ? "function" : "label";
    return rec;
  } catch (...) {
    log_caught_exception("getSymbol");
    return std::nullopt;
  }
}

std::vector<TypeRecord> ArchAdapter::listTypes(const std::string& query) {
  std::vector<TypeRecord> result;
  if (!arch_) return result;

  try {
    TypeFactory* tf = arch_->types;

    // Use dependentOrder to get all types (tree is private)
    vector<Datatype*> deporder;
    tf->dependentOrder(deporder);

    std::uint64_t id_counter = 0;
    for (Datatype* dt : deporder) {
      // Substring filter
      if (!query.empty() && dt->getName().find(query) == std::string::npos)
        continue;

      TypeRecord rec;
      rec.type_id = id_counter++;
      rec.name = dt->getName();
      rec.path_name = "/" + dt->getName();
      rec.display_name = dt->getDisplayName();
      rec.kind = metatype_to_kind(dt->getMetatype());
      rec.length = dt->getSize();
      result.push_back(std::move(rec));
    }
  } catch (...) {
    log_caught_exception("listTypes");
  }

  return result;
}

std::vector<TypeEnumRecord> ArchAdapter::listTypeEnums(const std::string& query) {
  std::vector<TypeEnumRecord> result;
  if (!arch_) return result;

  try {
    TypeFactory* tf = arch_->types;

    vector<Datatype*> deporder;
    tf->dependentOrder(deporder);

    std::uint64_t id_counter = 0;
    for (Datatype* dt : deporder) {
      TypeEnum* te = dynamic_cast<TypeEnum*>(dt);
      if (!te) continue;

      if (!query.empty() && te->getName().find(query) == std::string::npos)
        continue;

      TypeEnumRecord rec;
      rec.type_id = id_counter++;
      rec.path_name = "/" + te->getName();
      rec.name = te->getName();
      rec.width = te->getSize();
      result.push_back(std::move(rec));
    }
  } catch (...) {
    log_caught_exception("listTypeEnums");
  }

  return result;
}

std::vector<TypeEnumMemberRecord> ArchAdapter::listTypeEnumMembers(
    const std::string& type_name) {
  std::vector<TypeEnumMemberRecord> result;
  if (!arch_) return result;

  try {
    Datatype* dt = arch_->types->findByName(type_name);
    if (!dt) return result;
    TypeEnum* te = dynamic_cast<TypeEnum*>(dt);
    if (!te) return result;

    // Iterate enum name map via beginEnum/endEnum
    std::uint64_t ordinal = 0;
    for (auto eit = te->beginEnum(); eit != te->endEnum(); ++eit) {
      TypeEnumMemberRecord rec;
      rec.type_name = te->getName();
      rec.type_path_name = "/" + te->getName();
      rec.ordinal = ordinal;
      rec.name = eit->second;
      rec.value = static_cast<std::int64_t>(eit->first);
      auto cit = type_enum_member_comments_.find({type_name, ordinal});
      if (cit != type_enum_member_comments_.end())
        rec.comment = cit->second;
      ordinal++;
      result.push_back(std::move(rec));
    }
  } catch (...) {
    log_caught_exception("listTypeEnumMembers");
  }

  return result;
}

std::vector<TypeMemberRecord> ArchAdapter::listTypeMembers(
    const std::string& type_name) {
  std::vector<TypeMemberRecord> result;
  if (!arch_) return result;

  try {
    Datatype* dt = arch_->types->findByName(type_name);
    if (!dt) return result;
    TypeStruct* ts = dynamic_cast<TypeStruct*>(dt);
    if (!ts) return result;

    std::uint64_t ordinal = 0;
    for (auto fit = ts->beginField(); fit != ts->endField(); ++fit) {
      TypeMemberRecord rec;
      rec.parent_type_name = ts->getName();
      rec.parent_type_path_name = "/" + ts->getName();
      rec.ordinal = ordinal;
      rec.name = fit->name;
      rec.member_type = fit->type->getName();
      rec.offset = fit->offset;
      rec.size = fit->type->getSize();
      auto cit = type_member_comments_.find({type_name, ordinal});
      if (cit != type_member_comments_.end())
        rec.comment = cit->second;
      ordinal++;
      result.push_back(std::move(rec));
    }
  } catch (...) {
    log_caught_exception("listTypeMembers");
  }

  return result;
}

std::vector<std::uint8_t> ArchAdapter::readBytes(std::uint64_t address,
                                                 std::uint32_t length) {
  std::vector<std::uint8_t> result;
  if (!arch_ || length == 0) return result;

  try {
    result.resize(length);
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(address));
    arch_->loader->loadFill(result.data(), static_cast<int4>(length), addr);
  } catch (...) {
    log_caught_exception("readBytes");
    result.clear();
  }

  return result;
}

std::optional<InstructionRecord> ArchAdapter::getInstruction(std::uint64_t address) {
  if (!arch_) return std::nullopt;

  try {
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(address));

    StringAssemblyEmit emit;
    int4 len = arch_->translate->printAssembly(emit, addr);
    if (len <= 0) return std::nullopt;

    InstructionRecord rec;
    rec.address = address;
    rec.mnemonic = emit.mnemonic;
    rec.operand_text = emit.body;
    rec.disassembly = emit.mnemonic;
    if (!emit.body.empty()) {
      rec.disassembly += " " + emit.body;
    }
    rec.length = static_cast<std::uint32_t>(len);
    return rec;
  } catch (...) {
    log_caught_exception("getInstruction");
    return std::nullopt;
  }
}

std::vector<InstructionRecord> ArchAdapter::listInstructions(
    std::uint64_t range_start, std::uint64_t range_end, int limit) {
  std::vector<InstructionRecord> result;
  if (!arch_) return result;
  range_end = normalize_range_end(range_end);
  if (range_start >= range_end) return result;

  // Bound an unbounded (limit <= 0) sweep so a normalized "all" range cannot
  // walk the whole address space. getInstruction() already breaks at the first
  // gap; this cap is a hard backstop against a runaway linear disassembly.
  const int effective_limit = limit > 0 ? limit : kMaxUnboundedInstructions;

  try {
    std::uint64_t cur = range_start;
    int count = 0;

    while (cur < range_end && count < effective_limit) {
      auto insn = getInstruction(cur);
      if (!insn || insn->length == 0) break;

      result.push_back(std::move(*insn));
      cur += result.back().length;
      ++count;
    }
  } catch (...) {
    log_caught_exception("listInstructions");
  }

  return result;
}

namespace {
// Defined below; owns followFlow + perform and sets fd_out even on failure (for
// cleanup). listXrefsForFunction runs its OWN analysis via this so it reads a live
// Funcdata rather than one the caller already decompiled-and-cleared.
bool decompile_perform(Architecture* arch, std::uint64_t entry, Funcdata*& fd_out);
}  // namespace

std::vector<XrefRecord> ArchAdapter::listXrefsForFunction(
    std::uint64_t func_entry) {
  std::vector<XrefRecord> result;
  if (!arch_) return result;

  // Own the analysis lifetime: run the decompiler actions and read the xrefs
  // (below) BEFORE clearing. The caller no longer pre-decompiles — that ran
  // perform() then clearAnalysis(), leaving a re-fetched Funcdata non-null but
  // WIPED (empty numCalls()/beginOp), so every offline xref query returned empty.
  Funcdata* fd = nullptr;
  try {
    if (!decompile_perform(arch_, func_entry, fd)) {
      if (fd) arch_->clearAnalysis(fd);
      return result;
    }

    // Extract call xrefs from FuncCallSpecs
    for (int4 i = 0; i < fd->numCalls(); i++) {
      FuncCallSpecs* cs = fd->getCallSpecs(i);
      if (!cs) continue;

      PcodeOp* op = cs->getOp();
      if (!op) continue;

      XrefRecord rec;
      rec.from_address = op->getAddr().getOffset();
      rec.to_address = cs->getEntryAddress().getOffset();
      rec.ref_type = (op->code() == CPUI_CALLIND) ? "COMPUTED_CALL"
                                                   : "UNCONDITIONAL_CALL";
      rec.is_flow = true;
      rec.is_primary = true;
      rec.source = "ANALYSIS";
      result.push_back(std::move(rec));
    }

    // Extract data xrefs from LOAD operations with constant addresses
    for (auto it = fd->beginOp(CPUI_LOAD); it != fd->endOp(CPUI_LOAD); ++it) {
      PcodeOp* op = *it;
      if (!op || op->numInput() < 2) continue;

      const Varnode* addr_vn = op->getIn(1);
      if (addr_vn && addr_vn->isConstant()) {
        XrefRecord rec;
        rec.from_address = op->getAddr().getOffset();
        rec.to_address = addr_vn->getOffset();
        rec.ref_type = "DATA";
        rec.is_memory = true;
        rec.source = "ANALYSIS";
        result.push_back(std::move(rec));
      }
    }

    // Extract data xrefs from STORE operations with constant addresses
    for (auto it = fd->beginOp(CPUI_STORE); it != fd->endOp(CPUI_STORE); ++it) {
      PcodeOp* op = *it;
      if (!op || op->numInput() < 2) continue;

      const Varnode* addr_vn = op->getIn(1);
      if (addr_vn && addr_vn->isConstant()) {
        XrefRecord rec;
        rec.from_address = op->getAddr().getOffset();
        rec.to_address = addr_vn->getOffset();
        rec.ref_type = "WRITE";
        rec.is_memory = true;
        rec.source = "ANALYSIS";
        result.push_back(std::move(rec));
      }
    }
    arch_->clearAnalysis(fd);  // reads complete — release the analysis state
  } catch (...) {
    if (fd) arch_->clearAnalysis(fd);
    log_caught_exception("listXrefsForFunction");
  }

  return result;
}

std::optional<TypeRecord> ArchAdapter::getType(const std::string& name) {
  if (!arch_ || name.empty()) return std::nullopt;

  try {
    Datatype* dt = arch_->types->findByName(name);
    if (!dt) return std::nullopt;

    TypeRecord rec;
    rec.type_id = 0;
    rec.name = dt->getName();
    rec.path_name = "/" + dt->getName();
    rec.display_name = dt->getDisplayName();
    rec.kind = metatype_to_kind(dt->getMetatype());
    rec.length = dt->getSize();
    return rec;
  } catch (...) {
    log_caught_exception("getType");
    return std::nullopt;
  }
}

std::vector<TypeAliasRecord> ArchAdapter::listTypeAliases(
    const std::string& query) {
  std::vector<TypeAliasRecord> result;
  if (!arch_) return result;

  try {
    TypeFactory* tf = arch_->types;
    vector<Datatype*> deporder;
    tf->dependentOrder(deporder);

    std::uint64_t id_counter = 0;
    for (Datatype* dt : deporder) {
      Datatype* target = dt->getTypedef();
      if (!target) continue;

      if (!query.empty() && dt->getName().find(query) == std::string::npos)
        continue;

      TypeAliasRecord rec;
      rec.type_id = id_counter++;
      rec.path_name = "/" + dt->getName();
      rec.name = dt->getName();
      rec.target_type = target->getName();
      rec.declaration = "typedef " + target->getName() + " " + dt->getName();
      result.push_back(std::move(rec));
    }
  } catch (...) {
    log_caught_exception("listTypeAliases");
  }

  return result;
}

std::vector<TypeUnionRecord> ArchAdapter::listTypeUnions(
    const std::string& query) {
  std::vector<TypeUnionRecord> result;
  if (!arch_) return result;

  try {
    TypeFactory* tf = arch_->types;
    vector<Datatype*> deporder;
    tf->dependentOrder(deporder);

    std::uint64_t id_counter = 0;
    for (Datatype* dt : deporder) {
      if (dt->getMetatype() != TYPE_UNION) continue;

      if (!query.empty() && dt->getName().find(query) == std::string::npos)
        continue;

      TypeUnionRecord rec;
      rec.type_id = id_counter++;
      rec.path_name = "/" + dt->getName();
      rec.name = dt->getName();
      rec.size = dt->getSize();
      result.push_back(std::move(rec));
    }
  } catch (...) {
    log_caught_exception("listTypeUnions");
  }

  return result;
}

std::vector<MemoryBlockRecord> ArchAdapter::listMemoryBlocks() {
  std::vector<MemoryBlockRecord> result;
  if (!arch_) return result;

  try {
    AddrSpace* code_space = arch_->getDefaultCodeSpace();
    if (!code_space) return result;

    MemoryBlockRecord rec;
    rec.name = code_space->getName();
    rec.start_address = 0;
    rec.end_address = code_space->getHighest();
    rec.size = rec.end_address + 1;
    rec.is_read = true;
    rec.is_execute = true;
    rec.is_initialized = true;
    rec.source_name = "raw";
    result.push_back(std::move(rec));
  } catch (...) {
    log_caught_exception("listMemoryBlocks");
  }

  return result;
}

std::optional<FunctionSignatureRecord> ArchAdapter::getFunctionSignature(
    std::uint64_t address) {
  if (!arch_) return std::nullopt;

  try {
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(address));
    Scope* global = arch_->symboltab->getGlobalScope();
    Funcdata* fd = global->queryFunction(addr);
    if (!fd) return std::nullopt;

    const FuncProto& proto = fd->getFuncProto();

    FunctionSignatureRecord rec;
    rec.function_entry_address = address;
    rec.function_name = fd->getName();
    rec.has_var_args = proto.isDotdotdot();

    // Return type
    Datatype* ret_type = proto.getOutputType();
    rec.return_type = ret_type ? ret_type->getName() : "void";

    // Calling convention
    rec.calling_convention = proto.getModelName();

    // Parameters
    int4 num_params = proto.numParams();
    for (int4 i = 0; i < num_params; i++) {
      ProtoParameter* pp = proto.getParam(i);
      ParameterRecord prec;
      prec.ordinal = i;
      prec.name = pp->getName();
      Datatype* pt = pp->getType();
      prec.data_type = pt ? pt->getName() : "undefined";
      prec.formal_data_type = prec.data_type;
      rec.parameters.push_back(std::move(prec));
    }

    // Build prototype string
    std::string proto_str = rec.return_type + " " + fd->getName() + "(";
    for (int4 i = 0; i < num_params; i++) {
      if (i > 0) proto_str += ", ";
      proto_str += rec.parameters[i].data_type + " " + rec.parameters[i].name;
    }
    if (rec.has_var_args) {
      if (num_params > 0) proto_str += ", ";
      proto_str += "...";
    }
    proto_str += ")";
    rec.prototype = std::move(proto_str);

    return rec;
  } catch (...) {
    log_caught_exception("getFunctionSignature");
    return std::nullopt;
  }
}

// Recursively collect all BlockBasic leaf nodes from a structured FlowBlock.
// Handles BlockGraph children (BlockIf, etc.) and BlockCopy wrappers.
static void collectBasicBlocks(const FlowBlock* block,
                               std::vector<const BlockBasic*>& out) {
  if (block->getType() == FlowBlock::t_basic) {
    out.push_back(static_cast<const BlockBasic*>(block));
    return;
  }
  // BlockGraph subclasses: use getSize()/getBlock()
  const BlockGraph* graph = dynamic_cast<const BlockGraph*>(block);
  if (graph) {
    for (int4 i = 0; i < graph->getSize(); i++) {
      collectBasicBlocks(graph->getBlock(i), out);
    }
    return;
  }
  // BlockCopy and other wrappers: subBlock(0) returns the wrapped block
  const FlowBlock* sub = block->subBlock(0);
  if (sub) {
    collectBasicBlocks(sub, out);
  }
}

ArchAdapter::CFGResult ArchAdapter::decompileAndExtractCFG(
    std::uint64_t func_entry) {
  CFGResult result;
  if (!arch_) return result;

  try {
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(func_entry));
    Scope* global = arch_->symboltab->getGlobalScope();

    // Create or find the function
    Funcdata* fd = global->queryFunction(addr);
    if (!fd) {
      string name;
      arch_->nameFunction(addr, name);
      fd = global->addFunction(addr, name)->getFunction();
    }

    // Follow control flow
    Address baddr(space, 0);
    Address eaddr(space, space->getHighest());
    fd->followFlow(baddr, eaddr);

    // Run decompilation actions (populates blocks + pcode)
    arch_->allacts.getCurrent()->reset(*fd);
    int4 res = arch_->allacts.getCurrent()->perform(*fd);
    if (res < 0) {
      arch_->clearAnalysis(fd);
      return result;
    }

    // Extract blocks and edges BEFORE clearAnalysis destroys them.
    // Try sblocks first (structured), fall back to bblocks (raw).
    const BlockGraph& structure = fd->getStructure();
    const BlockGraph& raw = fd->getBasicBlocks();
    std::vector<const BlockBasic*> basics;

    if (structure.getSize() > 0) {
      for (int4 i = 0; i < structure.getSize(); i++) {
        collectBasicBlocks(structure.getBlock(i), basics);
      }
    } else if (raw.getSize() > 0) {
      for (int4 i = 0; i < raw.getSize(); i++) {
        collectBasicBlocks(raw.getBlock(i), basics);
      }
    }

    for (const BlockBasic* bb : basics) {
      Address start = bb->getStart();
      Address stop = bb->getStop();
      if (start.isInvalid()) continue;

      BasicBlockRecord rec;
      rec.function_entry = func_entry;
      rec.start_address = start.getOffset();
      // INCLUSIVE end: getStop() already points at the block's last
      // instruction, matching the live Java host's inclusive maxAddress
      // contract — no +1.
      rec.end_address = stop.isInvalid() ? rec.start_address : stop.getOffset();
      rec.in_degree = static_cast<std::uint32_t>(bb->sizeIn());
      rec.out_degree = static_cast<std::uint32_t>(bb->sizeOut());
      result.blocks.push_back(std::move(rec));
    }

    for (const BlockBasic* bb : basics) {
      Address src_start = bb->getStart();
      if (src_start.isInvalid()) continue;

      for (int4 j = 0; j < bb->sizeOut(); j++) {
        const FlowBlock* dst = bb->getOut(j);
        // Walk through structured wrappers to find the leaf BlockBasic
        const BlockGraph* dg;
        while (dst && dst->getType() != FlowBlock::t_basic &&
               (dg = dynamic_cast<const BlockGraph*>(dst)) != nullptr &&
               dg->getSize() > 0) {
          dst = dg->getBlock(0);
        }
        if (!dst || dst->getType() != FlowBlock::t_basic) continue;

        const BlockBasic* dst_bb = static_cast<const BlockBasic*>(dst);
        Address dst_start = dst_bb->getStart();
        if (dst_start.isInvalid()) continue;

        CFGEdgeRecord rec;
        rec.function_entry = func_entry;
        rec.src_block_start = src_start.getOffset();
        rec.dst_block_start = dst_start.getOffset();

        if (dst_bb->getIndex() <= bb->getIndex()) {
          rec.edge_kind = "BACK";
        } else if (bb->sizeOut() == 2) {
          rec.edge_kind = (j == 0) ? "FALSE" : "TRUE";
        } else {
          rec.edge_kind = "FALL_THROUGH";
        }

        result.edges.push_back(std::move(rec));
      }
    }

    // Clean up analysis
    arch_->clearAnalysis(fd);
  } catch (...) {
    log_caught_exception("decompileAndExtractCFG");
  }

  return result;
}

// -- Function-local surface (enumeration + durable rename/retype) -------------
//
// The offline decompiler has no program database, so it cannot reproduce the
// live host's persistent "local:id:<dbid>" identity nor its Java storage
// serialization string.  Instead it emits its OWN canonical local_id (stack and
// anon forms match the live scheme; register/dynamic forms are offline-native)
// and resolves a rename/retype by re-deriving the SAME id and matching by string
// -- exactly how the Java host's matchesLocalId round-trips.  Because emit and
// resolve share this one function, the round-trip is self-consistent regardless
// of cross-engine parity.

namespace {

std::string to_hex(std::uint64_t v) {
  std::ostringstream ss;
  ss << std::hex << v;
  return ss.str();
}

std::string format_stack_offset(intb off) {
  std::ostringstream ss;
  if (off < 0)
    ss << "-0x" << std::hex << static_cast<std::uint64_t>(-off);
  else
    ss << "0x" << std::hex << static_cast<std::uint64_t>(off);
  return ss.str();
}

// Parse a C type string into a Datatype (mirrors Decompiler::Impl::parseType so
// the offline retype path shares the global path's grammar + C-alias handling).
Datatype* parse_c_type(Architecture* arch, const std::string& type_str) {
  try {
    std::string base = type_str;
    std::string array_suffix;
    size_t bracket = type_str.find('[');
    if (bracket != std::string::npos) {
      base = type_str.substr(0, bracket);
      array_suffix = type_str.substr(bracket);
      while (!base.empty() && base.back() == ' ') base.pop_back();
    }
    std::istringstream ss(base + " _p" + array_suffix);
    string name;
    return parse_type(ss, name, arch);
  } catch (...) {
    return nullptr;
  }
}

// Canonical local_id, mirroring the live host's FunctionSupport.canonicalLocalId
// for the cases the offline engine can produce.
std::string canonical_local_id(Architecture* arch, Funcdata* fd, const Symbol* sym) {
  if (sym->getCategory() == Symbol::function_parameter)
    return "arg" + std::to_string(static_cast<unsigned>(sym->getCategoryIndex()));

  const SymbolEntry* entry = sym->getFirstWholeMap();
  int first_use = 0;
  if (entry != nullptr) {
    Address fu = entry->getFirstUseAddress();
    if (!fu.isInvalid())
      first_use = static_cast<int>(static_cast<intb>(fu.getOffset()) -
                                   static_cast<intb>(fd->getAddress().getOffset()));
  }
  if (entry != nullptr && !entry->getAddr().isInvalid()) {
    const Address& a = entry->getAddr();
    AddrSpace* space = a.getSpace();
    if (space == arch->getStackSpace()) {
      // Stack-first, offset-only: durable across rename AND retype (retype changes
      // size, not the frame slot).
      intb off = sign_extend(static_cast<intb>(a.getOffset()),
                             space->getAddrSize() * 8 - 1);
      return "local:Stack[" + format_stack_offset(off) + "]";
    }
    // Offline-native (no program-DB ids exist here): storage-space snapshot.
    return "local:" + space->getName() + ":0x" + to_hex(a.getOffset()) + ":" +
           std::to_string(first_use);
  }
  if (entry != nullptr && entry->getHash() != 0)
    return "local:hash:0x" + to_hex(entry->getHash()) + ":" + std::to_string(first_use);
  return "local:anon:" + std::to_string(first_use);
}

DecompileLocalKind classify_local_kind(const Symbol* sym) {
  if (sym->getCategory() == Symbol::function_parameter)
    return DecompileLocalKind::kParam;
  const SymbolEntry* e = sym->getFirstWholeMap();
  if (e != nullptr && e->getAddr().isInvalid())
    return DecompileLocalKind::kTemp;  // dynamic/hash storage
  return DecompileLocalKind::kLocal;
}

std::string local_storage_string(Architecture* arch, const Symbol* sym) {
  const SymbolEntry* e = sym->getFirstWholeMap();
  if (e == nullptr) return "";
  const Address& a = e->getAddr();
  if (a.isInvalid()) return "hash";
  AddrSpace* space = a.getSpace();
  if (space == arch->getStackSpace()) {
    intb off = sign_extend(static_cast<intb>(a.getOffset()),
                           space->getAddrSize() * 8 - 1);
    return "Stack[" + format_stack_offset(off) + "]";
  }
  return space->getName() + (":0x" + to_hex(a.getOffset()));
}

// Enumerate the distinct local symbols of a decompiled function, pairing each
// live Symbol* with its record. MUST be called after perform() and BEFORE
// clearAnalysis(). Dedups by symbol and by canonical id (matching the live
// host's seen-set), skipping hidden-return symbols.
void collect_function_locals(
    Architecture* arch, Funcdata* fd,
    std::vector<std::pair<Symbol*, DecompileLocalRecord>>& out) {
  Scope* local = fd->getScopeLocal();
  if (local == nullptr) return;
  std::set<const Symbol*> seen_syms;
  std::set<std::string> seen_ids;

  auto handle = [&](Symbol* sym) {
    if (sym == nullptr) return;
    if (!seen_syms.insert(sym).second) return;
    if (sym->isHiddenReturn()) return;
    DecompileLocalRecord rec;
    rec.local_id = canonical_local_id(arch, fd, sym);
    if (rec.local_id.empty()) return;
    if (!seen_ids.insert(rec.local_id).second) return;
    rec.kind = classify_local_kind(sym);
    rec.name = sym->getName();
    if (rec.name.empty()) rec.name = rec.local_id;
    Datatype* dt = sym->getType();
    rec.data_type = (dt != nullptr) ? dt->getName() : "";
    rec.storage = local_storage_string(arch, sym);
    rec.ordinal = (sym->getCategory() == Symbol::function_parameter)
                      ? static_cast<int>(sym->getCategoryIndex())
                      : -1;
    out.emplace_back(sym, std::move(rec));
  };

  for (MapIterator it = local->begin(); it != local->end(); ++it)
    handle((*it)->getSymbol());
  for (auto dit = local->beginDynamic(); dit != local->endDynamic(); ++dit)
    handle((*dit).getSymbol());
}

struct AnalysisCleanup {
  Architecture* arch = nullptr;
  Funcdata* fd = nullptr;

  ~AnalysisCleanup() { clear(); }

  void clear() {
    if (arch != nullptr && fd != nullptr) {
      arch->clearAnalysis(fd);
      fd = nullptr;
#ifdef LIBGHIDRA_LOCAL_TEST_HOOKS
      ++testhooks::analysis_clear_count;
#endif
    }
  }
};

// Test-only: simulate a decompiler failure at the exact point a live Funcdata*
// exists and the AnalysisCleanup guard is armed. No-op in production builds.
inline void maybe_inject_post_decompile_fault() {
#ifdef LIBGHIDRA_LOCAL_TEST_HOOKS
  if (testhooks::post_decompile_fault != nullptr) testhooks::post_decompile_fault();
#endif
}

// Find/create the function at entry and run the decompiler actions. Returns
// false (with fd_out still set for cleanup) if decompilation did not complete.
bool decompile_perform(Architecture* arch, std::uint64_t entry, Funcdata*& fd_out) {
  fd_out = nullptr;
  AddrSpace* space = arch->getDefaultCodeSpace();
  Address addr(space, static_cast<uintb>(entry));
  Scope* global = arch->symboltab->getGlobalScope();
  Funcdata* fd = global->queryFunction(addr);
  if (fd == nullptr) {
    string name;
    arch->nameFunction(addr, name);
    fd = global->addFunction(addr, name)->getFunction();
  }
  fd_out = fd;
  Address baddr(space, 0);
  Address eaddr(space, space->getHighest());
  fd->followFlow(baddr, eaddr);
  arch->allacts.getCurrent()->reset(*fd);
  int4 res = arch->allacts.getCurrent()->perform(*fd);
  return res >= 0;
}

}  // namespace

ArchAdapter::DecompileWithLocalsResult ArchAdapter::decompileWithLocals(
    std::uint64_t func_entry) {
  DecompileWithLocalsResult result;
  if (!arch_) return result;

  try {
    AnalysisCleanup cleanup{arch_};
    if (!decompile_perform(arch_, func_entry, cleanup.fd)) {
      result.error = "Decompilation did not complete";
      return result;
    }
    maybe_inject_post_decompile_fault();
    Funcdata* fd = cleanup.fd;

    // Re-apply persisted local renames BEFORE reading — a name-lock alone does not
    // survive the clearUnlocked this fresh decompile just ran, so without this the
    // rename would vanish from the pseudocode + locals list.
    reapplyLocalRenames(func_entry, fd);

    // Pseudocode (same printer path as Decompiler::decompileAt). The RAII guard
    // resets the print stream off `oss` before it is destroyed, so arch_->print
    // is never left dangling.
    std::ostringstream oss;
    {
      ScopedPrintStream print_guard(arch_->print, oss);
      arch_->print->docFunction(fd);
    }
    result.pseudocode = oss.str();

    // Locals — enumerate BEFORE clearAnalysis destroys the scope's live state.
    std::vector<std::pair<Symbol*, DecompileLocalRecord>> pairs;
    collect_function_locals(arch_, fd, pairs);
    result.locals.reserve(pairs.size());
    for (auto& p : pairs) result.locals.push_back(std::move(p.second));

    result.ok = !result.pseudocode.empty();
    if (!result.ok) result.error = "Decompilation produced no output";
  } catch (...) {
    result.error = describe_current_exception();
    log_caught_exception("decompileWithLocals");
  }

  return result;
}

LocalMutationStatus ArchAdapter::applyLocalRename(std::uint64_t func_entry,
                                                  const std::string& local_id,
                                                  const std::string& new_name) {
  if (!arch_) return LocalMutationStatus::kDecompileFailed;
  LocalMutationStatus status = LocalMutationStatus::kNotFound;
  try {
    AnalysisCleanup cleanup{arch_};
    if (!decompile_perform(arch_, func_entry, cleanup.fd)) {
      return LocalMutationStatus::kDecompileFailed;
    }
    maybe_inject_post_decompile_fault();
    Funcdata* fd = cleanup.fd;
    std::vector<std::pair<Symbol*, DecompileLocalRecord>> pairs;
    collect_function_locals(arch_, fd, pairs);
    for (auto& p : pairs) {
      if (local_id_resolves(p.second, local_id)) {
        Symbol* sym = p.first;
        // Persist the rename: a name-lock alone does NOT survive clearUnlocked on
        // the next decompile (only type-locked symbols are held), so record it and
        // re-apply after every decompile (reapplyLocalRenames).
        local_renames_[{func_entry, local_id}] = new_name;
        sym->getScope()->renameSymbol(sym, new_name);
        sym->getScope()->setAttribute(sym, Varnode::namelock);
        status = LocalMutationStatus::kOk;
        break;
      }
    }
  } catch (...) {
    log_caught_exception("applyLocalRename");
    return LocalMutationStatus::kDecompileFailed;
  }
  return status;
}

LocalMutationStatus ArchAdapter::applyLocalRetype(std::uint64_t func_entry,
                                                  const std::string& local_id,
                                                  const std::string& new_type) {
  if (!arch_) return LocalMutationStatus::kDecompileFailed;
  LocalMutationStatus status = LocalMutationStatus::kNotFound;
  try {
    Datatype* dt = parse_c_type(arch_, new_type);
    if (dt == nullptr) return LocalMutationStatus::kInvalidType;

    AnalysisCleanup cleanup{arch_};
    if (!decompile_perform(arch_, func_entry, cleanup.fd)) {
      return LocalMutationStatus::kDecompileFailed;
    }
    maybe_inject_post_decompile_fault();
    Funcdata* fd = cleanup.fd;
    std::vector<std::pair<Symbol*, DecompileLocalRecord>> pairs;
    collect_function_locals(arch_, fd, pairs);
    for (auto& p : pairs) {
      if (local_id_resolves(p.second, local_id)) {
        Symbol* sym = p.first;
        sym->getScope()->retypeSymbol(sym, dt);
        sym->getScope()->setAttribute(sym, Varnode::typelock);
        status = LocalMutationStatus::kOk;
        break;
      }
    }
  } catch (...) {
    log_caught_exception("applyLocalRetype");
    return LocalMutationStatus::kDecompileFailed;
  }
  return status;
}

void ArchAdapter::reapplyLocalRenames(std::uint64_t func_entry, void* fd_ptr) {
  if (local_renames_.empty() || arch_ == nullptr || fd_ptr == nullptr) return;
  auto* fd = static_cast<Funcdata*>(fd_ptr);
  std::vector<std::pair<Symbol*, DecompileLocalRecord>> pairs;
  bool collected = false;
  for (const auto& kv : local_renames_) {
    if (kv.first.first != func_entry) continue;
    if (!collected) {
      collect_function_locals(arch_, fd, pairs);
      collected = true;
    }
    for (auto& p : pairs) {
      if (local_id_resolves(p.second, kv.first.second)) {
        try {
          p.first->getScope()->renameSymbol(p.first, kv.second);
          p.first->getScope()->setAttribute(p.first, Varnode::namelock);
        } catch (...) {
          // Name conflict / invalid — leave the auto name for this decompile.
        }
        break;
      }
    }
  }
}

bool ArchAdapter::deleteSymbol(std::uint64_t address) {
  if (!arch_) return false;

  try {
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(address));
    Scope* global = arch_->symboltab->getGlobalScope();
    SymbolEntry* entry = global->findAddr(addr, Address());
    if (!entry) return false;

    Symbol* sym = entry->getSymbol();
    if (!sym) return false;

    global->removeSymbol(sym);
    return true;
  } catch (...) {
    log_caught_exception("deleteSymbol");
    return false;
  }
}

std::vector<ArchAdapter::CommentEntry> ArchAdapter::getComments(
    std::uint64_t range_start, std::uint64_t range_end) {
  std::vector<CommentEntry> result;
  range_end = normalize_range_end(range_end);

  for (const auto& [key, text] : comments_) {
    std::uint64_t addr = key.first;
    if (addr < range_start || addr >= range_end) continue;
    result.push_back({addr, key.second, text});
  }

  return result;
}

void ArchAdapter::setComment(std::uint64_t address, int kind,
                             const std::string& text) {
  comments_[{address, kind}] = text;
}

bool ArchAdapter::deleteComment(std::uint64_t address, int kind) {
  return comments_.erase({address, kind}) > 0;
}

std::vector<ArchAdapter::DataItemEntry> ArchAdapter::listDataItems(
    std::uint64_t range_start, std::uint64_t range_end) {
  std::vector<DataItemEntry> result;
  if (!arch_) return result;
  range_end = normalize_range_end(range_end);

  try {
    Scope* global = arch_->symboltab->getGlobalScope();
    MapIterator it = global->begin();
    MapIterator end = global->end();

    while (it != end) {
      const SymbolEntry* entry = *it;
      const Symbol* sym = entry->getSymbol();

      // Skip function symbols
      if (dynamic_cast<const FunctionSymbol*>(sym) != nullptr) {
        ++it;
        continue;
      }

      std::uint64_t addr = entry->getAddr().getOffset();

      if (addr < range_start || addr >= range_end) {
        ++it;
        continue;
      }

      DataItemEntry item;
      item.address = addr;
      item.name = sym->getName();
      Datatype* dt = sym->getType();
      item.data_type = dt ? dt->getName() : "undefined";
      item.size = dt ? dt->getSize() : 0;
      result.push_back(std::move(item));

      ++it;
    }
  } catch (...) {
    log_caught_exception("listDataItems");
  }

  return result;
}

bool ArchAdapter::createTypeAlias(const std::string& alias_name,
                                  const std::string& target_name) {
  if (!arch_ || alias_name.empty() || target_name.empty()) return false;

  try {
    TypeFactory* tf = arch_->types;
    Datatype* target = tf->findByName(target_name);
    if (!target) return false;
    tf->getTypedef(target, alias_name, 0, 0);
    return true;
  } catch (...) {
    log_caught_exception("createTypeAlias");
    return false;
  }
}

bool ArchAdapter::deleteTypeAlias(const std::string& alias_name) {
  if (!arch_ || alias_name.empty()) return false;

  try {
    Datatype* dt = arch_->types->findByName(alias_name);
    if (!dt) return false;
    if (!dt->getTypedef()) return false;  // not a typedef
    arch_->types->destroyType(dt);
    return true;
  } catch (...) {
    log_caught_exception("deleteTypeAlias");
    return false;
  }
}

bool ArchAdapter::setTypeAliasTarget(const std::string& alias_name,
                                     const std::string& new_target_name) {
  if (!arch_ || alias_name.empty() || new_target_name.empty()) return false;

  try {
    TypeFactory* tf = arch_->types;
    Datatype* dt = tf->findByName(alias_name);
    if (!dt) return false;
    if (!dt->getTypedef()) return false;  // not a typedef

    Datatype* new_target = tf->findByName(new_target_name);
    if (!new_target) return false;

    // Destroy and recreate (no retarget API)
    tf->destroyType(dt);
    tf->getTypedef(new_target, alias_name, 0, 0);
    return true;
  } catch (...) {
    log_caught_exception("setTypeAliasTarget");
    return false;
  }
}

bool ArchAdapter::renameDataItem(std::uint64_t address,
                                 const std::string& new_name) {
  if (!arch_ || new_name.empty()) return false;

  try {
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(address));
    Scope* global = arch_->symboltab->getGlobalScope();
    SymbolEntry* entry = global->findAddr(addr, Address());
    if (!entry) return false;

    Symbol* sym = entry->getSymbol();
    if (!sym) return false;
    if (dynamic_cast<FunctionSymbol*>(sym) != nullptr) return false;

    global->renameSymbol(sym, new_name);
    global->setAttribute(sym, Varnode::namelock);
    return true;
  } catch (...) {
    log_caught_exception("renameDataItem");
    return false;
  }
}

bool ArchAdapter::deleteDataItem(std::uint64_t address) {
  if (!arch_) return false;

  try {
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(address));
    Scope* global = arch_->symboltab->getGlobalScope();
    SymbolEntry* entry = global->findAddr(addr, Address());
    if (!entry) return false;

    Symbol* sym = entry->getSymbol();
    if (!sym) return false;
    if (dynamic_cast<FunctionSymbol*>(sym) != nullptr) return false;

    global->removeSymbol(sym);
    return true;
  } catch (...) {
    log_caught_exception("deleteDataItem");
    return false;
  }
}

bool ArchAdapter::deleteType(const std::string& name) {
  if (!arch_ || name.empty()) return false;

  try {
    Datatype* dt = arch_->types->findByName(name);
    if (!dt) return false;
    arch_->types->destroyType(dt);
    return true;
  } catch (...) {
    log_caught_exception("deleteType");
    return false;
  }
}

bool ArchAdapter::renameType(const std::string& old_name,
                             const std::string& new_name) {
  if (!arch_ || old_name.empty() || new_name.empty()) return false;

  try {
    Datatype* dt = arch_->types->findByName(old_name);
    if (!dt) return false;
    arch_->types->setName(dt, new_name);
    return true;
  } catch (...) {
    log_caught_exception("renameType");
    return false;
  }
}

void ArchAdapter::setTypeMemberComment(const std::string& type_name,
                                       std::uint64_t ordinal,
                                       const std::string& comment) {
  type_member_comments_[{type_name, ordinal}] = comment;
}

void ArchAdapter::setTypeEnumMemberComment(const std::string& type_name,
                                           std::uint64_t ordinal,
                                           const std::string& comment) {
  type_enum_member_comments_[{type_name, ordinal}] = comment;
}

}  // namespace libghidra::client::detail
