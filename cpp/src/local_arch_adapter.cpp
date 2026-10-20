// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "local_arch_adapter.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <ostream>
#include <set>
#include <sstream>
#include <streambuf>
#include <utility>

#include "libdecomp.hh"
#include "libghidra/error_codes.hpp"
#include "ghidra_decompiler.h"
#include "project_types.h"
#include "host_print.h"
#include "symbol_entry.hpp"

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

// "List all" range convention, matching the live Java host: range_end is an
// INCLUSIVE upper bound (the host stops only once an address is past it -- the
// proto's convention; ghidrasql converts to its own exclusive model at its
// boundary), and range_end == 0 is the "all addresses" sentinel, normalized to
// the full 64-bit space. (0, 0) and (0, UINT64_MAX) both mean "everything".
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

// The host's type kind (RuntimeMappers.detectTypeKind): TYPEDEF, STRUCT, UNION,
// ENUM, POINTER, ARRAY, FUNCTION_DEF or BUILTIN. A typedef is a copy of its target
// in the decompiler, so it is told apart by getTypedef() first.
std::string type_kind(Datatype* dt) {
  if (dt->getTypedef() != nullptr) return "TYPEDEF";
  if (dt->isEnumType()) return "ENUM";
  switch (dt->getMetatype()) {
    case TYPE_STRUCT:
      return "STRUCT";
    case TYPE_UNION:
      return "UNION";
    case TYPE_PTR:
    case TYPE_PTRREL:
      return "POINTER";
    case TYPE_ARRAY:
      return "ARRAY";
    case TYPE_CODE:
      return dt->isCoreType() ? "BUILTIN" : "FUNCTION_DEF";
    case TYPE_PARTIALSTRUCT:
    case TYPE_PARTIALUNION:
    case TYPE_PARTIALENUM:
    case TYPE_SPACEBASE:
      return "OTHER";
    default:
      return "BUILTIN";
  }
}

// DataType.getLength(): a function definition (or a typedef of one) has none.
int type_length(Datatype* dt) {
  Datatype* base = dt;
  while (base->getTypedef() != nullptr) base = base->getTypedef();
  if (base->getMetatype() == TYPE_CODE && !base->isCoreType()) return -1;
  // An empty composite still reports one byte (Composite.getLength).
  if ((base->getMetatype() == TYPE_STRUCT || base->getMetatype() == TYPE_UNION) && dt->getSize() == 0)
    return 1;
  return dt->getSize();
}

}  // namespace

// -- ArchAdapter implementation ----------------------------------------------

ArchAdapter::ArchAdapter(void* arch_ptr, ghidra_standalone::Decompiler* project)
    : arch_(static_cast<Architecture*>(arch_ptr)),
      project_(project),
      type_categories_(project != nullptr ? &project->typeCategories() : nullptr) {}

namespace {

// A function's signature as the live host reports it (RuntimeMappers.
// toFunctionSignatureRecord over FunctionDB): data types by Ghidra path name,
// the prototype string of Function.getPrototypeString(false, false). A
// prototype that is not input-locked is a DEFAULT signature: Ghidra reports
// `undefined f()` with no parameters, whatever a decompile may have inferred.
FunctionSignatureRecord signatureRecord(Architecture* arch, Funcdata* fd,
                                        const ghidra_standalone::Decompiler* project,
                                        const std::map<std::uint64_t, std::string>* cats) {
  const FuncProto& proto = fd->getFuncProto();
  const int ptr = arch->types->getSizeOfPointer();
  FunctionSignatureRecord rec;
  rec.function_entry_address = fd->getAddress().getOffset();
  rec.function_name = fd->getName();
  rec.calling_convention = proto.getModelName();
  if (!proto.isInputLocked()) {
    if (project != nullptr) {
      const std::string saved = project->savedModelName(rec.function_entry_address);
      if (!saved.empty()) rec.calling_convention = saved;
    }
    rec.return_type = "/undefined";
    rec.prototype = "undefined " + rec.function_name + "()";
    return rec;
  }
  // The saved prototype, when there is one: a decompile rewrote the
  // Funcdata's copy (every size-locked "undefined" became undefined1).
  PrototypePieces pieces;
  bool output_locked = proto.isOutputLocked();
  const PrototypePieces* saved =
      project != nullptr ? project->savedPrototype(rec.function_entry_address, &output_locked)
                         : nullptr;
  if (saved != nullptr) {
    pieces = *saved;
  } else {
    proto.getPieces(pieces);
    pieces.innames.clear();
    for (int4 i = 0; i < proto.numParams(); ++i) pieces.innames.push_back(proto.getParam(i)->getName());
  }
  if (pieces.model != nullptr) rec.calling_convention = pieces.model->getName();
  rec.has_var_args = pieces.firstVarArgSlot >= 0;
  // An unlocked return in a saved signature is Ghidra's DEFAULT "undefined":
  // the host does not lock it either, and a decompile only infers it.
  std::string out_name = "undefined";
  rec.return_type = "/undefined";
  if (output_locked && pieces.outtype != nullptr) {
    Datatype* out = pieces.outtype;
    out_name = ghidra_standalone::ghidraTypeName(out, ptr);
    rec.return_type = ghidra_standalone::ghidraTypePath(out, ptr, cats);
  }
  std::string text = out_name + " " + rec.function_name + "(";
  const int4 count = static_cast<int4>(pieces.intypes.size());
  for (int4 i = 0; i < count; i++) {
    ParameterRecord prec;
    prec.ordinal = i;
    prec.name = i < static_cast<int4>(pieces.innames.size()) ? pieces.innames[i] : std::string();
    prec.data_type = ghidra_standalone::ghidraTypePath(pieces.intypes[i], ptr, cats);
    prec.formal_data_type = prec.data_type;
    if (i > 0) text += ", ";
    text += ghidra_standalone::ghidraTypeName(pieces.intypes[i], ptr) + " " + prec.name;
    rec.parameters.push_back(std::move(prec));
  }
  if (rec.has_var_args)
    text += count > 0 ? ", ..." : "...";
  else if (count == 0)
    text += "void";
  rec.prototype = text + ")";
  return rec;
}

}  // namespace

bool ArchAdapter::isProjectThunk(std::uint64_t entry) const {
  return project_ != nullptr && project_->projectThunks().count(entry) != 0;
}

bool ArchAdapter::isExternalStub(std::uint64_t address) const {
  return project_ != nullptr && project_->externalStubs().count(address) != 0;
}

bool ArchAdapter::fromProject() const {
  return project_ != nullptr && project_->isProjectLoaded();
}

std::uint64_t ArchAdapter::typeId(const Datatype* dt) const {
  return project_ != nullptr ? project_->ghidraTypeId(dt) : 0;
}

std::string ArchAdapter::typePath(const void* datatype) const {
  return ghidra_standalone::ghidraTypePath(
      const_cast<Datatype*>(static_cast<const Datatype*>(datatype)),
      arch_->types->getSizeOfPointer(), type_categories_);
}

namespace {

// The address holds bytes of the loaded image (LoadImage::loadFill succeeds).
bool address_loaded(Architecture* arch, std::uint64_t address) {
  try {
    uint1 byte = 0;
    arch->loader->loadFill(&byte, 1, Address(arch->getDefaultCodeSpace(), static_cast<uintb>(address)));
    return true;
  } catch (...) {
    return false;
  }
}

}  // namespace

std::optional<std::uint64_t> ArchAdapter::functionEntryFor(std::uint64_t address) {
  if (!arch_ || isExternalStub(address)) return std::nullopt;
  try {
    const Address addr(arch_->getDefaultCodeSpace(), static_cast<uintb>(address));
    if (arch_->symboltab->getGlobalScope()->queryFunction(addr) != nullptr) return address;
    SymbolEntry* entry = libghidra::detail::find_addr_any_scope(arch_, addr);
    if (entry != nullptr && dynamic_cast<const FunctionSymbol*>(entry->getSymbol()) != nullptr)
      return address;
  } catch (...) {
    log_caught_exception("functionEntryFor");
    return std::nullopt;
  }
  if (fromProject()) return project_->projectFunctionContaining(address);
  return std::nullopt;
}

bool ArchAdapter::functionStartsAt(std::uint64_t address) {
  if (!arch_ || isExternalStub(address)) return false;
  try {
    const Address addr(arch_->getDefaultCodeSpace(), static_cast<uintb>(address));
    if (arch_->symboltab->getGlobalScope()->queryFunction(addr) != nullptr) return true;
    SymbolEntry* entry = libghidra::detail::find_addr_any_scope(arch_, addr);
    return entry != nullptr && dynamic_cast<const FunctionSymbol*>(entry->getSymbol()) != nullptr;
  } catch (...) {
    log_caught_exception("functionStartsAt");
    return false;
  }
}

std::string ArchAdapter::defaultFunctionName(std::uint64_t address) {
  char buf[40];
  std::snprintf(buf, sizeof buf, "FUN_%08llx", static_cast<unsigned long long>(address));
  return buf;
}

std::optional<std::uint64_t> ArchAdapter::decompileEntryFor(std::uint64_t address) {
  if (auto entry = functionEntryFor(address)) return entry;
  if (!arch_ || fromProject() || isExternalStub(address)) return std::nullopt;
  return address_loaded(arch_, address) ? std::optional<std::uint64_t>(address) : std::nullopt;
}

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
      Funcdata* fd;
      std::string namespace_name;
    };
    std::vector<Fn> fns;
    libghidra::detail::for_each_namespace_scope(global, [&](Scope* scope) {
      for (MapIterator it = scope->begin(); it != scope->end(); ++it) {
        const SymbolEntry* entry = *it;
        const FunctionSymbol* fsym =
            dynamic_cast<const FunctionSymbol*>(entry->getSymbol());
        if (fsym == nullptr) continue;
        // Dynamic (hash-identified) storage has no address to list under; the
        // pre-split base class would have yielded an invalid Address here and
        // this loop would have recorded its offset as a real one.
        const auto* mapped = libghidra::detail::as_map_entry(entry);
        if (mapped == nullptr) continue;
        if (isExternalStub(mapped->getAddr().getOffset())) continue;
        int4 sz = fsym->getBytesConsumed();
        fns.push_back({mapped->getAddr().getOffset(), fsym->getName(),
                       sz > 0 ? static_cast<std::uint64_t>(sz) : 0,
                       const_cast<FunctionSymbol*>(fsym)->getFunction(),
                       libghidra::detail::namespace_path(scope)});
      }
    });
    // Namespaces are walked one after another; the size rule below needs the
    // functions in address order across all of them.
    std::sort(fns.begin(), fns.end(), [](const Fn& a, const Fn& b) { return a.addr < b.addr; });

    for (std::size_t i = 0; i < fns.size(); i++) {
      // Apply range filter; range_end is normalized so (0,0) == all.
      if (fns[i].addr < range_start || fns[i].addr > range_end) continue;

      FunctionRecord rec;
      rec.entry_address = fns[i].addr;
      rec.start_address = fns[i].addr;
      rec.name = fns[i].name;
      rec.is_thunk = isProjectThunk(fns[i].addr);
      rec.namespace_name = fns[i].namespace_name;
      if (fns[i].fd != nullptr) {
        // Function.getPrototypeString / getParameterCount, as the host reports.
        FunctionSignatureRecord sig = signatureRecord(arch_, fns[i].fd, project_, type_categories_);
        rec.prototype = std::move(sig.prototype);
        rec.parameter_count = static_cast<std::uint32_t>(sig.parameters.size());
      }
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

std::optional<FunctionRecord> ArchAdapter::getFunction(std::uint64_t requested) {
  const std::optional<std::uint64_t> resolved = functionEntryFor(requested);
  if (!resolved) return std::nullopt;
  const std::uint64_t address = *resolved;

  try {
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(address));
    Scope* global = arch_->symboltab->getGlobalScope();
    Funcdata* fd = global->queryFunction(addr);

    if (!fd) {
      // Check if there's a function symbol at this address
      SymbolEntry* entry = libghidra::detail::find_addr_any_scope(arch_, addr);
      if (!entry) return std::nullopt;
      const FunctionSymbol* fsym = dynamic_cast<const FunctionSymbol*>(entry->getSymbol());
      if (!fsym) return std::nullopt;

      FunctionRecord rec;
      rec.entry_address = address;
      rec.start_address = address;
      rec.name = fsym->getName();
      rec.namespace_name = libghidra::detail::namespace_path(fsym->getScope());
      rec.is_thunk = isProjectThunk(address);
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
    rec.is_thunk = isProjectThunk(rec.entry_address);
    rec.namespace_name = libghidra::detail::namespace_path(
        fd->getSymbol() != nullptr ? fd->getSymbol()->getScope() : nullptr);
    {
      FunctionSignatureRecord sig = signatureRecord(arch_, fd, project_, type_categories_);
      rec.prototype = std::move(sig.prototype);
      rec.parameter_count = static_cast<std::uint32_t>(sig.parameters.size());
    }
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

namespace {

// RuntimeMappers.toSymbolRecord: Symbol.getName(true) / getParentNamespace()
// .getName(true), and the SymbolType's own spelling ("Function", "Label").
SymbolRecord functionRecord(const Symbol* sym, std::uint64_t address, std::uint64_t id,
                            std::string source) {
  SymbolRecord rec;
  rec.symbol_id = id;
  rec.source = std::move(source);
  rec.address = address;
  rec.name = sym->getName();
  rec.namespace_name = libghidra::detail::namespace_path(sym->getScope());
  rec.full_name = sym->getScope()->getParent() == nullptr
                      ? sym->getName()
                      : rec.namespace_name + "::" + sym->getName();
  rec.is_primary = true;
  rec.type = "Function";
  return rec;
}

SymbolRecord labelRecord(const ghidra_standalone::LabelInfo& l) {
  SymbolRecord rec;
  rec.symbol_id = l.id;
  rec.address = l.address;
  rec.name = l.name;
  rec.namespace_name = l.namespace_path;
  rec.full_name = l.namespace_path == "Global" ? l.name : l.namespace_path + "::" + l.name;
  rec.is_primary = l.primary;
  rec.type = "Label";
  rec.source = l.source;
  return rec;
}

}  // namespace

std::vector<SymbolRecord> ArchAdapter::listSymbols(std::uint64_t range_start,
                                                   std::uint64_t range_end) {
  std::vector<SymbolRecord> result;
  if (!arch_) return result;
  range_end = normalize_range_end(range_end);

  try {
    libghidra::detail::for_each_namespace_scope(
        arch_->symboltab->getGlobalScope(), [&](Scope* scope) {
          for (MapIterator it = scope->begin(); it != scope->end(); ++it) {
            const SymbolEntry* entry = *it;
            const auto* fsym = dynamic_cast<const FunctionSymbol*>(entry->getSymbol());
            const auto* mapped = libghidra::detail::as_map_entry(entry);
            if (fsym == nullptr || mapped == nullptr) continue;
            const std::uint64_t addr = mapped->getAddr().getOffset();
            if (addr < range_start || addr > range_end || isExternalStub(addr)) continue;
            result.push_back(functionRecord(
                fsym, addr, project_ != nullptr ? project_->functionSymbolId(addr) : 0,
                project_ != nullptr ? project_->functionSymbolSource(addr) : std::string()));
          }
        });
    if (project_ != nullptr) {
      for (const auto& l : project_->labels(range_start, range_end)) result.push_back(labelRecord(l));
      for (auto& rec : result) rec.is_external_entry_point = project_->isExternalEntryPoint(rec.address);
    }
    // Address order, then symbol id order (the symbol table's address index).
    std::stable_sort(result.begin(), result.end(), [](const SymbolRecord& a, const SymbolRecord& b) {
      if (a.address != b.address) return a.address < b.address;
      return a.symbol_id < b.symbol_id;
    });
    // The imports, at their EXTERNAL-space offsets: that space follows the
    // program's memory in the symbol table's address order, as the host lists them.
    if (project_ != nullptr) {
      for (const auto& [l, is_function] : project_->externalSymbols(range_start, range_end)) {
        SymbolRecord rec = labelRecord(l);
        rec.type = is_function ? "Function" : "Label";
        rec.is_external = true;
        result.push_back(std::move(rec));
      }
    }
  } catch (...) {
    log_caught_exception("listSymbols");
  }

  return result;
}

std::optional<SymbolRecord> ArchAdapter::getSymbol(std::uint64_t address) {
  if (!arch_ || !isMapped(address)) return std::nullopt;
  // Symbol.isExternalEntryPoint: every symbol at an export or the entry.
  auto flagged = [&](SymbolRecord rec) {
    rec.is_external_entry_point = project_ != nullptr && project_->isExternalEntryPoint(address);
    return std::optional<SymbolRecord>(std::move(rec));
  };

  try {
    if (functionStartsAt(address)) {
      const Address addr(arch_->getDefaultCodeSpace(), static_cast<uintb>(address));
      if (Funcdata* fd = arch_->symboltab->getGlobalScope()->queryFunction(addr))
        return flagged(functionRecord(fd->getSymbol(), address,
                                      project_ != nullptr ? project_->functionSymbolId(address) : 0,
                                      project_ != nullptr ? project_->functionSymbolSource(address)
                                                          : std::string()));
      SymbolEntry* entry = libghidra::detail::find_addr_any_scope(arch_, addr);
      return flagged(functionRecord(entry->getSymbol(), address,
                                    project_ != nullptr ? project_->functionSymbolId(address) : 0,
                                    project_ != nullptr ? project_->functionSymbolSource(address)
                                                        : std::string()));
    }
    if (project_ == nullptr) return std::nullopt;
    if (auto label = project_->primaryLabel(address)) return flagged(labelRecord(*label));
    if (auto dynamic = project_->dynamicSymbol(address)) {
      SymbolRecord rec = labelRecord(*dynamic);
      rec.is_dynamic = true;
      return flagged(std::move(rec));
    }
    return std::nullopt;
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

    for (Datatype* dt : deporder) {
      // Substring filter
      if (!query.empty() && dt->getName().find(query) == std::string::npos)
        continue;

      TypeRecord rec;
      rec.type_id = typeId(dt);
      rec.name = dt->getName();
      rec.path_name = typePath(dt);
      rec.category_path = rec.path_name.substr(0, std::max<std::size_t>(1, rec.path_name.rfind('/')));
      rec.display_name = dt->getDisplayName();
      rec.kind = type_kind(dt);
      rec.length = type_length(dt);
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

    for (Datatype* dt : deporder) {
      TypeEnum* te = dynamic_cast<TypeEnum*>(dt);
      if (!te) continue;

      if (!query.empty() && te->getName().find(query) == std::string::npos)
        continue;

      TypeEnumRecord rec;
      rec.type_id = typeId(te);
      rec.path_name = typePath(te);
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
    Datatype* dt = findType(type_name);
    if (!dt) return result;
    TypeEnum* te = dynamic_cast<TypeEnum*>(dt);
    if (!te) return result;

    // Iterate enum name map via beginEnum/endEnum
    std::uint64_t ordinal = 0;
    for (auto eit = te->beginEnum(); eit != te->endEnum(); ++eit) {
      TypeEnumMemberRecord rec;
      rec.type_name = te->getName();
      rec.type_path_name = typePath(te);
      rec.ordinal = ordinal;
      rec.name = eit->second;
      rec.value = static_cast<std::int64_t>(eit->first);
      auto cit = member_comments_.find({te->getUnsizedId(), rec.name});
      if (cit != member_comments_.end()) rec.comment = cit->second;
      ordinal++;
      result.push_back(std::move(rec));
    }
  } catch (...) {
    log_caught_exception("listTypeEnumMembers");
  }

  return result;
}

namespace {

// Ghidra's name for an unnamed component (DataTypeComponent.getDefaultFieldName):
// field_0x<offset> in a structure, field<ordinal> in a union. The decompiler
// sees these names; the host lists such a member as field_<ordinal>.
std::string default_field_name(int offset) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "field_0x%x", offset);
  return buf;
}

std::string default_union_field_name(std::size_t ordinal) {
  return "field" + std::to_string(ordinal);
}

std::string listed_field_name(const std::string& name, const std::string& default_name,
                              std::uint64_t ordinal) {
  return name == default_name ? "field_" + std::to_string(ordinal) : name;
}

}  // namespace

std::vector<TypeMemberRecord> ArchAdapter::listTypeMembers(
    const std::string& type_name) {
  std::vector<TypeMemberRecord> result;
  if (!arch_) return result;

  try {
    Datatype* dt = findType(type_name);
    // Only a composite has members; a typedef of one is not a composite.
    if (!dt || dt->getTypedef() != nullptr) return result;
    const int ptr_size = arch_->types->getSizeOfPointer();
    if (auto* tu = dynamic_cast<TypeUnion*>(dt)) {
      const std::string parent_path = ghidra_standalone::ghidraTypePath(tu, ptr_size, type_categories_);
      const std::vector<std::string>& comments = unionComments(tu);
      for (int4 i = 0; i < tu->numDepend(); ++i) {
        const TypeField* f = tu->getField(i);
        TypeMemberRecord rec;
        rec.parent_type_id = typeId(tu);
        rec.parent_type_name = tu->getName();
        rec.parent_type_path_name = parent_path;
        rec.ordinal = static_cast<std::uint64_t>(i);
        rec.name = listed_field_name(f->name, default_union_field_name(static_cast<std::size_t>(i)),
                                     rec.ordinal);
        rec.member_type = ghidra_standalone::ghidraTypePath(f->type, ptr_size, type_categories_);
        rec.offset = 0;
        rec.size = static_cast<std::uint64_t>(f->type->getSize());
        rec.comment = comments[static_cast<std::size_t>(i)];
        result.push_back(std::move(rec));
      }
      return result;
    }
    TypeStruct* ts = dynamic_cast<TypeStruct*>(dt);
    if (!ts) return result;

    // The host reports DataTypeComponents in ordinal order: fields and
    // bitfields interleaved by position, types by path name, and a bitfield
    // as `<base>:<bits>` spanning the bytes its bits touch.
    const int ptr = arch_->types->getSizeOfPointer();
    struct Member {
      int offset;
      int order;  // bit position inside the offset, fields first
      TypeMemberRecord rec;
    };
    std::vector<Member> members;
    for (auto fit = ts->beginField(); fit != ts->endField(); ++fit) {
      TypeMemberRecord rec;
      rec.name = fit->name;
      rec.member_type = ghidra_standalone::ghidraTypePath(fit->type, ptr, type_categories_);
      rec.offset = fit->offset;
      rec.size = fit->type->getSize();
      members.push_back({fit->offset, -1, std::move(rec)});
    }
    for (int4 i = 0; i < ts->numBitFields(); ++i) {
      const TypeBitField& bf = ts->getBitField(i);
      TypeMemberRecord rec;
      rec.name = bf.name;
      rec.member_type = ghidra_standalone::ghidraTypePath(bf.type, ptr, type_categories_) + ":" +
                        std::to_string(bf.bits.numBits);
      rec.offset = bf.bits.byteOffset;
      rec.size = static_cast<std::uint64_t>(bf.bits.byteSize);
      members.push_back({bf.bits.byteOffset, bf.ident, std::move(rec)});
    }
    std::stable_sort(members.begin(), members.end(), [](const Member& a, const Member& b) {
      return a.offset != b.offset ? a.offset < b.offset : a.order < b.order;
    });
    const std::string parent_path =
        ghidra_standalone::ghidraTypePath(ts, ptr, type_categories_);
    // The host's component ordinals: without packing every undefined byte no
    // member covers is a component too (Composite.getDefinedComponents keeps
    // each defined one's real ordinal).
    const bool packed = project_ != nullptr && project_->isPackedType(ts->getUnsizedId());
    std::uint64_t ordinal = 0;
    int covered = 0;
    for (Member& m : members) {
      if (!packed && m.offset > covered) ordinal += static_cast<std::uint64_t>(m.offset - covered);
      TypeMemberRecord rec = std::move(m.rec);
      rec.parent_type_id = typeId(ts);
      rec.parent_type_name = ts->getName();
      rec.parent_type_path_name = parent_path;
      rec.ordinal = ordinal;
      auto cit = member_comments_.find({ts->getUnsizedId(), rec.name});
      if (cit != member_comments_.end()) rec.comment = cit->second;
      if (m.order < 0) rec.name = listed_field_name(rec.name, default_field_name(m.offset), ordinal);
      ordinal++;
      covered = std::max<int>(covered, m.offset + static_cast<int>(rec.size));
      result.push_back(std::move(rec));
    }
  } catch (...) {
    log_caught_exception("listTypeMembers");
  }

  return result;
}

std::optional<InstructionRecord> ArchAdapter::getInstruction(std::uint64_t address) {
  if (!arch_) return std::nullopt;
  // An opened project answers from its listing, as the host does
  // (Listing.getInstructionAt): no instruction starts inside another one or in
  // data, however the bytes there would decode.
  if (project_ != nullptr && !project_->projectInstructionAt(address)) return std::nullopt;

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
  if (range_start > range_end) return result;

  // Bound an unbounded (limit <= 0) sweep so a normalized "all" range cannot
  // walk the whole address space. getInstruction() already breaks at the first
  // gap; this cap is a hard backstop against a runaway linear disassembly.
  const int effective_limit = limit > 0 ? limit : kMaxUnboundedInstructions;

  try {
    std::uint64_t cur = range_start;
    int count = 0;

    while (cur <= range_end && count < effective_limit) {
      auto insn = getInstruction(cur);
      if (!insn || insn->length == 0) break;

      result.push_back(std::move(*insn));
      const std::uint64_t next = cur + result.back().length;
      if (next < cur) break;  // wrapped past the top of the address space
      cur = next;
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
bool decompile_perform(Architecture* arch, const ghidra_standalone::Decompiler* project,
                       std::uint64_t entry, Funcdata*& fd_out);
// The function at `entry`, created when the program may have one there: for an
// opened project only one of its own function entries; for a bare binary any
// address with loaded bytes (decompiling defines the function). nullptr
// otherwise, so no read leaves a phantom function behind.
Funcdata* find_or_create_function(Architecture* arch,
                                  const ghidra_standalone::Decompiler* project,
                                  std::uint64_t entry);
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
    if (!decompile_perform(arch_, project_, func_entry, fd)) {
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

Datatype* ArchAdapter::findType(const std::string& path_or_name) const {
  if (!arch_ || path_or_name.empty()) return nullptr;
  // A Ghidra path ("/category/Name"; a caller may have dropped the leading
  // '/') names the type and its category; a bare name only the type.
  std::string path = path_or_name;
  if (path[0] != '/' && path.find('/') != std::string::npos) path = "/" + path;
  if (path[0] != '/') return arch_->types->findByName(path);
  const std::string leaf = path.substr(path.rfind('/') + 1);
  Datatype* dt = arch_->types->findByName(leaf);
  if (dt != nullptr && typePath(dt) == path) return dt;
  // Another type of that name in another category (a typedef and the function
  // definition it points at), or a pointer or array the program holds
  // ("/cat/T *", "/cat/T[4]"), which has no name of its own in the decompiler:
  // found by its path.
  const bool derived = path.back() == '*' || path.back() == ']';
  if (dt == nullptr && !derived) return nullptr;
  vector<Datatype*> all;
  arch_->types->dependentOrder(all);
  for (Datatype* t : all)
    if ((derived ? t->getName().empty() : t->getName() == leaf) && typePath(t) == path) return t;
  return nullptr;
}

std::optional<TypeRecord> ArchAdapter::getType(const std::string& path) {
  if (!arch_ || path.empty()) return std::nullopt;

  try {
    Datatype* dt = findType(path);
    if (!dt) return std::nullopt;

    TypeRecord rec;
    rec.type_id = typeId(dt);
    rec.name = dt->getName();
    rec.path_name = typePath(dt);
    rec.category_path = rec.path_name.substr(0, std::max<std::size_t>(1, rec.path_name.rfind('/')));
    rec.display_name = dt->getDisplayName();
    rec.kind = type_kind(dt);
    rec.length = type_length(dt);
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

    for (Datatype* dt : deporder) {
      Datatype* target = dt->getTypedef();
      if (!target) continue;

      if (!query.empty() && dt->getName().find(query) == std::string::npos)
        continue;

      TypeAliasRecord rec;
      rec.type_id = typeId(dt);
      rec.path_name = typePath(dt);
      rec.name = dt->getName();
      rec.target_type = typePath(target);  // a Ghidra path, as the host spells it
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

    for (Datatype* dt : deporder) {
      if (dt->getMetatype() != TYPE_UNION) continue;

      if (!query.empty() && dt->getName().find(query) == std::string::npos)
        continue;

      TypeUnionRecord rec;
      rec.type_id = typeId(dt);
      rec.path_name = typePath(dt);
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
  if (!arch_ || project_ == nullptr) return result;
  for (const auto& b : project_->memoryBlocks()) {
    MemoryBlockRecord rec;
    rec.name = b.name;
    rec.start_address = b.start;
    rec.end_address = b.end;
    rec.size = b.end - b.start + 1;
    rec.is_read = b.read;
    rec.is_write = b.write;
    rec.is_execute = b.execute;
    rec.is_volatile = b.is_volatile;
    rec.is_initialized = b.initialized;
    rec.source_name = b.source_name;
    rec.comment = b.comment;
    result.push_back(std::move(rec));
  }
  return result;
}

std::optional<FunctionSignatureRecord> ArchAdapter::getFunctionSignature(
    std::uint64_t address) {
  const std::optional<std::uint64_t> entry = functionEntryFor(address);
  if (!entry) return std::nullopt;

  try {
    const Address addr(arch_->getDefaultCodeSpace(), static_cast<uintb>(*entry));
    Funcdata* fd = arch_->symboltab->getGlobalScope()->queryFunction(addr);
    if (fd == nullptr) {
      SymbolEntry* sym = libghidra::detail::find_addr_any_scope(arch_, addr);
      auto* fsym = sym != nullptr ? dynamic_cast<FunctionSymbol*>(sym->getSymbol()) : nullptr;
      if (fsym != nullptr) fd = fsym->getFunction();
    }
    if (!fd) return std::nullopt;
    return signatureRecord(arch_, fd, project_, type_categories_);
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

    // Find the function, or create it where the program may have one.
    Funcdata* fd = find_or_create_function(arch_, project_, func_entry);
    if (fd == nullptr) return result;

    if (project_ != nullptr) project_->prepareFunction(fd);

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
  if (const auto* mapped = libghidra::detail::as_map_entry(entry)) {
    const Address& a = mapped->getAddr();
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
  if (const auto* dynamic = libghidra::detail::as_dynamic_entry(entry))
    return "local:hash:0x" + to_hex(dynamic->getHash()) + ":" + std::to_string(first_use);
  return "local:anon:" + std::to_string(first_use);
}

DecompileLocalKind classify_local_kind(const Symbol* sym) {
  if (sym->getCategory() == Symbol::function_parameter)
    return DecompileLocalKind::kParam;
  const SymbolEntry* e = sym->getFirstWholeMap();
  if (e != nullptr && !libghidra::detail::as_map_entry(e))
    return DecompileLocalKind::kTemp;  // dynamic/hash storage
  return DecompileLocalKind::kLocal;
}

std::string local_storage_string(Architecture* arch, const Symbol* sym) {
  const SymbolEntry* e = sym->getFirstWholeMap();
  if (e == nullptr) return "";
  const auto* mapped = libghidra::detail::as_map_entry(e);
  if (!mapped) return "hash";
  const Address& a = mapped->getAddr();
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
    // DataType.getName(), as the host reports a local: `char * *`, `int[4]`.
    Datatype* dt = sym->getType();
    rec.data_type = (dt != nullptr)
                        ? ghidra_standalone::ghidraTypeName(dt, arch->types->getSizeOfPointer())
                        : "";
    rec.storage = local_storage_string(arch, sym);
    rec.ordinal = (sym->getCategory() == Symbol::function_parameter)
                      ? static_cast<int>(sym->getCategoryIndex())
                      : -1;
    out.emplace_back(sym, std::move(rec));
  };

  for (MapIterator it = local->begin(); it != local->end(); ++it)
    handle((*it)->getSymbol());
  // beginDynamic() iterates list<DynamicEntry *>, so *dit is a pointer.
  for (auto dit = local->beginDynamic(); dit != local->endDynamic(); ++dit)
    handle((*dit)->getSymbol());
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
Funcdata* find_or_create_function(Architecture* arch,
                                  const ghidra_standalone::Decompiler* project,
                                  std::uint64_t entry) {
  const Address addr(arch->getDefaultCodeSpace(), static_cast<uintb>(entry));
  Scope* global = arch->symboltab->getGlobalScope();
  if (Funcdata* fd = global->queryFunction(addr)) return fd;
  if (project != nullptr && project->isProjectLoaded()) {
    if (project->projectFunctionContaining(entry) != std::optional<uint64_t>(entry)) return nullptr;
  } else if (!address_loaded(arch, entry)) {
    return nullptr;
  }
  string name;
  arch->nameFunction(addr, name);
  return global->addFunction(addr, name)->getFunction();
}

bool decompile_perform(Architecture* arch, const ghidra_standalone::Decompiler* project,
                       std::uint64_t entry, Funcdata*& fd_out) {
  fd_out = nullptr;
  AddrSpace* space = arch->getDefaultCodeSpace();
  Funcdata* fd = find_or_create_function(arch, project, entry);
  if (fd == nullptr) return false;
  fd_out = fd;
  // Start from the saved prototype and locals, as the host does every time.
  if (project != nullptr) project->prepareFunction(fd);
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
    if (!decompile_perform(arch_, project_, func_entry, cleanup.fd)) {
      result.error = "Decompilation did not complete";
      return result;
    }
    maybe_inject_post_decompile_fault();
    Funcdata* fd = cleanup.fd;

    // Re-apply persisted local renames BEFORE reading — a name-lock alone does not
    // survive the clearUnlocked this fresh decompile just ran, so without this the
    // rename would vanish from the pseudocode + locals list.
    reapplyLocalRenames(func_entry, fd);

    // Pseudocode, printed as the host prints it (same path as
    // Decompiler::decompileAt): markup lines with sanitized symbol tokens.
    result.pseudocode = ghidra_standalone::printFunctionLikeHost(arch_, fd);

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
    if (!decompile_perform(arch_, project_, func_entry, cleanup.fd)) {
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
    // A Ghidra path (as the host takes it) or C type text.
    Datatype* dt = resolveArgumentType(new_type);
    if (dt == nullptr) return LocalMutationStatus::kInvalidType;

    AnalysisCleanup cleanup{arch_};
    if (!decompile_perform(arch_, project_, func_entry, cleanup.fd)) {
      return LocalMutationStatus::kDecompileFailed;
    }
    maybe_inject_post_decompile_fault();
    Funcdata* fd = cleanup.fd;
    std::vector<std::pair<Symbol*, DecompileLocalRecord>> pairs;
    collect_function_locals(arch_, fd, pairs);
    for (auto& p : pairs) {
      if (local_id_resolves(p.second, local_id)) {
        Symbol* sym = p.first;
        try {
          sym->getScope()->retypeSymbol(sym, dt);
        } catch (const RecovError&) {
          // ScopeInternal::retypeSymbol refuses a size change unless the
          // symbol is exactly one address-tied storage entry. That is a
          // property of the local, not a decompile failure: say so.
          return LocalMutationStatus::kRetypeRejected;
        }
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

std::vector<ArchAdapter::DataItemEntry> ArchAdapter::listDataItems(
    std::uint64_t range_start, std::uint64_t range_end) {
  std::vector<DataItemEntry> result;
  if (!arch_ || project_ == nullptr) return result;
  range_end = normalize_range_end(range_end);
  for (const auto& d : project_->dataItems(range_start, range_end)) {
    DataItemEntry item;
    item.address = d.address;
    item.name = d.name;
    item.data_type =
        d.type ? ghidra_standalone::ghidraTypeName(d.type, arch_->types->getSizeOfPointer())
               : "undefined";
    item.size = d.length > 0 ? static_cast<std::uint64_t>(d.length) : 1;
    result.push_back(std::move(item));
  }
  return result;
}

// -- Memory map -----------------------------------------------------------------

namespace {

// Whether the program has a memory map at all; without one (a loader that
// gives none) every loadable byte counts as mapped.
bool has_memory_map(const ghidra_standalone::Decompiler* project) {
  return project != nullptr && !project->memoryBlocks().empty();
}

// The loader holds `length` bytes at `address` (through the write overlay).
bool loader_holds(Architecture* arch, std::uint64_t address, std::uint64_t length) {
  if (length == 0) return true;
  try {
    std::vector<uint1> buf(static_cast<std::size_t>(length));
    arch->loader->loadFill(buf.data(), static_cast<int4>(length),
                           Address(arch->getDefaultCodeSpace(), static_cast<uintb>(address)));
    return true;
  } catch (...) {
    return false;
  }
}

}  // namespace

const ghidra_standalone::MemoryBlockInfo* ArchAdapter::blockAt(std::uint64_t address) const {
  return project_ != nullptr ? project_->blockAt(address) : nullptr;
}

bool ArchAdapter::isMapped(std::uint64_t address) {
  if (!arch_) return false;
  if (has_memory_map(project_)) return project_->blockAt(address) != nullptr;
  return address_loaded(arch_, address);
}

RangeStatus ArchAdapter::checkWritable(std::uint64_t address, std::uint64_t length) {
  if (!isMapped(address)) return RangeStatus::kUnmapped;
  if (length == 0) return RangeStatus::kOk;
  const std::uint64_t last = address + length - 1;
  if (last < address) return RangeStatus::kPastMapped;
  if (has_memory_map(project_)) {
    for (std::uint64_t cur = address;;) {
      const auto* b = project_->blockAt(cur);
      if (b == nullptr) return RangeStatus::kPastMapped;
      if (!b->initialized) return RangeStatus::kUninitialized;
      if (b->end >= last) break;
      cur = b->end + 1;
    }
  }
  return loader_holds(arch_, address, length) ? RangeStatus::kOk : RangeStatus::kUnavailable;
}

std::vector<std::uint8_t> ArchAdapter::readBytes(std::uint64_t address, std::uint32_t length,
                                                 RangeStatus& status) {
  status = RangeStatus::kOk;
  std::vector<std::uint8_t> result;
  if (!arch_ || length == 0) return result;
  std::uint64_t count = length;
  if (has_memory_map(project_)) {
    // Memory.getBytes on the host: the mapped, initialized bytes from the
    // address on, stopping where the memory map does.
    const auto* b = project_->blockAt(address);
    if (b == nullptr) {
      status = RangeStatus::kUnmapped;
      return result;
    }
    if (!b->initialized) {
      status = RangeStatus::kUninitialized;
      return result;
    }
    std::uint64_t end = b->end;
    while (end - address + 1 < count && end != UINT64_MAX) {
      const auto* next = project_->blockAt(end + 1);
      if (next == nullptr || !next->initialized) break;
      end = next->end;
    }
    count = std::min<std::uint64_t>(count, end - address + 1);
  }
  try {
    result.resize(static_cast<std::size_t>(count));
    arch_->loader->loadFill(result.data(), static_cast<int4>(count),
                            Address(arch_->getDefaultCodeSpace(), static_cast<uintb>(address)));
  } catch (...) {
    result.clear();
    status = has_memory_map(project_) ? RangeStatus::kUnavailable : RangeStatus::kUnmapped;
  }
  return result;
}

std::optional<std::uint64_t> ArchAdapter::insideInstruction(std::uint64_t address) {
  if (!arch_ || project_ == nullptr) return std::nullopt;
  const std::optional<std::uint64_t> start = project_->projectInstructionAtOrBefore(address);
  if (!start || *start == address) return std::nullopt;
  const std::optional<InstructionRecord> insn = getInstruction(*start);
  if (insn && address < *start + insn->length) return start;
  return std::nullopt;
}

bool ArchAdapter::codeOverlaps(std::uint64_t address, std::uint64_t length) {
  if (!arch_) return false;
  const std::uint64_t last = length > 0 && address + length - 1 >= address ? address + length - 1 : address;
  const bool has_listing =
      project_ != nullptr && project_->projectInstructionAtOrBefore(UINT64_MAX).has_value();
  if (has_listing) {
    const std::optional<std::uint64_t> start = project_->projectInstructionAtOrBefore(last);
    if (!start) return false;
    if (*start >= address) return true;
    const std::optional<InstructionRecord> insn = getInstruction(*start);
    return insn && *start + insn->length > address;
  }
  // A bare binary has no listing: its code is the functions it defines.
  return !listFunctions(address, last).empty();
}

// -- Types ------------------------------------------------------------------------

namespace {

namespace codes = libghidra::client::error_codes;

// "a struct", "an enum", ... for messages naming a type of the wrong kind.
std::string describe_kind(Datatype* dt) {
  if (dt->getTypedef() != nullptr) return "a typedef";
  if (dt->isEnumType()) return "an enum";
  switch (dt->getMetatype()) {
    case TYPE_STRUCT: return "a struct";
    case TYPE_UNION: return "a union";
    case TYPE_PTR:
    case TYPE_PTRREL: return "a pointer";
    case TYPE_ARRAY: return "an array";
    case TYPE_CODE: return "a function definition";
    default: return "a built-in type";
  }
}

std::string bare_name(const std::string& path) {
  const std::size_t slash = path.rfind('/');
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

}  // namespace

bool ArchAdapter::typeNameTaken(const std::string& name) const {
  return arch_ != nullptr && !name.empty() && arch_->types->findByName(bare_name(name)) != nullptr;
}

Datatype* ArchAdapter::resolveArgumentType(const std::string& text) const {
  if (!arch_ || text.empty()) return nullptr;
  if (Datatype* dt = findType(text)) return dt;
  // A Ghidra path or name with pointer stars after it ("/cat/T *").
  std::string base = text;
  int pointers = 0;
  for (;;) {
    while (!base.empty() && base.back() == ' ') base.pop_back();
    if (base.empty() || base.back() != '*') break;
    base.pop_back();
    ++pointers;
  }
  if (pointers > 0) {
    if (Datatype* dt = findType(base)) {
      for (int i = 0; i < pointers; ++i)
        dt = arch_->types->getTypePointer(arch_->types->getSizeOfPointer(), dt,
                                          arch_->getDefaultDataSpace()->getWordSize());
      return dt;
    }
  }
  return parse_c_type(arch_, text);
}

std::string ArchAdapter::typeUser(Datatype* dt) const {
  std::string user;
  auto note = [&](const std::string& who) {
    if (user.empty()) user = who;
  };
  vector<Datatype*> all;
  arch_->types->dependentOrder(all);
  for (Datatype* t : all) {
    if (t == dt) continue;
    if (t->getTypedef() == dt) note("typedef " + typePath(t));
    for (int4 i = 0; i < t->numDepend(); ++i) {
      if (t->getDepend(i) != dt) continue;
      const bool pointer = t->getMetatype() == TYPE_PTR || t->getMetatype() == TYPE_PTRREL;
      note((pointer ? "pointer type " : "type ") + typePath(t));
      break;
    }
  }
  libghidra::detail::for_each_namespace_scope(
      arch_->symboltab->getGlobalScope(), [&](Scope* scope) {
        for (MapIterator it = scope->begin(); it != scope->end(); ++it) {
          Symbol* sym = (*it)->getSymbol();
          if (sym->getType() == dt) note("symbol " + sym->getName());
          if (auto* fsym = dynamic_cast<FunctionSymbol*>(sym)) {
            Funcdata* fd = fsym->getFunction();
            const FuncProto& proto = fd->getFuncProto();
            bool uses = proto.getOutputType() == dt;
            for (int4 i = 0; i < proto.numParams() && !uses; ++i)
              uses = proto.getParam(i)->getType() == dt;
            if (uses) note("the prototype of " + fd->getName());
          }
        }
      });
  if (project_ != nullptr && project_->savedStateUses(dt)) note("a saved prototype or local");
  return user;
}

WriteStatus ArchAdapter::enumTarget(const std::string& path, Datatype*& out) const {
  out = findType(path);
  if (out == nullptr) return WriteStatus::Fail(codes::kNotFound, "no type '" + path + "'");
  if (dynamic_cast<TypeEnum*>(out) == nullptr || out->getTypedef() != nullptr)
    return WriteStatus::Fail(codes::kInvalidArgument,
                             "type '" + path + "' is " + describe_kind(out) + ", not an enum");
  return WriteStatus::Ok();
}

WriteStatus ArchAdapter::deleteType(const std::string& path) {
  Datatype* dt = findType(path);
  if (dt == nullptr) return WriteStatus::Fail(codes::kNotFound, "no type '" + path + "'");
  if (dt->isCoreType())
    return WriteStatus::Fail(codes::kInvalidArgument, "'" + path + "' is a built-in type");
  const std::string user = typeUser(dt);
  if (!user.empty())
    return WriteStatus::Fail(codes::kNotSupported,
                             "type '" + path + "' is used by " + user +
                                 "; the offline engine cannot delete or replace a type in use");
  try {
    const std::uint64_t id = dt->getUnsizedId();
    for (auto it = member_comments_.begin(); it != member_comments_.end();)
      it = it->first.first == id ? member_comments_.erase(it) : std::next(it);
    arch_->types->destroyType(dt);
    return WriteStatus::Ok();
  } catch (...) {
    return WriteStatus::Fail(codes::kInternalError, describe_current_exception());
  }
}

WriteStatus ArchAdapter::deleteTypeEnum(const std::string& path) {
  Datatype* dt = nullptr;
  WriteStatus target = enumTarget(path, dt);
  if (!target.ok()) return target;
  return deleteType(path);
}

void ArchAdapter::refreshEnumCopies(Datatype* te) {
  auto* source = dynamic_cast<TypeEnum*>(te);
  if (source == nullptr) return;
  const std::map<uintb, std::string> values(source->beginEnum(), source->endEnum());
  vector<Datatype*> all;
  arch_->types->dependentOrder(all);
  for (Datatype* t : all) {
    auto* copy = dynamic_cast<TypeEnum*>(t);
    if (copy != nullptr && copy != source && t->getTypedef() == te)
      arch_->types->setEnumValues(values, copy);
  }
}

WriteStatus ArchAdapter::renameType(const std::string& path, const std::string& new_name) {
  Datatype* dt = findType(path);
  if (dt == nullptr) return WriteStatus::Fail(codes::kNotFound, "no type '" + path + "'");
  if (dt->isCoreType())
    return WriteStatus::Fail(codes::kInvalidArgument, "'" + path + "' is a built-in type");
  Datatype* taken = arch_->types->findByName(new_name);
  if (taken != nullptr && taken != dt)
    return WriteStatus::Fail(codes::kDuplicateName,
                             "a type named '" + new_name + "' already exists: " + typePath(taken));
  try {
    // setName keeps the id, so the type keeps its category.
    arch_->types->setName(dt, new_name);
    return WriteStatus::Ok();
  } catch (...) {
    return WriteStatus::Fail(codes::kInternalError, describe_current_exception());
  }
}

WriteStatus ArchAdapter::createTypeAlias(const std::string& alias_name,
                                         const std::string& target_name) {
  if (typeNameTaken(alias_name)) {
    return WriteStatus::Fail(codes::kDuplicateName,
                             "a type named '" + alias_name + "' already exists: " +
                                 typePath(arch_->types->findByName(bare_name(alias_name))));
  }
  Datatype* target = resolveArgumentType(target_name);
  if (target == nullptr)
    return WriteStatus::Fail(codes::kUnknownType, "unknown data type '" + target_name + "'");
  try {
    arch_->types->getTypedef(target, alias_name, 0, 0);
    return WriteStatus::Ok();
  } catch (...) {
    return WriteStatus::Fail(codes::kInternalError, describe_current_exception());
  }
}

WriteStatus ArchAdapter::deleteTypeAlias(const std::string& path) {
  Datatype* dt = findType(path);
  if (dt == nullptr) return WriteStatus::Fail(codes::kNotFound, "no type '" + path + "'");
  if (dt->getTypedef() == nullptr)
    return WriteStatus::Fail(codes::kInvalidArgument,
                             "type '" + path + "' is " + describe_kind(dt) + ", not a typedef");
  const std::string user = typeUser(dt);
  if (!user.empty())
    return WriteStatus::Fail(codes::kNotSupported,
                             "type '" + path + "' is used by " + user +
                                 "; the offline engine cannot delete or replace a type in use");
  try {
    arch_->types->destroyType(dt);
    return WriteStatus::Ok();
  } catch (...) {
    return WriteStatus::Fail(codes::kInternalError, describe_current_exception());
  }
}

WriteStatus ArchAdapter::setTypeAliasTarget(const std::string& path,
                                            const std::string& new_target_name) {
  Datatype* dt = findType(path);
  if (dt == nullptr) return WriteStatus::Fail(codes::kNotFound, "no type '" + path + "'");
  if (dt->getTypedef() == nullptr)
    return WriteStatus::Fail(codes::kInvalidArgument,
                             "type '" + path + "' is " + describe_kind(dt) + ", not a typedef");
  Datatype* target = resolveArgumentType(new_target_name);
  if (target == nullptr)
    return WriteStatus::Fail(codes::kUnknownType, "unknown data type '" + new_target_name + "'");
  if (target == dt->getTypedef()) return WriteStatus::Ok();  // already its target
  const std::string user = typeUser(dt);
  if (!user.empty())
    return WriteStatus::Fail(codes::kNotSupported,
                             "type '" + path + "' is used by " + user +
                                 "; the offline engine cannot delete or replace a type in use");
  try {
    // A typedef is a copy of its target, so it is rebuilt -- under the same
    // name and id, which keeps its category.
    const std::string name = dt->getName();
    const uint8 id = dt->getId();
    const uint4 format = dt->getDisplayFormat();
    arch_->types->destroyType(dt);
    arch_->types->getTypedef(target, name, id, format);
    return WriteStatus::Ok();
  } catch (...) {
    return WriteStatus::Fail(codes::kInternalError, describe_current_exception());
  }
}

namespace {

using EnumMap = std::map<uintb, std::string>;

EnumMap enum_map(TypeEnum* te) { return EnumMap(te->beginEnum(), te->endEnum()); }

// The (value, name) at `ordinal` in value order, the order listTypeEnumMembers reports.
EnumMap::iterator enum_member(EnumMap& members, std::uint64_t ordinal) {
  auto it = members.begin();
  for (std::uint64_t i = 0; i < ordinal && it != members.end(); ++i) ++it;
  return it;
}

bool enum_name_used(const EnumMap& members, const std::string& name, uintb except) {
  for (const auto& [value, member] : members)
    if (member == name && value != except) return true;
  return false;
}

std::string ordinal_message(const std::string& path, std::uint64_t ordinal, std::size_t count) {
  return "type '" + path + "' has no member " + std::to_string(ordinal) + " (it has " +
         std::to_string(count) + ")";
}

}  // namespace

WriteStatus ArchAdapter::addTypeEnumMember(const std::string& path, const std::string& name,
                                           std::int64_t value) {
  Datatype* dt = nullptr;
  WriteStatus target = enumTarget(path, dt);
  if (!target.ok()) return target;
  auto* te = static_cast<TypeEnum*>(dt);
  EnumMap members = enum_map(te);
  const uintb key = static_cast<uintb>(value);
  if (enum_name_used(members, name, key) || (members.count(key) && members[key] == name))
    return WriteStatus::Fail(codes::kDuplicateName,
                             "enum '" + path + "' already has a member named '" + name + "'");
  if (members.count(key))
    return WriteStatus::Fail(codes::kNotSupported,
                             "enum '" + path + "' already names value " + std::to_string(value) +
                                 " ('" + members[key] + "'); the offline engine holds one name per value");
  members[key] = name;
  arch_->types->setEnumValues(members, te);
  refreshEnumCopies(te);
  return WriteStatus::Ok();
}

WriteStatus ArchAdapter::deleteTypeEnumMember(const std::string& path, std::uint64_t ordinal) {
  Datatype* dt = nullptr;
  WriteStatus target = enumTarget(path, dt);
  if (!target.ok()) return target;
  auto* te = static_cast<TypeEnum*>(dt);
  EnumMap members = enum_map(te);
  auto it = enum_member(members, ordinal);
  if (it == members.end())
    return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, members.size()));
  member_comments_.erase({te->getUnsizedId(), it->second});
  members.erase(it);
  arch_->types->setEnumValues(members, te);
  refreshEnumCopies(te);
  return WriteStatus::Ok();
}

WriteStatus ArchAdapter::renameTypeEnumMember(const std::string& path, std::uint64_t ordinal,
                                              const std::string& new_name) {
  Datatype* dt = nullptr;
  WriteStatus target = enumTarget(path, dt);
  if (!target.ok()) return target;
  auto* te = static_cast<TypeEnum*>(dt);
  EnumMap members = enum_map(te);
  auto it = enum_member(members, ordinal);
  if (it == members.end())
    return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, members.size()));
  if (enum_name_used(members, new_name, it->first))
    return WriteStatus::Fail(codes::kDuplicateName,
                             "enum '" + path + "' already has a member named '" + new_name + "'");
  auto comment = member_comments_.find({te->getUnsizedId(), it->second});
  if (comment != member_comments_.end()) {
    std::string text = std::move(comment->second);
    member_comments_.erase(comment);
    member_comments_[{te->getUnsizedId(), new_name}] = std::move(text);
  }
  it->second = new_name;
  arch_->types->setEnumValues(members, te);
  refreshEnumCopies(te);
  return WriteStatus::Ok();
}

WriteStatus ArchAdapter::setTypeEnumMemberValue(const std::string& path, std::uint64_t ordinal,
                                                std::int64_t value) {
  Datatype* dt = nullptr;
  WriteStatus target = enumTarget(path, dt);
  if (!target.ok()) return target;
  auto* te = static_cast<TypeEnum*>(dt);
  EnumMap members = enum_map(te);
  auto it = enum_member(members, ordinal);
  if (it == members.end())
    return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, members.size()));
  const uintb key = static_cast<uintb>(value);
  if (key == it->first) return WriteStatus::Ok();  // already that value
  if (members.count(key))
    return WriteStatus::Fail(codes::kNotSupported,
                             "enum '" + path + "' already names value " + std::to_string(value) +
                                 " ('" + members[key] + "'); the offline engine holds one name per value");
  const std::string name = it->second;
  members.erase(it);
  members[key] = name;
  arch_->types->setEnumValues(members, te);
  refreshEnumCopies(te);
  return WriteStatus::Ok();
}

WriteStatus ArchAdapter::setTypeEnumMemberComment(const std::string& path, std::uint64_t ordinal,
                                                  const std::string& comment) {
  Datatype* dt = nullptr;
  WriteStatus target = enumTarget(path, dt);
  if (!target.ok()) return target;
  auto* te = static_cast<TypeEnum*>(dt);
  EnumMap members = enum_map(te);
  auto it = enum_member(members, ordinal);
  if (it == members.end())
    return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, members.size()));
  member_comments_[{te->getUnsizedId(), it->second}] = comment;
  return WriteStatus::Ok();
}

namespace {

int round_up(int value, int align) { return align <= 1 ? value : (value + align - 1) / align * align; }

// A struct's fields, in offset order, as TypeStruct holds them.
std::vector<TypeField> struct_fields(TypeStruct* ts) {
  return std::vector<TypeField>(ts->beginField(), ts->endField());
}

// A union's fields, in ordinal order.
std::vector<TypeField> union_fields(TypeUnion* tu) {
  std::vector<TypeField> out;
  for (int4 i = 0; i < tu->numDepend(); ++i) out.push_back(*tu->getField(i));
  return out;
}

bool field_name_used(const std::vector<TypeField>& fields, const std::string& name,
                     std::size_t except) {
  for (std::size_t i = 0; i < fields.size(); ++i)
    if (i != except && fields[i].name == name) return true;
  return false;
}

// One component of the host's view of a structure: a field, or (without
// packing) an undefined byte no field covers.
struct Component {
  int offset;
  int length;
  std::ptrdiff_t field;  // index into the fields, -1 for an undefined byte
};

std::vector<Component> components(TypeStruct* ts, const std::vector<TypeField>& fields, bool packed) {
  std::vector<Component> out;
  int covered = 0;
  for (std::size_t i = 0; i < fields.size(); ++i) {
    for (int b = covered; !packed && b < fields[i].offset; ++b) out.push_back({b, 1, -1});
    out.push_back({fields[i].offset, fields[i].type->getSize(), static_cast<std::ptrdiff_t>(i)});
    covered = std::max(covered, fields[i].offset + fields[i].type->getSize());
  }
  for (int b = covered; !packed && b < ts->getSize(); ++b) out.push_back({b, 1, -1});
  return out;
}

}  // namespace

// -- Composite layout -------------------------------------------------------------
//
// The host's DataTypeManager keeps every composite consistent with what it
// holds: when a type changes size, each structure, union and array holding it
// by value is laid out again (StructureDB/UnionDB/ArrayDB.dataTypeSizeChanged).
// An edit is planned first -- the edited composite's new fields, then every
// holder's -- and applied only when the whole plan is possible, each type in
// place (TypeFactory::redefineStruct / redefineUnion / resizeArray), so every
// pointer, prototype and symbol that refers to one stays valid.

int ArchAdapter::packingOf(const Datatype* dt) const {
  return project_ != nullptr ? project_->packing(dt->getUnsizedId()) : -1;
}

namespace {

// Every typedef copy of `dt`, transitively (a typedef of a composite or array
// is a copy of it in the decompiler).
std::vector<Datatype*> copies_of(const std::vector<Datatype*>& all, Datatype* dt) {
  std::vector<Datatype*> out;
  std::set<Datatype*> seen{dt};
  for (std::size_t i = 0; i <= out.size(); ++i) {
    Datatype* base = i == 0 ? dt : out[i - 1];
    for (Datatype* t : all)
      if (t->getTypedef() == base && seen.insert(t).second) out.push_back(t);
  }
  return out;
}

}  // namespace

ArchAdapter::Layout ArchAdapter::layoutOf(Datatype* dt, const LayoutPlan& plan) const {
  auto it = plan.layouts.find(dt);
  if (it != plan.layouts.end()) return it->second;
  Layout l;
  l.size = dt->getSize();
  l.align = dt->getAlignment();
  if (dt->getMetatype() == TYPE_STRUCT) l.fields = struct_fields(static_cast<TypeStruct*>(dt));
  else if (dt->getMetatype() == TYPE_UNION) l.fields = union_fields(static_cast<TypeUnion*>(dt));
  return l;
}

void ArchAdapter::layOut(Datatype* dt, Layout& l, const LayoutPlan& plan) const {
  const int pack = packingOf(dt);
  auto size_of = [&](Datatype* t) { return layoutOf(t, plan).size; };
  auto align_of = [&](Datatype* t) {
    int a = std::max(1, layoutOf(t, plan).align);
    return pack > 0 ? std::min(a, pack) : a;
  };
  if (dt->getMetatype() == TYPE_UNION) {
    // UnionDB: as long as its longest member; packed, rounded to its alignment.
    int size = 0, align = 1;
    for (std::size_t i = 0; i < l.fields.size(); ++i) {
      // An unnamed member is named by its ordinal, which an edit may move.
      if (l.fields[i].name == default_union_field_name(static_cast<std::size_t>(l.fields[i].ident)))
        l.fields[i].name = default_union_field_name(i);
      l.fields[i].offset = 0;
      l.fields[i].ident = static_cast<int4>(i);
      size = std::max(size, size_of(l.fields[i].type));
      align = std::max(align, align_of(l.fields[i].type));
    }
    l.size = pack >= 0 ? round_up(size, align) : size;
    l.align = pack >= 0 ? align : 1;
    return;
  }
  for (std::size_t i = 0; i < l.fields.size(); ++i) l.fields[i].ident = static_cast<int4>(i);
  if (pack < 0) {
    // Without packing the offsets stand and the structure is byte aligned.
    l.align = 1;
    return;
  }
  int offset = 0, align = 1;
  for (TypeField& f : l.fields) {
    const int a = align_of(f.type);
    offset = round_up(offset, a);
    if (f.name == default_field_name(f.offset)) f.name = default_field_name(offset);
    f.offset = offset;
    offset += size_of(f.type);
    align = std::max(align, a);
  }
  l.size = round_up(offset, align);
  l.align = align;
}

WriteStatus ArchAdapter::planLayout(Datatype* target, Layout layout, LayoutPlan& plan) const {
  vector<Datatype*> all;
  arch_->types->dependentOrder(all);
  auto record = [&](Datatype* dt, const Layout& l) {
    plan.layouts[dt] = l;
    plan.order.erase(std::remove(plan.order.begin(), plan.order.end(), dt), plan.order.end());
    plan.order.push_back(dt);  // after everything it holds
  };
  record(target, layout);
  std::vector<Datatype*> work{target};
  for (std::size_t w = 0; w < work.size(); ++w) {
    Datatype* changed = work[w];
    const Layout now = plan.layouts.at(changed);
    if (now.size == changed->getSize() && now.align == changed->getAlignment()) continue;
    const int old_size = changed->getSize();
    std::set<Datatype*> held{changed};
    for (Datatype* copy : copies_of(all, changed)) held.insert(copy);
    for (Datatype* h : all) {
      if (h->getTypedef() != nullptr || held.count(h) != 0) continue;  // copies follow their base
      if (h->getMetatype() == TYPE_ARRAY) {
        auto* array = static_cast<TypeArray*>(h);
        if (held.count(array->getBase()) == 0) continue;
        Layout l;
        l.align = std::max(1, now.align);
        l.size = array->numElements() * round_up(now.size, l.align);
        record(h, l);
        work.push_back(h);
        continue;
      }
      const type_metatype meta = h->getMetatype();
      if (meta != TYPE_STRUCT && meta != TYPE_UNION) continue;
      Layout l = layoutOf(h, plan);
      bool holds = false;
      for (const TypeField& f : l.fields) holds = holds || held.count(f.type) != 0;
      if (!holds) continue;
      if (meta == TYPE_STRUCT && static_cast<TypeStruct*>(h)->numBitFields() > 0)
        return WriteStatus::Fail(codes::kNotSupported,
                                 "type '" + typePath(h) + "' holds '" + typePath(changed) +
                                     "' by value and has bitfields; the offline engine cannot "
                                     "lay it out again");
      if (meta == TYPE_STRUCT && packingOf(h) < 0) {
        // StructureDB.dataTypeSizeChanged without packing: a component that
        // shrinks leaves undefined bytes; one that grows takes the undefined
        // bytes after it, and the last one grows the structure.
        for (std::size_t i = 0; i < l.fields.size(); ++i) {
          if (held.count(l.fields[i].type) == 0 || now.size <= old_size) continue;
          const int end = l.fields[i].offset + now.size;
          if (i + 1 == l.fields.size()) {
            l.size = std::max(l.size, end);
          } else if (end > l.fields[i + 1].offset) {
            // The host truncates the component here (its length stays below
            // its type's), which the decompiler's types cannot represent.
            return WriteStatus::Fail(
                codes::kNotSupported,
                "'" + typePath(changed) + "' would grow to " + std::to_string(now.size) +
                    " bytes inside '" + typePath(h) + "' at offset " +
                    std::to_string(l.fields[i].offset) + ", where only " +
                    std::to_string(l.fields[i + 1].offset - l.fields[i].offset) +
                    " are free; the offline engine cannot hold a truncated member");
          }
        }
      }
      layOut(h, l, plan);
      record(h, l);
      work.push_back(h);
    }
  }
  return WriteStatus::Ok();
}

void ArchAdapter::applyLayout(const LayoutPlan& plan) {
  bool resized = false;
  vector<Datatype*> all;
  arch_->types->dependentOrder(all);
  for (Datatype* dt : plan.order) {
    const Layout& l = plan.layouts.at(dt);
    resized = resized || l.size != dt->getSize();
    // The factory updates a type's direct typedef copies with it; a typedef
    // of a typedef is a copy too, updated the same way.
    std::vector<Datatype*> targets{dt};
    for (Datatype* copy : copies_of(all, dt))
      if (copy->getTypedef() != dt) targets.push_back(copy);
    for (Datatype* t : targets) {
      switch (t->getMetatype()) {
        case TYPE_ARRAY:
          arch_->types->resizeArray(static_cast<TypeArray*>(t));
          break;
        case TYPE_UNION:
          arch_->types->redefineUnion(static_cast<TypeUnion*>(t), l.fields, l.size, l.align);
          break;
        case TYPE_STRUCT: {
          auto* ts = static_cast<TypeStruct*>(t);
          std::vector<TypeBitField> bits;
          for (int4 i = 0; i < ts->numBitFields(); ++i) bits.push_back(ts->getBitField(i));
          arch_->types->redefineStruct(ts, l.fields, bits, l.size, l.align);
          break;
        }
        default:
          break;
      }
    }
  }
  if (resized && project_ != nullptr) project_->refreshDataSizes();
}

WriteStatus ArchAdapter::relayout(Datatype* target, Layout layout) {
  layOut(target, layout, LayoutPlan());
  LayoutPlan plan;
  WriteStatus planned = planLayout(target, std::move(layout), plan);
  if (!planned.ok()) return planned;
  try {
    applyLayout(plan);
    return WriteStatus::Ok();
  } catch (...) {
    return WriteStatus::Fail(codes::kInternalError, describe_current_exception());
  }
}

WriteStatus ArchAdapter::compositeTarget(const std::string& path, Datatype*& out) const {
  out = findType(path);
  if (out == nullptr) return WriteStatus::Fail(codes::kNotFound, "no type '" + path + "'");
  const type_metatype meta = out->getMetatype();
  if ((meta != TYPE_STRUCT && meta != TYPE_UNION) || out->getTypedef() != nullptr)
    return WriteStatus::Fail(codes::kInvalidArgument, "type '" + path + "' is " +
                                                          describe_kind(out) +
                                                          ", not a struct or union");
  if (meta == TYPE_STRUCT && static_cast<TypeStruct*>(out)->numBitFields() > 0)
    return WriteStatus::Fail(codes::kNotSupported,
                             "the members of '" + path +
                                 "' cannot be edited offline: it has bitfields");
  return WriteStatus::Ok();
}

std::vector<std::string>& ArchAdapter::unionComments(TypeUnion* tu) {
  std::vector<std::string>& c = union_comments_[tu->getUnsizedId()];
  c.resize(static_cast<std::size_t>(tu->numDepend()));
  return c;
}

WriteStatus ArchAdapter::addTypeMember(const std::string& path, const std::string& name,
                                       const std::string& member_type) {
  Datatype* dt = nullptr;
  WriteStatus target = compositeTarget(path, dt);
  if (!target.ok()) return target;
  Datatype* type = resolveArgumentType(member_type);
  if (type == nullptr)
    return WriteStatus::Fail(codes::kUnknownType, "unknown data type '" + member_type + "'");
  if (type->getSize() <= 0 || type->getMetatype() == TYPE_VOID)
    return WriteStatus::Fail(codes::kInvalidArgument,
                             "'" + member_type + "' has no size and cannot be a member");
  Layout l = layoutOf(dt, LayoutPlan());
  if (dt->getMetatype() == TYPE_UNION) {
    // Union.insert at the end; a union may repeat a member name.
    l.fields.push_back(TypeField(static_cast<int4>(l.fields.size()), 0, name, type));
    std::vector<std::string> comments = unionComments(static_cast<TypeUnion*>(dt));
    WriteStatus done = relayout(dt, std::move(l));
    if (done.ok()) {
      comments.push_back("");
      union_comments_[dt->getUnsizedId()] = std::move(comments);
    }
    return done;
  }
  if (field_name_used(l.fields, name, l.fields.size()))
    return WriteStatus::Fail(codes::kDuplicateName,
                             "type '" + path + "' already has a member named '" + name + "'");
  // Appended after the struct's last byte, as the host inserts at the end.
  l.fields.push_back(TypeField(0, dt->getSize(), name, type));
  l.size = dt->getSize() + type->getSize();
  return relayout(dt, std::move(l));
}

WriteStatus ArchAdapter::deleteTypeMember(const std::string& path, std::uint64_t ordinal) {
  Datatype* dt = nullptr;
  WriteStatus target = compositeTarget(path, dt);
  if (!target.ok()) return target;
  Layout l = layoutOf(dt, LayoutPlan());
  if (dt->getMetatype() == TYPE_UNION) {
    if (ordinal >= l.fields.size())
      return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, l.fields.size()));
    std::vector<std::string> comments = unionComments(static_cast<TypeUnion*>(dt));
    l.fields.erase(l.fields.begin() + static_cast<std::ptrdiff_t>(ordinal));
    WriteStatus done = relayout(dt, std::move(l));
    if (done.ok()) {
      comments.erase(comments.begin() + static_cast<std::ptrdiff_t>(ordinal));
      union_comments_[dt->getUnsizedId()] = std::move(comments);
    }
    return done;
  }
  auto* ts = static_cast<TypeStruct*>(dt);
  const std::vector<Component> parts = components(ts, l.fields, packingOf(ts) >= 0);
  if (ordinal >= parts.size())
    return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, parts.size()));
  const Component c = parts[ordinal];
  std::string removed;
  if (c.field >= 0) {
    removed = l.fields[static_cast<std::size_t>(c.field)].name;
    l.fields.erase(l.fields.begin() + c.field);
  }
  // The components after it move down by its length (Structure.delete).
  for (TypeField& f : l.fields) {
    if (f.offset <= c.offset) continue;
    const bool unnamed = f.name == default_field_name(f.offset);
    f.offset -= c.length;
    if (unnamed) f.name = default_field_name(f.offset);  // an unnamed member's name follows it
  }
  l.size = std::max(0, ts->getSize() - c.length);
  WriteStatus done = relayout(dt, std::move(l));
  if (done.ok() && !removed.empty()) member_comments_.erase({ts->getUnsizedId(), removed});
  return done;
}

WriteStatus ArchAdapter::renameTypeMember(const std::string& path, std::uint64_t ordinal,
                                          const std::string& new_name) {
  Datatype* dt = nullptr;
  WriteStatus target = compositeTarget(path, dt);
  if (!target.ok()) return target;
  Layout l = layoutOf(dt, LayoutPlan());
  if (dt->getMetatype() == TYPE_UNION) {
    if (ordinal >= l.fields.size())
      return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, l.fields.size()));
    l.fields[static_cast<std::size_t>(ordinal)].name = new_name;
    return relayout(dt, std::move(l));
  }
  auto* ts = static_cast<TypeStruct*>(dt);
  const std::vector<Component> parts = components(ts, l.fields, packingOf(ts) >= 0);
  if (ordinal >= parts.size())
    return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, parts.size()));
  const Component c = parts[ordinal];
  if (field_name_used(l.fields, new_name,
                      c.field >= 0 ? static_cast<std::size_t>(c.field) : l.fields.size()))
    return WriteStatus::Fail(codes::kDuplicateName,
                             "type '" + path + "' already has a member named '" + new_name + "'");
  std::string old_name;
  if (c.field < 0) {
    // Naming an undefined byte makes it a member of its own.
    l.fields.push_back(TypeField(0, c.offset, new_name, arch_->types->getBase(1, TYPE_UNKNOWN)));
    std::stable_sort(l.fields.begin(), l.fields.end(),
                     [](const TypeField& a, const TypeField& b) { return a.offset < b.offset; });
  } else {
    TypeField& f = l.fields[static_cast<std::size_t>(c.field)];
    old_name = f.name;
    f.name = new_name;
  }
  WriteStatus done = relayout(dt, std::move(l));
  if (done.ok() && !old_name.empty()) {
    auto comment = member_comments_.find({ts->getUnsizedId(), old_name});
    if (comment != member_comments_.end()) {
      std::string text = std::move(comment->second);
      member_comments_.erase(comment);
      member_comments_[{ts->getUnsizedId(), new_name}] = std::move(text);
    }
  }
  return done;
}

WriteStatus ArchAdapter::setTypeMemberType(const std::string& path, std::uint64_t ordinal,
                                           const std::string& member_type) {
  Datatype* dt = nullptr;
  WriteStatus target = compositeTarget(path, dt);
  if (!target.ok()) return target;
  Layout l = layoutOf(dt, LayoutPlan());
  const bool is_union = dt->getMetatype() == TYPE_UNION;
  std::vector<Component> parts;
  if (!is_union) parts = components(static_cast<TypeStruct*>(dt), l.fields, packingOf(dt) >= 0);
  const std::size_t count = is_union ? l.fields.size() : parts.size();
  if (ordinal >= count)
    return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, count));
  Datatype* type = resolveArgumentType(member_type);
  if (type == nullptr)
    return WriteStatus::Fail(codes::kUnknownType, "unknown data type '" + member_type + "'");
  if (type->getSize() <= 0 || type->getMetatype() == TYPE_VOID)
    return WriteStatus::Fail(codes::kInvalidArgument,
                             "'" + member_type + "' has no size and cannot be a member");
  if (is_union) {
    TypeField& f = l.fields[static_cast<std::size_t>(ordinal)];
    if (f.type == type) return WriteStatus::Ok();
    f.type = type;  // delete and insert in its place, keeping its name and comment
    return relayout(dt, std::move(l));
  }
  const Component c = parts[ordinal];
  if (c.field >= 0 && l.fields[static_cast<std::size_t>(c.field)].type == type) return WriteStatus::Ok();
  if (packingOf(dt) < 0) {
    // Structure.replace without packing: the offsets stand. A longer type takes
    // the undefined bytes after the component; the last component may grow the
    // structure; anything else is refused.
    const int needed = type->getSize() - c.length;
    if (needed > 0) {
      int next = dt->getSize();
      bool last = true;
      for (const TypeField& f : l.fields)
        if (f.offset > c.offset) {
          next = f.offset;
          last = false;
          break;
        }
      const int free = next - (c.offset + c.length);
      if (free < needed) {
        if (!last) {
          char where[32];
          std::snprintf(where, sizeof where, "0x%x", c.offset);
          return WriteStatus::Fail(
              codes::kInvalidArgument,
              "Not enough undefined bytes to fit " + typePath(type) + " in structure " +
                  typePath(dt) + " at offset " + where + ". It needs " +
                  std::to_string(needed - free) + " more byte(s) to be able to fit.");
        }
        l.size = c.offset + type->getSize();
      }
    }
  }
  if (c.field >= 0) {
    l.fields[static_cast<std::size_t>(c.field)].type = type;
  } else {
    l.fields.push_back(TypeField(0, c.offset, default_field_name(c.offset), type));
    std::stable_sort(l.fields.begin(), l.fields.end(),
                     [](const TypeField& a, const TypeField& b) { return a.offset < b.offset; });
  }
  return relayout(dt, std::move(l));
}

WriteStatus ArchAdapter::setTypeMemberComment(const std::string& path, std::uint64_t ordinal,
                                              const std::string& comment) {
  Datatype* dt = nullptr;
  WriteStatus target = compositeTarget(path, dt);
  if (!target.ok()) return target;
  Layout l = layoutOf(dt, LayoutPlan());
  if (dt->getMetatype() == TYPE_UNION) {
    if (ordinal >= l.fields.size())
      return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, l.fields.size()));
    unionComments(static_cast<TypeUnion*>(dt))[static_cast<std::size_t>(ordinal)] = comment;
    return WriteStatus::Ok();
  }
  auto* ts = static_cast<TypeStruct*>(dt);
  const std::vector<Component> parts = components(ts, l.fields, packingOf(ts) >= 0);
  if (ordinal >= parts.size())
    return WriteStatus::Fail(codes::kNotFound, ordinal_message(path, ordinal, parts.size()));
  const Component c = parts[ordinal];
  if (c.field < 0) {
    // A comment on an undefined byte makes it a member of its own.
    l.fields.push_back(TypeField(0, c.offset, default_field_name(c.offset),
                                 arch_->types->getBase(1, TYPE_UNKNOWN)));
    std::stable_sort(l.fields.begin(), l.fields.end(),
                     [](const TypeField& a, const TypeField& b) { return a.offset < b.offset; });
    WriteStatus done = relayout(dt, std::move(l));
    if (done.ok()) member_comments_[{ts->getUnsizedId(), default_field_name(c.offset)}] = comment;
    return done;
  }
  member_comments_[{ts->getUnsizedId(), l.fields[static_cast<std::size_t>(c.field)].name}] = comment;
  return WriteStatus::Ok();
}

WriteStatus ArchAdapter::parseDeclarations(const std::string& text, std::vector<std::string>& created) {
  if (!arch_ || project_ == nullptr) return WriteStatus::Fail(codes::kNotLoaded, "no program");
  auto replace = [this](Datatype* existing, Datatype* parsed, const std::vector<TypeField>& fields,
                        std::string& error) {
    Layout l;
    l.fields = fields;
    l.size = parsed->getSize();
    l.align = parsed->getAlignment();
    WriteStatus done = relayout(existing, std::move(l));
    if (!done.ok()) error = done.message;
    return done.ok();
  };
  if (project_->parseDeclarations(text, created, replace)) return WriteStatus::Ok();
  return WriteStatus::Fail(project_->getErrorKind() == ghidra_standalone::EngineError::kParse
                               ? codes::kParseError
                               : codes::kInternalError,
                           project_->getError());
}

WriteStatus ArchAdapter::applyDataType(std::uint64_t address, const std::string& type_text) {
  if (!isMapped(address)) {
    char buf[64];
    std::snprintf(buf, sizeof buf, "no memory block contains 0x%llx",
                  static_cast<unsigned long long>(address));
    return WriteStatus::Fail(codes::kUnmappedAddress, buf);
  }
  Datatype* type = resolveArgumentType(type_text);
  if (type == nullptr)
    return WriteStatus::Fail(codes::kUnknownType, "unknown data type '" + type_text + "'");
  const std::uint64_t length = std::max<std::int64_t>(1, type->getSize());
  char where[64];
  std::snprintf(where, sizeof where, "0x%llx", static_cast<unsigned long long>(address));
  // Applying data over code is refused, not a silent clear of the code.
  if (codeOverlaps(address, length))
    return WriteStatus::Fail(codes::kInvalidArgument,
                             std::string("instructions occupy ") + where +
                                 "; clear the code before applying a data type");
  const RangeStatus range = checkWritable(address, length);
  if (range == RangeStatus::kPastMapped)
    return WriteStatus::Fail(codes::kInvalidArgument,
                             "'" + type_text + "' (" + std::to_string(length) + " bytes) at " +
                                 where + " runs past mapped memory");
  try {
    // Existing data takes the new type and keeps its name; new data is named
    // by the primary label there, or Ghidra's dynamic name.
    if (project_ == nullptr || !project_->defineData(address, type))
      return WriteStatus::Fail(codes::kInternalError,
                               project_ != nullptr ? project_->getError() : "no program");
    return WriteStatus::Ok();
  } catch (...) {
    return WriteStatus::Fail(codes::kInternalError, describe_current_exception());
  }
}

}  // namespace libghidra::client::detail
