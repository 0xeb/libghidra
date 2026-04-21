// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "local_arch_adapter.hpp"

#include <cstdio>
#include <sstream>

#include "libdecomp.hh"

using namespace ghidra;

namespace libghidra::client::detail {

// -- AssemblyEmit helper for disassembly -------------------------------------

namespace {

void log_caught_exception(const char* context) {
  try {
    throw;
  } catch (const std::exception& e) {
    fprintf(stderr, "[libghidra] %s: %s\n", context, e.what());
  } catch (const char* msg) {
    fprintf(stderr, "[libghidra] %s: %s\n", context, msg);
  } catch (...) {
    fprintf(stderr, "[libghidra] %s: unknown exception\n", context);
  }
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

  try {
    Scope* global = arch_->symboltab->getGlobalScope();
    MapIterator it = global->begin();
    MapIterator end = global->end();

    while (it != end) {
      const SymbolEntry* entry = *it;
      const Symbol* sym = entry->getSymbol();
      const FunctionSymbol* fsym = dynamic_cast<const FunctionSymbol*>(sym);
      if (fsym != nullptr) {
        std::uint64_t addr = entry->getAddr().getOffset();

        // Apply range filter (0,0 means all)
        if (range_start != range_end) {
          if (addr < range_start || addr >= range_end) {
            ++it;
            continue;
          }
        }

        FunctionRecord rec;
        rec.entry_address = addr;
        rec.start_address = addr;
        rec.name = fsym->getName();
        int4 sz = fsym->getBytesConsumed();
        rec.size = (sz > 0) ? static_cast<std::uint64_t>(sz) : 0;
        rec.end_address = rec.start_address + rec.size;
        result.push_back(std::move(rec));
      }
      ++it;
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
      rec.end_address = rec.start_address + rec.size;
      return rec;
    }

    FunctionRecord rec;
    rec.entry_address = fd->getAddress().getOffset();
    rec.start_address = rec.entry_address;
    rec.name = fd->getName();
    rec.size = fd->getSize();
    rec.end_address = rec.start_address + rec.size;
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

  try {
    Scope* global = arch_->symboltab->getGlobalScope();
    MapIterator it = global->begin();
    MapIterator end = global->end();
    std::uint64_t id_counter = 0;

    while (it != end) {
      const SymbolEntry* entry = *it;
      const Symbol* sym = entry->getSymbol();
      std::uint64_t addr = entry->getAddr().getOffset();

      if (range_start != range_end) {
        if (addr < range_start || addr >= range_end) {
          ++it;
          continue;
        }
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
  if (!arch_ || range_start >= range_end) return result;

  try {
    std::uint64_t cur = range_start;
    int count = 0;

    while (cur < range_end && (limit <= 0 || count < limit)) {
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

std::vector<XrefRecord> ArchAdapter::listXrefsForFunction(
    std::uint64_t func_entry) {
  std::vector<XrefRecord> result;
  if (!arch_) return result;

  try {
    AddrSpace* space = arch_->getDefaultCodeSpace();
    Address addr(space, static_cast<uintb>(func_entry));
    Scope* global = arch_->symboltab->getGlobalScope();
    Funcdata* fd = global->queryFunction(addr);
    if (!fd) return result;

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
  } catch (...) {
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
      rec.end_address = stop.isInvalid() ? rec.start_address : (stop.getOffset() + 1);
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

  for (const auto& [key, text] : comments_) {
    std::uint64_t addr = key.first;
    if (range_start != range_end) {
      if (addr < range_start || addr >= range_end) continue;
    }
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

      if (range_start != range_end) {
        if (addr < range_start || addr >= range_end) {
          ++it;
          continue;
        }
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
