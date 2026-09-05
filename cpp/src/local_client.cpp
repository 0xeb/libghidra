// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "libghidra/local.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "decompiler_pool.hpp"
#include "ghidra_decompiler.h"
#include "local_arch_adapter.hpp"

namespace libghidra::client {

using Status = libghidra::client::Status;

namespace {
template <typename Container>
Container paginate(const Container& all, int limit, int offset) {
  int n = static_cast<int>(all.size());
  int start = std::min(offset, n);
  int end = (limit > 0) ? std::min(start + limit, n) : n;
  return Container(all.begin() + start, all.begin() + end);
}

std::string to_hex_string(std::uint64_t v) {
  char buf[19];
  std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(v));
  return buf;
}
}  // namespace

// -- LocalClient implementation -----------------------------------------------

class LocalClient final : public IClient {
 public:
  explicit LocalClient(LocalClientOptions opts)
      : opts_(std::move(opts)),
        pool_(std::make_unique<detail::DecompilerPool>(
            std::max(opts_.pool_size, 1), opts_.ghidra_root)) {}

  ~LocalClient() override = default;

  // -- IHealthClient ----------------------------------------------------------

  StatusOr<HealthStatus> GetStatus() override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    HealthStatus hs;
    hs.ok = (pool_ != nullptr);
    hs.service_name = "local-decompiler";
    hs.service_version = "1.0.0";
    hs.host_mode = "local";
    hs.modification_number = revision_;
    return StatusOr<HealthStatus>::FromValue(std::move(hs));
  }

  StatusOr<std::vector<Capability>> GetCapabilities() override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    std::string decompiler_note =
        pool_->size() > 1
            ? "parallel (" + std::to_string(pool_->size()) + " engines)"
            : "supported";
    std::vector<Capability> caps = {
        {"health", "supported", ""},
        {"session", "supported", ""},
        {"decompiler", "supported", decompiler_note},
        {"functions", "supported", "basic blocks and CFG edges via decompilation"},
        {"symbols", "supported", "rename (functions), delete (all)"},
        {"types", "supported", "full CRUD including aliases, member comments"},
        {"signatures", "supported", "full mutation via prototype rebuild"},
        {"memory", "supported", "read + write (copy-on-write overlay)"},
        {"listing", "supported", "instructions, comments, data items, strings (no bookmarks)"},
        {"xrefs", "partial", "call and data xrefs via decompiler analysis"},
    };
    return StatusOr<std::vector<Capability>>::FromValue(std::move(caps));
  }

  // -- ISessionClient ---------------------------------------------------------

  StatusOr<OpenProgramResponse> OpenProgram(
      const OpenProgramRequest& request) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    bool ok = false;

    if (!request.project_path.empty()) {
      ok = pool_->loadProject(request.project_path, request.program_path);
    } else if (!request.program_path.empty()) {
      // Dispatch by detected format: BFD/XML-recognised formats (elf/pe/mach-o)
      // auto-identify their target from the file header, so we pass "default"
      // to let ArchitectureCapability self-select. Passing a Ghidra language_id
      // like "AARCH64:LE:64:v8A" straight through would be interpreted as a BFD
      // target name (e.g. "elf64-littleaarch64"), which bfd_openr does not
      // recognise — yielding "Unable to open image file: …" despite a perfectly
      // valid ELF. For raw/unknown/empty formats, the explicit language_id is
      // still required because raw_arch can't auto-detect.
      // Always pass the full Sleigh spec id ("processor:endian:size:variant:
      // compiler") to Ghidra so the language is unambiguous. The previous
      // "let BFD auto-detect with target=default" branch produced wrong
      // results for non-x86 ELF binaries because Ghidra's BfdArchitecture::
      // resolveArchitecture has a hardcoded "elf64 -> x86:LE:64:default:gcc"
      // mapping at bfd_arch.cc:102-103, so an aarch64 ELF on a Pi would load
      // as x86 and disassembly was nonsense.
      //
      // Our patched bfd_arch.cc::buildLoader now sees a colon-bearing target
      // and passes empty BFD target so bfd_check_format auto-detects the
      // actual file format, while archid stays at the Sleigh id we sent.
      // For raw_arch (no BFD on macOS/Windows) the same full Sleigh id is
      // exactly what Ghidra needs.
      std::string arch;
      if (request.language_id.empty()) {
        arch = opts_.default_arch;
      } else if (!request.compiler_spec_id.empty()) {
        arch = request.language_id + ":" + request.compiler_spec_id;
      } else {
        arch = request.language_id;
      }
      ok = pool_->loadBinary(request.program_path, arch, request.base_address,
                             request.format);
    } else {
      return StatusOr<OpenProgramResponse>::FromError(
          "INVALID_ARGUMENT", "program_path or project_path required");
    }

    if (!ok) {
      return StatusOr<OpenProgramResponse>::FromError("LOAD_FAILED",
                                                      pool_->getError());
    }

    // Auto-load state if configured and file exists
    if (!opts_.state_path.empty()) {
      pool_->loadState(opts_.state_path);  // best-effort, primary only
    }

    program_loaded_ = true;
    revision_++;

    OpenProgramResponse resp;
    resp.program_name = request.program_path.empty() ? request.project_path
                                                     : request.program_path;
    resp.language_id =
        request.language_id.empty() ? opts_.default_arch : request.language_id;
    resp.compiler_spec = request.compiler_spec_id;
    return StatusOr<OpenProgramResponse>::FromValue(std::move(resp));
  }

  StatusOr<CloseProgramResponse> CloseProgram(ShutdownPolicy policy) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    return closeProgramLocked(policy);
  }

  StatusOr<SaveProgramResponse> SaveProgram() override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!program_loaded_) {
      return StatusOr<SaveProgramResponse>::FromError("NO_PROGRAM",
                                                      "no program loaded");
    }
    if (opts_.state_path.empty()) {
      return StatusOr<SaveProgramResponse>::FromError(
          "NO_STATE_PATH", "state_path not configured");
    }

    bool ok = pool_->saveState(opts_.state_path);
    SaveProgramResponse resp;
    resp.saved = ok;
    if (!ok) {
      return StatusOr<SaveProgramResponse>::FromError("SAVE_FAILED",
                                                      pool_->getError());
    }
    return StatusOr<SaveProgramResponse>::FromValue(std::move(resp));
  }

  StatusOr<DiscardProgramResponse> DiscardProgram() override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    DiscardProgramResponse resp;
    resp.discarded = true;
    return StatusOr<DiscardProgramResponse>::FromValue(std::move(resp));
  }

  StatusOr<RevisionResponse> GetRevision() override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    RevisionResponse resp;
    resp.modification_number = revision_;
    return StatusOr<RevisionResponse>::FromValue(std::move(resp));
  }

  StatusOr<ShutdownResponse> Shutdown(ShutdownPolicy policy) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (program_loaded_) {
      // Call the non-locking helper, NOT the public CloseProgram(): we already
      // hold req_mu_ and it is a non-recursive std::mutex, so re-entering it
      // here would self-deadlock.
      auto closed = closeProgramLocked(policy);
      if (!closed.ok()) {
        return StatusOr<ShutdownResponse>::FromError(
            closed.status.code, closed.status.message);
      }
    }
    ShutdownResponse resp;
    resp.accepted = true;
    return StatusOr<ShutdownResponse>::FromValue(std::move(resp));
  }

  StatusOr<AddPerfBenchmarkResponse> AddPerfBenchmark(
      const PerfBenchmarkRecord& record) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!program_loaded_) {
      return StatusOr<AddPerfBenchmarkResponse>::FromError("NO_PROGRAM",
                                                           "no program loaded");
    }
    if (record.bench_id.empty()) {
      return StatusOr<AddPerfBenchmarkResponse>::FromError("invalid_argument",
                                                           "bench_id is required");
    }
    // Upsert keyed on bench_id (matches the live Java host's PerfBenchmarkStore):
    // a re-run of a benchmark replaces its previous record instead of
    // accumulating duplicates.
    perf_benchmarks_.erase(
        std::remove_if(perf_benchmarks_.begin(), perf_benchmarks_.end(),
                       [&](const PerfBenchmarkRecord& r) {
                         return r.bench_id == record.bench_id;
                       }),
        perf_benchmarks_.end());
    perf_benchmarks_.push_back(record);
    revision_++;
    AddPerfBenchmarkResponse resp;
    resp.added = true;
    return StatusOr<AddPerfBenchmarkResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListPerfBenchmarksResponse> ListPerfBenchmarks() override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!program_loaded_) {
      return StatusOr<ListPerfBenchmarksResponse>::FromError("NO_PROGRAM",
                                                             "no program loaded");
    }
    ListPerfBenchmarksResponse resp;
    resp.records = perf_benchmarks_;
    return StatusOr<ListPerfBenchmarksResponse>::FromValue(std::move(resp));
  }

  StatusOr<ClearPerfBenchmarksResponse> ClearPerfBenchmarks() override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!program_loaded_) {
      return StatusOr<ClearPerfBenchmarksResponse>::FromError("NO_PROGRAM",
                                                              "no program loaded");
    }
    ClearPerfBenchmarksResponse resp;
    resp.removed_count = static_cast<std::uint32_t>(perf_benchmarks_.size());
    resp.cleared = true;
    perf_benchmarks_.clear();
    revision_++;
    return StatusOr<ClearPerfBenchmarksResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeletePerfBenchmarkResponse> DeletePerfBenchmark(
      const std::string& bench_id) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!program_loaded_) {
      return StatusOr<DeletePerfBenchmarkResponse>::FromError("NO_PROGRAM",
                                                              "no program loaded");
    }
    if (bench_id.empty()) {
      return StatusOr<DeletePerfBenchmarkResponse>::FromError("invalid_argument",
                                                              "bench_id is required");
    }
    const auto before = perf_benchmarks_.size();
    perf_benchmarks_.erase(
        std::remove_if(perf_benchmarks_.begin(), perf_benchmarks_.end(),
                       [&](const PerfBenchmarkRecord& r) {
                         return r.bench_id == bench_id;
                       }),
        perf_benchmarks_.end());
    const bool deleted = perf_benchmarks_.size() != before;
    if (deleted) revision_++;
    DeletePerfBenchmarkResponse resp;
    resp.deleted = deleted;
    return StatusOr<DeletePerfBenchmarkResponse>::FromValue(std::move(resp));
  }

  // -- IDecompilerClient ------------------------------------------------------

  StatusOr<GetDecompilationResponse> GetDecompilation(std::uint64_t address,
                                                      int /*timeout_ms*/) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<GetDecompilationResponse>();

    // Single decompilation — use primary instance. decompileWithLocals returns
    // both the pseudocode and the local-variable surface in one pass.
    auto dl = pool_->primaryAdapter().decompileWithLocals(address);

    GetDecompilationResponse resp;
    if (!dl.ok) {
      resp.decompilation = DecompilationRecord{};
      resp.decompilation->function_entry_address = address;
      resp.decompilation->completed = false;
      // Offline decompile bypasses Decompiler::decompileAt, so pool_->getError()
      // is stale/empty — carry the accurate reason from the result itself.
      resp.decompilation->error_message = dl.error;
    } else {
      DecompilationRecord rec;
      rec.function_entry_address = address;
      rec.pseudocode = std::move(dl.pseudocode);
      rec.locals = std::move(dl.locals);
      rec.completed = true;
      resp.decompilation = std::move(rec);
    }
    return StatusOr<GetDecompilationResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListDecompilationsResponse> ListDecompilations(
      std::uint64_t range_start, std::uint64_t range_end, int limit, int offset,
      int /*timeout_ms*/) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListDecompilationsResponse>();

    auto funcs = paginate(
        pool_->primaryAdapter().listFunctions(range_start, range_end),
        limit, offset);

    // Collect addresses and names for the batch
    std::vector<std::uint64_t> addresses;
    std::vector<std::string> names;
    for (const auto& f : funcs) {
      addresses.push_back(f.entry_address);
      names.push_back(f.name);
    }

    // Parallel decompilation across pool
    auto records = pool_->decompileMany(addresses, names);

    ListDecompilationsResponse resp;
    resp.decompilations = std::move(records);
    return StatusOr<ListDecompilationsResponse>::FromValue(std::move(resp));
  }

  // GetPcode intentionally remains the IClient NOT_SUPPORTED default in the
  // offline backend. Raw p-code currently lives behind the Java host's listing
  // model, while refined p-code needs a separate offline adapter contract.

  // -- IFunctionsClient -------------------------------------------------------

  StatusOr<GetFunctionResponse> GetFunction(std::uint64_t address) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<GetFunctionResponse>();

    GetFunctionResponse resp;
    resp.function = pool_->primaryAdapter().getFunction(address);
    return StatusOr<GetFunctionResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListFunctionsResponse> ListFunctions(std::uint64_t range_start,
                                                std::uint64_t range_end,
                                                int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListFunctionsResponse>();

    auto all = pool_->primaryAdapter().listFunctions(range_start, range_end);

    ListFunctionsResponse resp;
    resp.functions = paginate(all, limit, offset);
    return StatusOr<ListFunctionsResponse>::FromValue(std::move(resp));
  }

  StatusOr<RenameFunctionResponse> RenameFunction(
      std::uint64_t address, const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameFunctionResponse>();

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.nameFunction(address, new_name); });
    if (ok) revision_++;

    RenameFunctionResponse resp;
    resp.renamed = ok;
    resp.name = new_name;
    if (!ok) {
      return StatusOr<RenameFunctionResponse>::FromError("RENAME_FAILED",
                                                         pool_->getError());
    }
    return StatusOr<RenameFunctionResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListBasicBlocksResponse> ListBasicBlocks(std::uint64_t range_start,
                                                     std::uint64_t range_end,
                                                     int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListBasicBlocksResponse>();

    auto funcs = pool_->primaryAdapter().listFunctions(range_start, range_end);
    std::vector<BasicBlockRecord> all_blocks;

    if (pool_->size() <= 1) {
      for (const auto& func : funcs) {
        auto cfg = pool_->primaryAdapter().decompileAndExtractCFG(func.entry_address);
        all_blocks.insert(all_blocks.end(),
                          std::make_move_iterator(cfg.blocks.begin()),
                          std::make_move_iterator(cfg.blocks.end()));
      }
    } else {
      std::mutex mu;
      std::vector<std::future<void>> futures;
      futures.reserve(funcs.size());

      for (const auto& func : funcs) {
        futures.push_back(std::async(std::launch::async, [&, addr = func.entry_address] {
          auto lease = pool_->acquire();
          auto cfg = lease.adapter().decompileAndExtractCFG(addr);
          std::lock_guard lock(mu);
          all_blocks.insert(all_blocks.end(),
                            std::make_move_iterator(cfg.blocks.begin()),
                            std::make_move_iterator(cfg.blocks.end()));
        }));
      }
      for (auto& f : futures) {
        f.get();
      }
    }

    ListBasicBlocksResponse resp;
    resp.blocks = paginate(all_blocks, limit, offset);
    return StatusOr<ListBasicBlocksResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListCFGEdgesResponse> ListCFGEdges(std::uint64_t range_start,
                                               std::uint64_t range_end,
                                               int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListCFGEdgesResponse>();

    auto funcs = pool_->primaryAdapter().listFunctions(range_start, range_end);
    std::vector<CFGEdgeRecord> all_edges;

    if (pool_->size() <= 1) {
      for (const auto& func : funcs) {
        auto cfg = pool_->primaryAdapter().decompileAndExtractCFG(func.entry_address);
        all_edges.insert(all_edges.end(),
                         std::make_move_iterator(cfg.edges.begin()),
                         std::make_move_iterator(cfg.edges.end()));
      }
    } else {
      std::mutex mu;
      std::vector<std::future<void>> futures;
      futures.reserve(funcs.size());

      for (const auto& func : funcs) {
        futures.push_back(std::async(std::launch::async, [&, addr = func.entry_address] {
          auto lease = pool_->acquire();
          auto cfg = lease.adapter().decompileAndExtractCFG(addr);
          std::lock_guard lock(mu);
          all_edges.insert(all_edges.end(),
                           std::make_move_iterator(cfg.edges.begin()),
                           std::make_move_iterator(cfg.edges.end()));
        }));
      }
      for (auto& f : futures) {
        f.get();
      }
    }

    ListCFGEdgesResponse resp;
    resp.edges = paginate(all_edges, limit, offset);
    return StatusOr<ListCFGEdgesResponse>::FromValue(std::move(resp));
  }

  // -- ISymbolsClient ---------------------------------------------------------

  StatusOr<GetSymbolResponse> GetSymbol(std::uint64_t address) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<GetSymbolResponse>();

    GetSymbolResponse resp;
    resp.symbol = pool_->primaryAdapter().getSymbol(address);
    return StatusOr<GetSymbolResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListSymbolsResponse> ListSymbols(std::uint64_t range_start,
                                            std::uint64_t range_end, int limit,
                                            int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListSymbolsResponse>();

    auto all = pool_->primaryAdapter().listSymbols(range_start, range_end);

    ListSymbolsResponse resp;
    resp.symbols = paginate(all, limit, offset);
    return StatusOr<ListSymbolsResponse>::FromValue(std::move(resp));
  }

  StatusOr<RenameSymbolResponse> RenameSymbol(
      std::uint64_t address, const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameSymbolResponse>();

    auto sym = pool_->primaryAdapter().getSymbol(address);
    if (!sym) {
      return StatusOr<RenameSymbolResponse>::FromError(
          "NOT_FOUND", "no symbol found at address");
    }

    if (sym->type == "function") {
      bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.nameFunction(address, new_name); });
      if (ok) revision_++;

      RenameSymbolResponse resp;
      resp.renamed = ok;
      resp.name = new_name;
      if (!ok) {
        return StatusOr<RenameSymbolResponse>::FromError("RENAME_FAILED",
                                                          pool_->getError());
      }
      return StatusOr<RenameSymbolResponse>::FromValue(std::move(resp));
    }

    return StatusOr<RenameSymbolResponse>::FromError(
        "NOT_SUPPORTED",
        "RenameSymbol for non-function symbols not yet supported");
  }

  StatusOr<DeleteSymbolResponse> DeleteSymbol(
      std::uint64_t address, const std::string& /*name*/) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteSymbolResponse>();

    bool ok = pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { return a.deleteSymbol(address); });

    DeleteSymbolResponse resp;
    resp.deleted = ok;
    resp.deleted_count = ok ? 1 : 0;
    if (!ok) {
      return StatusOr<DeleteSymbolResponse>::FromError(
          "NOT_FOUND", "no symbol found at address");
    }
    revision_++;
    return StatusOr<DeleteSymbolResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient -----------------------------------------------------------

  StatusOr<ListTypesResponse> ListTypes(const std::string& query, int limit,
                                        int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListTypesResponse>();

    auto all = pool_->primaryAdapter().listTypes(query);

    ListTypesResponse resp;
    resp.types = paginate(all, limit, offset);
    return StatusOr<ListTypesResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListTypeEnumsResponse> ListTypeEnums(const std::string& query,
                                                int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListTypeEnumsResponse>();

    auto all = pool_->primaryAdapter().listTypeEnums(query);

    ListTypeEnumsResponse resp;
    resp.enums = paginate(all, limit, offset);
    return StatusOr<ListTypeEnumsResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListTypeEnumMembersResponse> ListTypeEnumMembers(
      const std::string& type_id_or_path, int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListTypeEnumMembersResponse>();

    std::string name = type_id_or_path;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    auto all = pool_->primaryAdapter().listTypeEnumMembers(name);

    ListTypeEnumMembersResponse resp;
    resp.members = paginate(all, limit, offset);
    return StatusOr<ListTypeEnumMembersResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListTypeMembersResponse> ListTypeMembers(
      const std::string& type_id_or_path, int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListTypeMembersResponse>();

    std::string name = type_id_or_path;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    auto all = pool_->primaryAdapter().listTypeMembers(name);

    ListTypeMembersResponse resp;
    resp.members = paginate(all, limit, offset);
    return StatusOr<ListTypeMembersResponse>::FromValue(std::move(resp));
  }

  StatusOr<GetTypeResponse> GetType(const std::string& name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<GetTypeResponse>();

    GetTypeResponse resp;
    resp.type = pool_->primaryAdapter().getType(name);
    return StatusOr<GetTypeResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListTypeAliasesResponse> ListTypeAliases(const std::string& query,
                                                     int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListTypeAliasesResponse>();

    auto all = pool_->primaryAdapter().listTypeAliases(query);

    ListTypeAliasesResponse resp;
    resp.aliases = paginate(all, limit, offset);
    return StatusOr<ListTypeAliasesResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListTypeUnionsResponse> ListTypeUnions(const std::string& query,
                                                   int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListTypeUnionsResponse>();

    auto all = pool_->primaryAdapter().listTypeUnions(query);

    ListTypeUnionsResponse resp;
    resp.unions = paginate(all, limit, offset);
    return StatusOr<ListTypeUnionsResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetFunctionSignatureResponse> SetFunctionSignature(
      std::uint64_t address, const std::string& prototype) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetFunctionSignatureResponse>();

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.setPrototype(address, prototype); });
    if (ok) revision_++;

    SetFunctionSignatureResponse resp;
    resp.updated = ok;
    resp.prototype = prototype;
    if (!ok) {
      return StatusOr<SetFunctionSignatureResponse>::FromError(
          "SET_PROTOTYPE_FAILED", pool_->getError());
    }
    return StatusOr<SetFunctionSignatureResponse>::FromValue(std::move(resp));
  }

  StatusOr<CreateTypeResponse> CreateType(const std::string& name,
                                          const std::string& kind,
                                          std::uint64_t size) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<CreateTypeResponse>();

    if (kind == "struct") {
      bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.defineStruct(name, {}); });
      if (ok) revision_++;
      CreateTypeResponse resp;
      resp.updated = ok;
      if (!ok) {
        return StatusOr<CreateTypeResponse>::FromError("CREATE_TYPE_FAILED",
                                                       pool_->getError());
      }
      return StatusOr<CreateTypeResponse>::FromValue(std::move(resp));
    }

    return StatusOr<CreateTypeResponse>::FromError(
        "NOT_SUPPORTED", "only struct kind is currently supported for creation");
  }

  StatusOr<AddTypeMemberResponse> AddTypeMember(
      const std::string& parent, const std::string& member_name,
      const std::string& member_type, std::uint64_t size) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<AddTypeMemberResponse>();

    std::string name = parent;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    auto existing = pool_->primaryAdapter().listTypeMembers(name);

    int off = 0;
    for (const auto& m : existing) {
      int end = static_cast<int>(m.offset) + static_cast<int>(m.size);
      if (end > off) off = end;
    }

    std::vector<ghidra_standalone::FieldDef> fields;
    for (const auto& m : existing) {
      fields.push_back({m.name, m.member_type, static_cast<int>(m.offset)});
    }
    fields.push_back({member_name, member_type, off});

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.defineStruct(name, fields); });
    if (ok) revision_++;

    AddTypeMemberResponse resp;
    resp.updated = ok;
    if (!ok) {
      return StatusOr<AddTypeMemberResponse>::FromError("ADD_MEMBER_FAILED",
                                                         pool_->getError());
    }
    return StatusOr<AddTypeMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<CreateTypeEnumResponse> CreateTypeEnum(const std::string& name,
                                                  std::uint64_t width,
                                                  bool is_signed) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<CreateTypeEnumResponse>();

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.defineEnum(name, std::vector<ghidra_standalone::EnumValue>{}); });
    if (ok) revision_++;

    CreateTypeEnumResponse resp;
    resp.updated = ok;
    if (!ok) {
      return StatusOr<CreateTypeEnumResponse>::FromError(
          "CREATE_ENUM_FAILED", pool_->getError());
    }
    return StatusOr<CreateTypeEnumResponse>::FromValue(std::move(resp));
  }

  StatusOr<AddTypeEnumMemberResponse> AddTypeEnumMember(
      const std::string& type_id_or_path, const std::string& name,
      std::int64_t value) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<AddTypeEnumMemberResponse>();

    std::string type_name = type_id_or_path;
    if (!type_name.empty() && type_name[0] == '/') type_name = type_name.substr(1);

    auto existing = pool_->primaryAdapter().listTypeEnumMembers(type_name);

    std::vector<ghidra_standalone::EnumValue> entries;
    for (const auto& m : existing) {
      entries.push_back({m.name, static_cast<uint64_t>(m.value)});
    }
    entries.push_back({name, static_cast<uint64_t>(value)});

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.defineEnum(type_name, entries); });
    if (ok) revision_++;

    AddTypeEnumMemberResponse resp;
    resp.updated = ok;
    if (!ok) {
      return StatusOr<AddTypeEnumMemberResponse>::FromError(
          "ADD_ENUM_MEMBER_FAILED", pool_->getError());
    }
    return StatusOr<AddTypeEnumMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteTypeResponse> DeleteType(
      const std::string& type_id_or_path) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteTypeResponse>();

    std::string name = type_id_or_path;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    bool ok = pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { return a.deleteType(name); });

    DeleteTypeResponse resp;
    resp.deleted = ok;
    if (!ok) {
      return StatusOr<DeleteTypeResponse>::FromError(
          "DELETE_TYPE_FAILED", "type not found or is a core type");
    }
    revision_++;
    return StatusOr<DeleteTypeResponse>::FromValue(std::move(resp));
  }

  StatusOr<RenameTypeResponse> RenameType(
      const std::string& type_id_or_path,
      const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameTypeResponse>();

    std::string name = type_id_or_path;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    bool ok = pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { return a.renameType(name, new_name); });

    RenameTypeResponse resp;
    resp.updated = ok;
    resp.name = new_name;
    if (!ok) {
      return StatusOr<RenameTypeResponse>::FromError(
          "RENAME_TYPE_FAILED", "type not found");
    }
    revision_++;
    return StatusOr<RenameTypeResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteTypeMemberResponse> DeleteTypeMember(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteTypeMemberResponse>();

    std::string name = parent_type_id_or_path;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    auto existing = pool_->primaryAdapter().listTypeMembers(name);
    if (ordinal >= existing.size()) {
      return StatusOr<DeleteTypeMemberResponse>::FromError(
          "NOT_FOUND", "ordinal out of range");
    }

    std::vector<ghidra_standalone::FieldDef> fields;
    for (std::uint64_t i = 0; i < existing.size(); i++) {
      if (i == ordinal) continue;
      fields.push_back({existing[i].name, existing[i].member_type,
                         static_cast<int>(existing[i].offset)});
    }

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.defineStruct(name, fields); });

    DeleteTypeMemberResponse resp;
    resp.deleted = ok;
    if (!ok) {
      return StatusOr<DeleteTypeMemberResponse>::FromError(
          "DELETE_MEMBER_FAILED", pool_->getError());
    }
    revision_++;
    return StatusOr<DeleteTypeMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<RenameTypeMemberResponse> RenameTypeMember(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameTypeMemberResponse>();

    std::string name = parent_type_id_or_path;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    auto existing = pool_->primaryAdapter().listTypeMembers(name);
    if (ordinal >= existing.size()) {
      return StatusOr<RenameTypeMemberResponse>::FromError(
          "NOT_FOUND", "ordinal out of range");
    }

    std::vector<ghidra_standalone::FieldDef> fields;
    for (std::uint64_t i = 0; i < existing.size(); i++) {
      std::string field_name = (i == ordinal) ? new_name : existing[i].name;
      fields.push_back({field_name, existing[i].member_type,
                         static_cast<int>(existing[i].offset)});
    }

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.defineStruct(name, fields); });

    RenameTypeMemberResponse resp;
    resp.updated = ok;
    if (!ok) {
      return StatusOr<RenameTypeMemberResponse>::FromError(
          "RENAME_MEMBER_FAILED", pool_->getError());
    }
    revision_++;
    return StatusOr<RenameTypeMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetTypeMemberTypeResponse> SetTypeMemberType(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& member_type) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetTypeMemberTypeResponse>();

    std::string name = parent_type_id_or_path;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    auto existing = pool_->primaryAdapter().listTypeMembers(name);
    if (ordinal >= existing.size()) {
      return StatusOr<SetTypeMemberTypeResponse>::FromError(
          "NOT_FOUND", "ordinal out of range");
    }

    std::vector<ghidra_standalone::FieldDef> fields;
    for (std::uint64_t i = 0; i < existing.size(); i++) {
      std::string type_str = (i == ordinal) ? member_type : existing[i].member_type;
      fields.push_back({existing[i].name, type_str,
                         static_cast<int>(existing[i].offset)});
    }

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.defineStruct(name, fields); });

    SetTypeMemberTypeResponse resp;
    resp.updated = ok;
    if (!ok) {
      return StatusOr<SetTypeMemberTypeResponse>::FromError(
          "SET_MEMBER_TYPE_FAILED", pool_->getError());
    }
    revision_++;
    return StatusOr<SetTypeMemberTypeResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteTypeEnumMemberResponse> DeleteTypeEnumMember(
      const std::string& type_id_or_path,
      std::uint64_t ordinal) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteTypeEnumMemberResponse>();

    std::string type_name = type_id_or_path;
    if (!type_name.empty() && type_name[0] == '/') type_name = type_name.substr(1);

    auto existing = pool_->primaryAdapter().listTypeEnumMembers(type_name);
    if (ordinal >= existing.size()) {
      return StatusOr<DeleteTypeEnumMemberResponse>::FromError(
          "NOT_FOUND", "ordinal out of range");
    }

    std::vector<ghidra_standalone::EnumValue> entries;
    for (std::uint64_t i = 0; i < existing.size(); i++) {
      if (i == ordinal) continue;
      entries.push_back({existing[i].name, static_cast<uint64_t>(existing[i].value)});
    }

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.defineEnum(type_name, entries); });

    DeleteTypeEnumMemberResponse resp;
    resp.deleted = ok;
    if (!ok) {
      return StatusOr<DeleteTypeEnumMemberResponse>::FromError(
          "DELETE_ENUM_MEMBER_FAILED", pool_->getError());
    }
    revision_++;
    return StatusOr<DeleteTypeEnumMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<RenameTypeEnumMemberResponse> RenameTypeEnumMember(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameTypeEnumMemberResponse>();

    std::string type_name = type_id_or_path;
    if (!type_name.empty() && type_name[0] == '/') type_name = type_name.substr(1);

    auto existing = pool_->primaryAdapter().listTypeEnumMembers(type_name);
    if (ordinal >= existing.size()) {
      return StatusOr<RenameTypeEnumMemberResponse>::FromError(
          "NOT_FOUND", "ordinal out of range");
    }

    std::vector<ghidra_standalone::EnumValue> entries;
    for (std::uint64_t i = 0; i < existing.size(); i++) {
      std::string entry_name = (i == ordinal) ? new_name : existing[i].name;
      entries.push_back({entry_name, static_cast<uint64_t>(existing[i].value)});
    }

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.defineEnum(type_name, entries); });

    RenameTypeEnumMemberResponse resp;
    resp.updated = ok;
    if (!ok) {
      return StatusOr<RenameTypeEnumMemberResponse>::FromError(
          "RENAME_ENUM_MEMBER_FAILED", pool_->getError());
    }
    revision_++;
    return StatusOr<RenameTypeEnumMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetTypeEnumMemberValueResponse> SetTypeEnumMemberValue(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      std::int64_t value) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetTypeEnumMemberValueResponse>();

    std::string type_name = type_id_or_path;
    if (!type_name.empty() && type_name[0] == '/') type_name = type_name.substr(1);

    auto existing = pool_->primaryAdapter().listTypeEnumMembers(type_name);
    if (ordinal >= existing.size()) {
      return StatusOr<SetTypeEnumMemberValueResponse>::FromError(
          "NOT_FOUND", "ordinal out of range");
    }

    std::vector<ghidra_standalone::EnumValue> entries;
    for (std::uint64_t i = 0; i < existing.size(); i++) {
      uint64_t entry_value = (i == ordinal)
          ? static_cast<uint64_t>(value)
          : static_cast<uint64_t>(existing[i].value);
      entries.push_back({existing[i].name, entry_value});
    }

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.defineEnum(type_name, entries); });

    SetTypeEnumMemberValueResponse resp;
    resp.updated = ok;
    if (!ok) {
      return StatusOr<SetTypeEnumMemberValueResponse>::FromError(
          "SET_ENUM_VALUE_FAILED", pool_->getError());
    }
    revision_++;
    return StatusOr<SetTypeEnumMemberValueResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (signatures) -----------------------------------------------

  StatusOr<GetFunctionSignatureResponse> GetFunctionSignature(
      std::uint64_t address) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<GetFunctionSignatureResponse>();

    // Decompile first to populate FuncProto, then extract signature
    pool_->primary().decompileAt(address);

    GetFunctionSignatureResponse resp;
    resp.signature = pool_->primaryAdapter().getFunctionSignature(address);
    return StatusOr<GetFunctionSignatureResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListFunctionSignaturesResponse> ListFunctionSignatures(
      std::uint64_t range_start, std::uint64_t range_end, int limit,
      int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListFunctionSignaturesResponse>();

    auto funcs = paginate(
        pool_->primaryAdapter().listFunctions(range_start, range_end),
        limit, offset);

    std::vector<FunctionSignatureRecord> sigs;

    if (pool_->size() <= 1) {
      // Single-threaded path
      for (const auto& f : funcs) {
        pool_->primary().decompileAt(f.entry_address);
        auto sig = pool_->primaryAdapter().getFunctionSignature(f.entry_address);
        if (sig) sigs.push_back(std::move(*sig));
      }
    } else {
      // Multi-threaded path: lease pool slots for parallel decompile+extract
      sigs.resize(funcs.size());
      std::vector<bool> valid(funcs.size(), false);
      std::vector<std::future<void>> futures;
      futures.reserve(funcs.size());

      for (int i = 0; i < static_cast<int>(funcs.size()); i++) {
        futures.push_back(std::async(std::launch::async,
            [&, addr = funcs[i].entry_address, idx = i] {
              auto lease = pool_->acquire();
              lease.decomp().decompileAt(addr);
              auto sig = lease.adapter().getFunctionSignature(addr);
              if (sig) {
                sigs[idx] = std::move(*sig);
                valid[idx] = true;
              }
            }));
      }
      for (auto& f : futures) {
        f.get();
      }

      // Remove invalid entries
      std::vector<FunctionSignatureRecord> filtered;
      for (int i = 0; i < static_cast<int>(sigs.size()); i++) {
        if (valid[i]) filtered.push_back(std::move(sigs[i]));
      }
      sigs = std::move(filtered);
    }

    ListFunctionSignaturesResponse resp;
    resp.signatures = std::move(sigs);
    return StatusOr<ListFunctionSignaturesResponse>::FromValue(std::move(resp));
  }

  // -- IXrefsClient -----------------------------------------------------------

  StatusOr<ListXrefsResponse> ListXrefs(std::uint64_t range_start,
                                        std::uint64_t range_end, int limit,
                                        int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListXrefsResponse>();

    auto funcs = pool_->primaryAdapter().listFunctions(range_start, range_end);

    // Xref extraction requires decompilation + Funcdata in the SAME instance,
    // so we decompile each function in its leased instance and extract xrefs
    // there before releasing.
    std::vector<XrefRecord> all_xrefs;

    if (pool_->size() <= 1) {
      // Single-threaded path (same as before)
      for (const auto& func : funcs) {
        // listXrefsForFunction() now runs its own decompile; a preceding
        // decompileAt() would perform() then clearAnalysis(), wiping the very
        // Funcdata the extraction reads (offline xrefs came back empty).
        auto func_xrefs =
            pool_->primaryAdapter().listXrefsForFunction(func.entry_address);
        all_xrefs.insert(all_xrefs.end(),
                          std::make_move_iterator(func_xrefs.begin()),
                          std::make_move_iterator(func_xrefs.end()));
      }
    } else {
      // Multi-threaded path: lease a pool slot per function, decompile + extract
      std::mutex xrefs_mu;
      std::vector<std::future<void>> futures;
      futures.reserve(funcs.size());

      for (const auto& func : funcs) {
        futures.push_back(std::async(std::launch::async, [&, addr = func.entry_address] {
          auto lease = pool_->acquire();
          // listXrefsForFunction() runs its own decompile (see the single-
          // threaded path); no pre-decompile that would clear the analysis.
          auto func_xrefs = lease.adapter().listXrefsForFunction(addr);
          std::lock_guard lock(xrefs_mu);
          all_xrefs.insert(all_xrefs.end(),
                            std::make_move_iterator(func_xrefs.begin()),
                            std::make_move_iterator(func_xrefs.end()));
        }));
      }
      for (auto& f : futures) {
        f.get();
      }
    }

    ListXrefsResponse resp;
    resp.xrefs = paginate(all_xrefs, limit, offset);
    return StatusOr<ListXrefsResponse>::FromValue(std::move(resp));
  }

  // -- IMemoryClient ----------------------------------------------------------

  StatusOr<ReadBytesResponse> ReadBytes(std::uint64_t address,
                                        std::uint32_t length) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ReadBytesResponse>();

    auto data = pool_->primaryAdapter().readBytes(address, length);

    ReadBytesResponse resp;
    resp.data = std::move(data);
    return StatusOr<ReadBytesResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListMemoryBlocksResponse> ListMemoryBlocks(int limit,
                                                       int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListMemoryBlocksResponse>();

    auto all = pool_->primaryAdapter().listMemoryBlocks();

    ListMemoryBlocksResponse resp;
    resp.blocks = paginate(all, limit, offset);
    return StatusOr<ListMemoryBlocksResponse>::FromValue(std::move(resp));
  }

  // -- IListingClient ---------------------------------------------------------

  StatusOr<GetInstructionResponse> GetInstruction(std::uint64_t address) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<GetInstructionResponse>();

    GetInstructionResponse resp;
    resp.instruction = pool_->primaryAdapter().getInstruction(address);
    return StatusOr<GetInstructionResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListInstructionsResponse> ListInstructions(
      std::uint64_t range_start, std::uint64_t range_end, int limit,
      int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListInstructionsResponse>();

    auto all = pool_->primaryAdapter().listInstructions(range_start, range_end,
                                                        limit + offset);

    ListInstructionsResponse resp;
    resp.instructions = paginate(all, limit, offset);
    return StatusOr<ListInstructionsResponse>::FromValue(std::move(resp));
  }

  // ListInstructionOperands is intentionally NOT overridden here: the offline
  // decompiler bridge renders whole-instruction records (mnemonic + combined
  // operand text) but does not decompose into the per-operand representation the
  // RPC returns (Ghidra's getDefaultOperandRepresentation / getOperandType /
  // getOperandRefType are Java-host-only). The offline backend therefore inherits
  // IClient's honest NOT_SUPPORTED for it — this is a capability boundary, not a TODO.

  StatusOr<GetCommentsResponse> GetComments(std::uint64_t range_start,
                                            std::uint64_t range_end,
                                            int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<GetCommentsResponse>();

    auto all = paginate(
        pool_->primaryAdapter().getComments(range_start, range_end),
        limit, offset);

    GetCommentsResponse resp;
    for (const auto& c : all) {
      CommentRecord rec;
      rec.address = c.address;
      rec.kind = static_cast<CommentKind>(c.kind);
      rec.text = c.text;
      resp.comments.push_back(std::move(rec));
    }
    return StatusOr<GetCommentsResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetCommentResponse> SetComment(std::uint64_t address,
                                          CommentKind kind,
                                          const std::string& text) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetCommentResponse>();

    pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { a.setComment(address, static_cast<int>(kind), text); return true; });
    revision_++;

    SetCommentResponse resp;
    resp.updated = true;
    return StatusOr<SetCommentResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteCommentResponse> DeleteComment(std::uint64_t address,
                                                CommentKind kind) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteCommentResponse>();

    bool ok = pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { return a.deleteComment(address, static_cast<int>(kind)); });

    DeleteCommentResponse resp;
    resp.deleted = ok;
    if (!ok) {
      return StatusOr<DeleteCommentResponse>::FromError(
          "NOT_FOUND", "no comment at address with given kind");
    }
    revision_++;
    return StatusOr<DeleteCommentResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListDataItemsResponse> ListDataItems(std::uint64_t range_start,
                                                std::uint64_t range_end,
                                                int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListDataItemsResponse>();

    auto all = paginate(
        pool_->primaryAdapter().listDataItems(range_start, range_end),
        limit, offset);

    ListDataItemsResponse resp;
    for (const auto& d : all) {
      DataItemRecord rec;
      rec.address = d.address;
      rec.name = d.name;
      rec.data_type = d.data_type;
      rec.size = d.size;
      // end_address is INCLUSIVE (last byte), matching the live Java host's
      // Ghidra maxAddress semantics. A zero-size item degenerates to
      // end == address.
      rec.end_address = d.size > 0 ? d.address + d.size - 1 : d.address;
      resp.data_items.push_back(std::move(rec));
    }
    return StatusOr<ListDataItemsResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListDefinedStringsResponse> ListDefinedStrings(
      std::uint64_t /*range_start*/, std::uint64_t /*range_end*/,
      int /*limit*/, int /*offset*/) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListDefinedStringsResponse>();

    // The offline decompiler engine does not maintain a defined-string database.
    // Return empty results (operation is valid but no data to report).
    ListDefinedStringsResponse resp;
    return StatusOr<ListDefinedStringsResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (type aliases) -------------------------------------------

  StatusOr<CreateTypeAliasResponse> CreateTypeAlias(
      const std::string& alias_name, const std::string& target_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<CreateTypeAliasResponse>();

    bool ok = pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { return a.createTypeAlias(alias_name, target_name); });

    CreateTypeAliasResponse resp;
    resp.updated = ok;
    if (!ok) {
      return StatusOr<CreateTypeAliasResponse>::FromError(
          "CREATE_ALIAS_FAILED", "target type not found or alias creation failed");
    }
    revision_++;
    return StatusOr<CreateTypeAliasResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteTypeAliasResponse> DeleteTypeAlias(
      const std::string& alias_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteTypeAliasResponse>();

    std::string name = alias_name;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    bool ok = pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { return a.deleteTypeAlias(name); });

    DeleteTypeAliasResponse resp;
    resp.deleted = ok;
    if (!ok) {
      return StatusOr<DeleteTypeAliasResponse>::FromError(
          "DELETE_ALIAS_FAILED", "alias not found or not a typedef");
    }
    revision_++;
    return StatusOr<DeleteTypeAliasResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetTypeAliasTargetResponse> SetTypeAliasTarget(
      const std::string& alias_name,
      const std::string& new_target_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetTypeAliasTargetResponse>();

    std::string name = alias_name;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    bool ok = pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { return a.setTypeAliasTarget(name, new_target_name); });

    SetTypeAliasTargetResponse resp;
    resp.updated = ok;
    if (!ok) {
      return StatusOr<SetTypeAliasTargetResponse>::FromError(
          "SET_ALIAS_TARGET_FAILED",
          "alias not found, not a typedef, or new target not found");
    }
    revision_++;
    return StatusOr<SetTypeAliasTargetResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (type member comments) -----------------------------------

  StatusOr<SetTypeMemberCommentResponse> SetTypeMemberComment(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& comment) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetTypeMemberCommentResponse>();

    std::string name = parent_type_id_or_path;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { a.setTypeMemberComment(name, ordinal, comment); return true; });
    revision_++;

    SetTypeMemberCommentResponse resp;
    resp.updated = true;
    return StatusOr<SetTypeMemberCommentResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetTypeEnumMemberCommentResponse> SetTypeEnumMemberComment(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      const std::string& comment) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetTypeEnumMemberCommentResponse>();

    std::string name = type_id_or_path;
    if (!name.empty() && name[0] == '/') name = name.substr(1);

    pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { a.setTypeEnumMemberComment(name, ordinal, comment); return true; });
    revision_++;

    SetTypeEnumMemberCommentResponse resp;
    resp.updated = true;
    return StatusOr<SetTypeEnumMemberCommentResponse>::FromValue(std::move(resp));
  }

  // -- IListingClient (data item mutations) ----------------------------------

  StatusOr<RenameDataItemResponse> RenameDataItem(
      std::uint64_t address, const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameDataItemResponse>();

    bool ok = pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { return a.renameDataItem(address, new_name); });

    RenameDataItemResponse resp;
    resp.updated = ok;
    resp.name = new_name;
    if (!ok) {
      return StatusOr<RenameDataItemResponse>::FromError(
          "RENAME_FAILED", "no data item at address or is a function symbol");
    }
    revision_++;
    return StatusOr<RenameDataItemResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteDataItemResponse> DeleteDataItem(std::uint64_t address) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteDataItemResponse>();

    bool ok = pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) { return a.deleteDataItem(address); });

    DeleteDataItemResponse resp;
    resp.deleted = ok;
    if (!ok) {
      return StatusOr<DeleteDataItemResponse>::FromError(
          "NOT_FOUND", "no data item at address or is a function symbol");
    }
    revision_++;
    return StatusOr<DeleteDataItemResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (function parameter mutations) ---------------------------

  StatusOr<RenameFunctionParameterResponse> RenameFunctionParameter(
      std::uint64_t address, int ordinal,
      const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameFunctionParameterResponse>();

    // Decompile to populate FuncProto, then extract current signature
    pool_->primary().decompileAt(address);
    auto sig = pool_->primaryAdapter().getFunctionSignature(address);
    if (!sig) {
      return StatusOr<RenameFunctionParameterResponse>::FromError(
          "NOT_FOUND", "no function at address");
    }

    if (ordinal < 0 || ordinal >= static_cast<int>(sig->parameters.size())) {
      return StatusOr<RenameFunctionParameterResponse>::FromError(
          "OUT_OF_RANGE", "parameter ordinal out of range");
    }

    // Modify parameter name and rebuild prototype
    sig->parameters[ordinal].name = new_name;
    std::string proto = buildPrototypeString(*sig);

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.setPrototype(address, proto); });
    if (ok) revision_++;

    RenameFunctionParameterResponse resp;
    resp.updated = ok;
    resp.name = new_name;
    if (!ok) {
      return StatusOr<RenameFunctionParameterResponse>::FromError(
          "SET_PROTOTYPE_FAILED", pool_->getError());
    }
    return StatusOr<RenameFunctionParameterResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetFunctionParameterTypeResponse> SetFunctionParameterType(
      std::uint64_t address, int ordinal,
      const std::string& new_type) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetFunctionParameterTypeResponse>();

    pool_->primary().decompileAt(address);
    auto sig = pool_->primaryAdapter().getFunctionSignature(address);
    if (!sig) {
      return StatusOr<SetFunctionParameterTypeResponse>::FromError(
          "NOT_FOUND", "no function at address");
    }

    if (ordinal < 0 || ordinal >= static_cast<int>(sig->parameters.size())) {
      return StatusOr<SetFunctionParameterTypeResponse>::FromError(
          "OUT_OF_RANGE", "parameter ordinal out of range");
    }

    sig->parameters[ordinal].data_type = new_type;
    std::string proto = buildPrototypeString(*sig);

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.setPrototype(address, proto); });
    if (ok) revision_++;

    SetFunctionParameterTypeResponse resp;
    resp.updated = ok;
    resp.data_type = new_type;
    if (!ok) {
      return StatusOr<SetFunctionParameterTypeResponse>::FromError(
          "SET_PROTOTYPE_FAILED", pool_->getError());
    }
    return StatusOr<SetFunctionParameterTypeResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (ApplyDataType) ------------------------------------------

  StatusOr<ApplyDataTypeResponse> ApplyDataType(
      std::uint64_t address, const std::string& data_type) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ApplyDataTypeResponse>();

    // Check for existing symbol name or generate one
    auto sym = pool_->primaryAdapter().getSymbol(address);
    std::string name;
    if (sym && !sym->name.empty()) {
      name = sym->name;
    } else {
      // Generate DAT_<hex> name
      char buf[32];
      snprintf(buf, sizeof(buf), "DAT_%08llx",
               static_cast<unsigned long long>(address));
      name = buf;
    }

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { return d.nameGlobal(address, name, data_type); });
    if (ok) revision_++;

    ApplyDataTypeResponse resp;
    resp.updated = ok;
    resp.data_type = data_type;
    if (!ok) {
      return StatusOr<ApplyDataTypeResponse>::FromError(
          "APPLY_FAILED", pool_->getError());
    }
    return StatusOr<ApplyDataTypeResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (function local mutations) -------------------------------

  StatusOr<RenameFunctionLocalResponse> RenameFunctionLocal(
      std::uint64_t address, const std::string& local_id,
      const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameFunctionLocalResponse>();

    // Apply the rename to the decompiler scope on every slot (name-locked so it
    // survives re-decompilation). Reports honest, specific failure so ghidrasql
    // surfaces a real "UPDATE decomp_lvars failed" with a precise reason.
    switch (pool_->applyLocalRenameAllSlots(address, local_id, new_name)) {
      case detail::LocalMutationStatus::kOk:
        break;
      case detail::LocalMutationStatus::kNotFound:
        return StatusOr<RenameFunctionLocalResponse>::FromError(
            "NOT_FOUND",
            "no local matching id '" + local_id + "' in function at 0x" +
                to_hex_string(address));
      case detail::LocalMutationStatus::kDecompileFailed:
      case detail::LocalMutationStatus::kInvalidType:  // unreachable for rename
        return StatusOr<RenameFunctionLocalResponse>::FromError(
            "DECOMPILE_FAILED",
            "could not decompile function at 0x" + to_hex_string(address) +
                " to rename local '" + local_id + "'");
    }
    revision_++;

    RenameFunctionLocalResponse resp;
    resp.updated = true;
    resp.local_id = local_id;
    resp.name = new_name;
    return StatusOr<RenameFunctionLocalResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetFunctionLocalTypeResponse> SetFunctionLocalType(
      std::uint64_t address, const std::string& local_id,
      const std::string& new_type) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetFunctionLocalTypeResponse>();

    // Apply the retype to the decompiler scope on every slot (type-locked).
    // Distinguish a bad type string from a missing local from a decompile
    // failure so the caller gets an actionable error code.
    switch (pool_->applyLocalRetypeAllSlots(address, local_id, new_type)) {
      case detail::LocalMutationStatus::kOk:
        break;
      case detail::LocalMutationStatus::kInvalidType:
        return StatusOr<SetFunctionLocalTypeResponse>::FromError(
            "INVALID_TYPE",
            "could not parse type '" + new_type + "' for local '" + local_id +
                "'");
      case detail::LocalMutationStatus::kNotFound:
        return StatusOr<SetFunctionLocalTypeResponse>::FromError(
            "NOT_FOUND",
            "no local matching id '" + local_id + "' in function at 0x" +
                to_hex_string(address));
      case detail::LocalMutationStatus::kDecompileFailed:
        return StatusOr<SetFunctionLocalTypeResponse>::FromError(
            "DECOMPILE_FAILED",
            "could not decompile function at 0x" + to_hex_string(address) +
                " to retype local '" + local_id + "'");
    }
    revision_++;

    SetFunctionLocalTypeResponse resp;
    resp.updated = true;
    resp.local_id = local_id;
    resp.data_type = new_type;
    return StatusOr<SetFunctionLocalTypeResponse>::FromValue(std::move(resp));
  }

  // -- IMemoryClient (write support) -----------------------------------------

  StatusOr<WriteBytesResponse> WriteBytes(
      std::uint64_t address,
      const std::vector<std::uint8_t>& data) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<WriteBytesResponse>();

    pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { d.writeBytes(address, data); return true; });
    revision_++;

    WriteBytesResponse resp;
    resp.bytes_written = static_cast<std::uint32_t>(data.size());
    return StatusOr<WriteBytesResponse>::FromValue(std::move(resp));
  }

  StatusOr<PatchBytesBatchResponse> PatchBytesBatch(
      const std::vector<BytePatch>& patches) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<PatchBytesBatchResponse>();

    std::uint32_t total_bytes = 0;
    for (const auto& patch : patches) {
      pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) { d.writeBytes(patch.address, patch.data); return true; });
      total_bytes += static_cast<std::uint32_t>(patch.data.size());
    }
    revision_++;

    PatchBytesBatchResponse resp;
    resp.patch_count = static_cast<std::uint32_t>(patches.size());
    resp.bytes_written = total_bytes;
    return StatusOr<PatchBytesBatchResponse>::FromValue(std::move(resp));
  }

 private:
  bool ensure_loaded() const {
    return program_loaded_ && pool_ && pool_->primaryAdapter().valid();
  }

  template <typename T>
  StatusOr<T> not_loaded() const {
    return StatusOr<T>::FromError("NO_PROGRAM", "no program loaded; call OpenProgram first");
  }

  /// Non-locking body of CloseProgram(). The caller MUST already hold req_mu_.
  /// Extracted so Shutdown() (which holds the lock) can close the program
  /// without re-entering the non-recursive req_mu_ (which would self-deadlock).
  StatusOr<CloseProgramResponse> closeProgramLocked(ShutdownPolicy policy) {
    if (!program_loaded_) {
      return StatusOr<CloseProgramResponse>::FromError("NO_PROGRAM",
                                                       "no program loaded");
    }

    const bool should_save = policy == ShutdownPolicy::kSave;
    if (should_save && !opts_.state_path.empty() &&
        !pool_->saveState(opts_.state_path)) {
      return StatusOr<CloseProgramResponse>::FromError(
          "SAVE_FAILED", pool_->getError());
    }

    pool_->resetAdapters();
    program_loaded_ = false;
    perf_benchmarks_.clear();

    CloseProgramResponse resp;
    resp.closed = true;
    return StatusOr<CloseProgramResponse>::FromValue(std::move(resp));
  }

  /// Build a C prototype string from a FunctionSignatureRecord.
  static std::string buildPrototypeString(const FunctionSignatureRecord& sig) {
    std::string proto = sig.return_type + " " + sig.function_name + "(";
    for (std::size_t i = 0; i < sig.parameters.size(); i++) {
      if (i > 0) proto += ", ";
      proto += sig.parameters[i].data_type + " " + sig.parameters[i].name;
    }
    if (sig.has_var_args) {
      if (!sig.parameters.empty()) proto += ", ";
      proto += "...";
    }
    proto += ")";
    return proto;
  }

  LocalClientOptions opts_;
  std::unique_ptr<detail::DecompilerPool> pool_;
  bool program_loaded_ = false;
  std::uint64_t revision_ = 0;

  // In-memory perf_benchmarks store. The offline backend has no persistent
  // program database, so benchmark rows live for the duration of the loaded
  // program and are dropped when the program is closed. This keeps the write
  // path exercisable offline (parity with the HTTP backend's persisted store).
  std::vector<PerfBenchmarkRecord> perf_benchmarks_;

  // Serializes every public IClient dispatch method. The in-process pool is only
  // internally thread-safe for lease-vs-lease and lease-vs-applyToAllSlots: the
  // ungated primary()/primaryAdapter() slot-0 reads (GetDecompilation,
  // GetFunctionSignature, ListXrefs, RenameFunctionParameter, ...) bypass the
  // availability gate, so a concurrent applyToAllSlots scope mutation could race
  // a primary-slot decompile on the shared Architecture. Holding this lock for
  // the whole request makes LocalClient safe under concurrent transport dispatch
  // and also keeps the non-atomic revision_ counter consistent. Invariant: a
  // public method never calls another public method (which would re-enter this
  // non-recursive mutex and self-deadlock); shared bodies are factored into
  // non-locking *Locked helpers (e.g. closeProgramLocked) that the lock-holding
  // public method delegates to.
  mutable std::mutex req_mu_;
};

// -- Factory ------------------------------------------------------------------

std::unique_ptr<IClient> CreateLocalClient(LocalClientOptions options) {
  return std::make_unique<LocalClient>(std::move(options));
}

}  // namespace libghidra::client
