// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "libghidra/local.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "decompiler_pool.hpp"
#include "ghidra_decompiler.h"
#include "libghidra/error_codes.hpp"
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

std::string hex(std::uint64_t v) { return "0x" + to_hex_string(v); }

namespace codes = libghidra::client::error_codes;
using detail::RangeStatus;
using detail::WriteStatus;
using ghidra_standalone::EngineError;

// The vocabulary code for why an engine call failed.
const char* engine_code(EngineError kind) {
  switch (kind) {
    case EngineError::kNotFound: return codes::kNotFound;
    case EngineError::kParse: return codes::kParseError;
    case EngineError::kUnknownType: return codes::kUnknownType;
    case EngineError::kInvalid: return codes::kInvalidArgument;
    default: return codes::kInternalError;
  }
}

std::string lower(std::string text) {
  for (char& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return text;
}

std::string trim(const std::string& text) {
  const auto first = text.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = text.find_last_not_of(" \t\r\n");
  return text.substr(first, last - first + 1);
}

// SymbolUtilities.validateName for the ASCII range: at most 2000 characters, no
// space or control character (Ghidra rejects every whitespace/unprintable code point).
bool validSymbolName(const std::string& name) {
  if (name.empty() || name.size() > 2000) return false;
  for (unsigned char c : name)
    if (c <= 0x20 || c == 0x7f) return false;
  return true;
}

// The inclusive end of a listing range: 0 means "to the end", as on the host.
std::uint64_t range_end_of(std::uint64_t range_end) { return range_end == 0 ? UINT64_MAX : range_end; }

// -- Breakpoints, stored as bookmarks (the host's BreakpointBookmarkStore) ----

constexpr const char* kBreakpointType = "GhidraAPI Breakpoint";
constexpr const char* kBreakpointCategory = "libghidra.breakpoint";

std::string base64url(const std::string& in) {
  static const char* kAlphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  std::uint32_t buf = 0;
  int bits = 0;
  for (unsigned char c : in) {
    buf = (buf << 8) | c;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += kAlphabet[(buf >> bits) & 0x3f];
    }
  }
  if (bits > 0) out += kAlphabet[(buf << (6 - bits)) & 0x3f];
  return out;
}

std::optional<std::string> unbase64url(const std::string& in) {
  std::string out;
  std::uint32_t buf = 0;
  int bits = 0;
  for (char c : in) {
    int v;
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
    else if (c >= '0' && c <= '9') v = c - '0' + 52;
    else if (c == '-' || c == '+') v = 62;
    else if (c == '_' || c == '/') v = 63;
    else if (c == '=') break;
    else return std::nullopt;
    buf = (buf << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += static_cast<char>((buf >> bits) & 0xff);
    }
  }
  return out;
}

BreakpointRecord breakpoint_from(const ghidra_standalone::BookmarkInfo& b) {
  BreakpointRecord row;
  row.address = b.address;
  row.enabled = true;
  row.kind = "software";
  row.size = 1;
  const std::string category = trim(b.category);
  row.group = lower(category) == kBreakpointCategory ? "" : category;
  std::map<std::string, std::string> fields;
  std::size_t at = 0;
  while (at <= b.comment.size()) {
    std::size_t semi = b.comment.find(';', at);
    if (semi == std::string::npos) semi = b.comment.size();
    const std::string part = b.comment.substr(at, semi - at);
    at = semi + 1;
    const std::size_t eq = part.find('=');
    if (eq == std::string::npos || eq == 0 || eq + 1 >= part.size()) continue;
    fields[lower(trim(part.substr(0, eq)))] = trim(part.substr(eq + 1));
  }
  auto text = [&](const char* b64, const char* plain, const std::string& fallback) {
    auto e = fields.find(b64);
    if (e != fields.end() && !e->second.empty()) return unbase64url(e->second).value_or(fallback);
    auto p = fields.find(plain);
    return p != fields.end() && !p->second.empty() ? p->second : fallback;
  };
  auto number = [&](const char* key, long long fallback) {
    auto it = fields.find(key);
    if (it == fields.end()) return fallback;
    try {
      return std::stoll(it->second);
    } catch (...) {
      return fallback;
    }
  };
  row.enabled = number("enabled", 1) != 0;
  row.kind = text("kind_b64", "kind", "software");
  row.size = static_cast<std::uint64_t>(std::max<long long>(1, number("size", 1)));
  row.condition = text("condition_b64", "condition", "");
  return row;
}

std::string breakpoint_comment(const BreakpointRecord& row) {
  const std::string kind = trim(row.kind).empty() ? "software" : trim(row.kind);
  return "enabled=" + std::string(row.enabled ? "1" : "0") + ";kind_b64=" + base64url(kind) +
         ";size=" + std::to_string(std::max<std::uint64_t>(1, row.size)) +
         ";condition_b64=" + base64url(row.condition);
}

std::string breakpoint_category(const std::string& group) {
  return trim(group).empty() ? kBreakpointCategory : trim(group);
}

bool breakpoint_kind_ok(const std::string& kind) {
  const std::string k = lower(kind);
  return k == "software" || k == "hardware" || k == "read" || k == "write" || k == "access";
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
        {"functions", "supported",
         "basic blocks and CFG edges via decompilation; leaf functions from a "
         "project's reference index"},
        {"symbols", "supported",
         "functions and labels from the project; rename (by old name too), create a label, "
         "delete"},
        {"types", "supported",
         "structs, unions, enums and aliases; member edits in place; C declarations"},
        {"signatures", "supported", "full mutation via prototype rebuild"},
        {"memory", "supported",
         "the program's memory map; read + write (copy-on-write overlay); no block writes"},
        {"listing", "supported",
         "instructions, comments, data items, bookmarks and breakpoints from the project"},
        {"xrefs", "partial", "call and data xrefs via decompiler analysis"},
    };
    return StatusOr<std::vector<Capability>>::FromValue(std::move(caps));
  }

  // -- ISessionClient ---------------------------------------------------------

  StatusOr<OpenProgramResponse> OpenProgram(
      const OpenProgramRequest& request) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    // One program at a time, as on the host.
    if (program_loaded_) {
      return StatusOr<OpenProgramResponse>::FromError(
          codes::kAccessConflict,
          "a program is already open (" + open_request_.program_path + open_request_.project_path +
              "); close it first");
    }
    Status loaded = loadLocked(request);
    if (!loaded.ok()) {
      return StatusOr<OpenProgramResponse>::FromError(loaded.code, loaded.message);
    }
    open_request_ = request;
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
      return StatusOr<SaveProgramResponse>::FromError(codes::kNotLoaded,
                                                      "no program loaded");
    }
    // Offline saves only to a configured state file.
    if (opts_.state_path.empty()) {
      return StatusOr<SaveProgramResponse>::FromError(
          codes::kConfigError,
          "the offline backend saves to LocalClientOptions::state_path, which is not set");
    }
    if (!pool_->saveState(opts_.state_path)) {
      return StatusOr<SaveProgramResponse>::FromError(codes::kInternalError,
                                                      pool_->getError());
    }
    SaveProgramResponse resp;
    resp.saved = true;
    return StatusOr<SaveProgramResponse>::FromValue(std::move(resp));
  }

  StatusOr<DiscardProgramResponse> DiscardProgram() override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!program_loaded_) {
      return StatusOr<DiscardProgramResponse>::FromError(codes::kNotLoaded,
                                                         "no program loaded");
    }
    // Drop every edit by loading the program again, as it was opened
    // (the host undoes every transaction; the program stays open).
    Status reloaded = loadLocked(open_request_);
    if (!reloaded.ok()) {
      program_loaded_ = false;
      return StatusOr<DiscardProgramResponse>::FromError(
          codes::kInternalError, "discard failed reloading the program: " + reloaded.message);
    }
    revision_++;
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
      return StatusOr<AddPerfBenchmarkResponse>::FromError(codes::kNotLoaded,
                                                           "no program loaded");
    }
    if (record.bench_id.empty()) {
      return StatusOr<AddPerfBenchmarkResponse>::FromError(codes::kInvalidArgument,
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
      return StatusOr<ListPerfBenchmarksResponse>::FromError(codes::kNotLoaded,
                                                             "no program loaded");
    }
    ListPerfBenchmarksResponse resp;
    resp.records = perf_benchmarks_;
    return StatusOr<ListPerfBenchmarksResponse>::FromValue(std::move(resp));
  }

  StatusOr<ClearPerfBenchmarksResponse> ClearPerfBenchmarks() override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!program_loaded_) {
      return StatusOr<ClearPerfBenchmarksResponse>::FromError(codes::kNotLoaded,
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
      return StatusOr<DeletePerfBenchmarkResponse>::FromError(codes::kNotLoaded,
                                                              "no program loaded");
    }
    if (bench_id.empty()) {
      return StatusOr<DeletePerfBenchmarkResponse>::FromError(codes::kInvalidArgument,
                                                              "bench_id is required");
    }
    const auto before = perf_benchmarks_.size();
    perf_benchmarks_.erase(
        std::remove_if(perf_benchmarks_.begin(), perf_benchmarks_.end(),
                       [&](const PerfBenchmarkRecord& r) {
                         return r.bench_id == bench_id;
                       }),
        perf_benchmarks_.end());
    if (perf_benchmarks_.size() == before) {
      return StatusOr<DeletePerfBenchmarkResponse>::FromError(
          codes::kNotFound, "no perf benchmark '" + bench_id + "'");
    }
    revision_++;
    DeletePerfBenchmarkResponse resp;
    resp.deleted = true;
    return StatusOr<DeletePerfBenchmarkResponse>::FromValue(std::move(resp));
  }

  // -- IDecompilerClient ------------------------------------------------------

  StatusOr<GetDecompilationResponse> GetDecompilation(std::uint64_t address,
                                                      int /*timeout_ms*/) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<GetDecompilationResponse>();

    // The function the address names, as the host resolves it (the one that
    // contains it); none is "not found": the record stays unset.
    GetDecompilationResponse resp;
    const std::optional<std::uint64_t> entry =
        pool_->primaryAdapter().decompileEntryFor(address);
    if (!entry) return StatusOr<GetDecompilationResponse>::FromValue(std::move(resp));

    // Single decompilation — use primary instance. decompileWithLocals returns
    // both the pseudocode and the local-variable surface in one pass.
    auto dl = pool_->primaryAdapter().decompileWithLocals(*entry);

    if (!dl.ok) {
      resp.decompilation = DecompilationRecord{};
      resp.decompilation->function_entry_address = *entry;
      resp.decompilation->completed = false;
      // Offline decompile bypasses Decompiler::decompileAt, so pool_->getError()
      // is stale/empty — carry the accurate reason from the result itself.
      resp.decompilation->error_message = dl.error;
    } else {
      DecompilationRecord rec;
      rec.function_entry_address = *entry;
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

  // GetPcode intentionally remains the IClient not_supported default in the
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

  // Leaves come from the reference index Ghidra recorded during analysis, read
  // out of the project db -- the same rule the live host applies -- so both
  // backends return the same set. The decompiler's own call graph is not used:
  // it classifies import thunks and lowered tail calls differently. A program
  // loaded from a bare binary has no such index, so it refuses rather than guess.
  StatusOr<ListFunctionsResponse> ListLeafFunctions(std::uint64_t range_start,
                                                    std::uint64_t range_end,
                                                    int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListFunctionsResponse>();

    std::vector<std::uint64_t> leaves;
    if (!pool_->primary().projectLeafEntries(leaves)) {
      return StatusOr<ListFunctionsResponse>::FromError(
          codes::kNotSupported,
          "ListLeafFunctions needs a program opened from a Ghidra project "
          "(project_path): it reads the reference index Ghidra recorded during analysis");
    }
    std::vector<FunctionRecord> matched;
    for (auto& f : pool_->primaryAdapter().listFunctions(range_start, range_end)) {
      if (std::binary_search(leaves.begin(), leaves.end(), f.entry_address))
        matched.push_back(std::move(f));
    }

    ListFunctionsResponse resp;
    resp.functions = paginate(matched, limit, offset);
    return StatusOr<ListFunctionsResponse>::FromValue(std::move(resp));
  }

  // The one write that makes a function: at the start of an instruction (of
  // the project's listing, or any decodable address of a bare binary), named
  // `name` or Ghidra's default FUN_<address>. Renames and prototype edits never
  // create one.
  StatusOr<CreateFunctionResponse> CreateFunction(
      std::uint64_t address, const std::optional<std::string>& name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<CreateFunctionResponse>();
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<CreateFunctionResponse>(mapped);
    auto& adapter = pool_->primaryAdapter();
    if (adapter.functionStartsAt(address)) {
      return StatusOr<CreateFunctionResponse>::FromError(
          codes::kDuplicateName, "a function already starts at " + hex(address));
    }
    if (!adapter.getInstruction(address)) {
      return StatusOr<CreateFunctionResponse>::FromError(
          codes::kInvalidArgument,
          "no instruction starts at " + hex(address) + "; a function starts at code");
    }
    const std::string fname =
        name && !name->empty() ? *name : detail::ArchAdapter::defaultFunctionName(address);
    Status created = decompilerWrite([&](ghidra_standalone::Decompiler& d) {
      return d.defineFunction(address, fname);
    });
    if (!created.ok()) return error<CreateFunctionResponse>(created);
    revision_++;

    CreateFunctionResponse resp;
    resp.created = true;
    if (auto fn = adapter.getFunction(address)) resp.function = std::move(*fn);
    return StatusOr<CreateFunctionResponse>::FromValue(std::move(resp));
  }

  StatusOr<RenameFunctionResponse> RenameFunction(
      std::uint64_t address, const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameFunctionResponse>();
    if (new_name.empty()) {
      return StatusOr<RenameFunctionResponse>::FromError(codes::kInvalidArgument,
                                                         "function name is required");
    }
    std::uint64_t entry = 0;
    Status found = requireFunction(address, entry);
    if (!found.ok()) return error<RenameFunctionResponse>(found);

    Status renamed = decompilerWrite([&](ghidra_standalone::Decompiler& d) {
      return d.renameFunction(entry, new_name);
    });
    if (!renamed.ok()) return error<RenameFunctionResponse>(renamed);
    revision_++;

    RenameFunctionResponse resp;
    resp.renamed = true;
    resp.name = new_name;
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

  // A label is added beside whatever the address has (the host's
  // SymbolTable.createLabel); it never renames another symbol.
  StatusOr<CreateLabelResponse> CreateLabel(std::uint64_t address,
                                            const std::string& name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<CreateLabelResponse>();
    const std::string label = trim(name);
    if (label.empty()) {
      return StatusOr<CreateLabelResponse>::FromError(codes::kInvalidArgument,
                                                      "label name is required");
    }
    if (!validSymbolName(label)) {
      return StatusOr<CreateLabelResponse>::FromError(
          codes::kInvalidArgument, "symbol name contains invalid characters: " + label);
    }
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<CreateLabelResponse>(mapped);
    auto& adapter = pool_->primaryAdapter();
    for (const auto& sym : adapter.listSymbols(address, address)) {
      if (sym.address == address && (sym.name == label || sym.full_name == label)) {
        return StatusOr<CreateLabelResponse>::FromError(
            codes::kDuplicateName,
            "a symbol named '" + label + "' is already at " + hex(address));
      }
    }
    Status created = decompilerWrite([&](ghidra_standalone::Decompiler& d) {
      return d.createLabel(address, label);
    });
    if (!created.ok()) return error<CreateLabelResponse>(created);
    revision_++;

    CreateLabelResponse resp;
    resp.created = true;
    for (auto& sym : adapter.listSymbols(address, address)) {
      if (sym.address == address && sym.name == label) resp.symbol = std::move(sym);
    }
    return StatusOr<CreateLabelResponse>::FromValue(std::move(resp));
  }

  // The primary symbol at a mapped address (a function's own, else the
  // primary label) is renamed, or a label is created when it has none (the
  // host's upsert). With `old_name`, exactly the symbol of that name.
  StatusOr<RenameSymbolResponse> RenameSymbol(
      std::uint64_t address, const std::string& new_name,
      const std::optional<std::string>& old_name = std::nullopt) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameSymbolResponse>();
    const std::string name = trim(new_name);
    if (name.empty()) {
      return StatusOr<RenameSymbolResponse>::FromError(codes::kInvalidArgument,
                                                       "new symbol name is required");
    }
    std::optional<std::string> old;
    if (old_name) {
      old = trim(*old_name);
      if (old->empty()) {
        return StatusOr<RenameSymbolResponse>::FromError(
            codes::kInvalidArgument, "old_name, when given, names the symbol to rename");
      }
    }
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<RenameSymbolResponse>(mapped);

    Status renamed = decompilerWrite([&](ghidra_standalone::Decompiler& d) {
      return d.renameSymbolAt(address, old, name);
    });
    if (!renamed.ok()) return error<RenameSymbolResponse>(renamed);
    revision_++;

    RenameSymbolResponse resp;
    resp.renamed = true;
    resp.name = name;
    return StatusOr<RenameSymbolResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteSymbolResponse> DeleteSymbol(
      std::uint64_t address, const std::string& name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteSymbolResponse>();
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<DeleteSymbolResponse>(mapped);

    // A function's own symbol goes back to its default name; the function
    // stays. The name filter selects which symbols at the address go.
    std::optional<std::uint32_t> count;
    const std::string filter = trim(name);
    pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) {
      const std::uint32_t n = d.deleteSymbolsAt(address, filter);
      if (!count) count = n;
      return n > 0;
    });
    if (count.value_or(0) == 0) {
      return StatusOr<DeleteSymbolResponse>::FromError(
          codes::kNotFound, name.empty() ? "no symbol at " + hex(address)
                                         : "no symbol named '" + name + "' at " + hex(address));
    }
    revision_++;

    DeleteSymbolResponse resp;
    resp.deleted = true;
    resp.deleted_count = *count;
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

    auto all = pool_->primaryAdapter().listTypeEnumMembers(type_id_or_path);

    ListTypeEnumMembersResponse resp;
    resp.members = paginate(all, limit, offset);
    return StatusOr<ListTypeEnumMembersResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListTypeMembersResponse> ListTypeMembers(
      const std::string& type_id_or_path, int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListTypeMembersResponse>();

    auto all = pool_->primaryAdapter().listTypeMembers(type_id_or_path);

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
    if (prototype.empty()) {
      return StatusOr<SetFunctionSignatureResponse>::FromError(codes::kInvalidArgument,
                                                               "prototype is required");
    }
    std::uint64_t entry = 0;
    Status found = requireFunction(address, entry);
    if (!found.ok()) return error<SetFunctionSignatureResponse>(found);

    Status set = decompilerWrite([&](ghidra_standalone::Decompiler& d) {
      return d.setPrototype(entry, prototype);
    });
    if (!set.ok()) return error<SetFunctionSignatureResponse>(set);
    revision_++;

    SetFunctionSignatureResponse resp;
    resp.updated = true;
    resp.prototype = prototype;
    return StatusOr<SetFunctionSignatureResponse>::FromValue(std::move(resp));
  }

  StatusOr<CreateTypeResponse> CreateType(const std::string& name,
                                          const std::string& kind,
                                          std::uint64_t size) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<CreateTypeResponse>();
    if (name.empty()) {
      return StatusOr<CreateTypeResponse>::FromError(codes::kInvalidArgument,
                                                     "type name is required");
    }
    const std::string k = lower(kind);
    if (k != "struct" && k != "enum" && k != "union") {
      return StatusOr<CreateTypeResponse>::FromError(
          codes::kInvalidArgument,
          "unknown type kind '" + kind + "'; expected struct, enum or union");
    }
    Status fresh = requireNewTypeName(name);
    if (!fresh.ok()) return error<CreateTypeResponse>(fresh);

    Status created = decompilerWrite([&](ghidra_standalone::Decompiler& d) {
      if (k == "struct") return d.defineStruct(name, {}, static_cast<int>(std::min<std::uint64_t>(size, 1u << 20)));
      if (k == "union") return d.defineUnion(name);
      // The host's CreateType "enum": size clamped to 1..8, 4 when unset.
      return d.defineEnum(name, std::vector<ghidra_standalone::EnumValue>{},
                          size == 0 ? 4 : static_cast<int>(std::min<std::uint64_t>(size, 8)));
    });
    if (!created.ok()) return error<CreateTypeResponse>(created);
    revision_++;
    CreateTypeResponse resp;
    resp.updated = true;
    return StatusOr<CreateTypeResponse>::FromValue(std::move(resp));
  }

  StatusOr<AddTypeMemberResponse> AddTypeMember(
      const std::string& parent, const std::string& member_name,
      const std::string& member_type, std::uint64_t /*size*/) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<AddTypeMemberResponse>();
    if (member_name.empty()) {
      return StatusOr<AddTypeMemberResponse>::FromError(codes::kInvalidArgument, "member name is required");
    }
    if (member_type.empty()) {
      return StatusOr<AddTypeMemberResponse>::FromError(codes::kInvalidArgument, "member type is required");
    }
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.addTypeMember(parent, member_name, member_type); });
    if (!written.ok()) return error<AddTypeMemberResponse>(written);
    revision_++;
    AddTypeMemberResponse resp;
    resp.updated = true;
    return StatusOr<AddTypeMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<CreateTypeEnumResponse> CreateTypeEnum(const std::string& name,
                                                  std::uint64_t width,
                                                  bool /*is_signed*/) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<CreateTypeEnumResponse>();
    if (name.empty()) {
      return StatusOr<CreateTypeEnumResponse>::FromError(codes::kInvalidArgument,
                                                         "enum name is required");
    }
    Status fresh = requireNewTypeName(name);
    if (!fresh.ok()) return error<CreateTypeEnumResponse>(fresh);

    Status created = decompilerWrite([&](ghidra_standalone::Decompiler& d) {
      // EnumDataType(name, width): width clamped to 1..8, 4 when unset; the
      // host records `signed` only as a description.
      return d.defineEnum(name, std::vector<ghidra_standalone::EnumValue>{},
                          width == 0 ? 4 : static_cast<int>(std::min<std::uint64_t>(width, 8)));
    });
    if (!created.ok()) return error<CreateTypeEnumResponse>(created);
    revision_++;
    CreateTypeEnumResponse resp;
    resp.updated = true;
    return StatusOr<CreateTypeEnumResponse>::FromValue(std::move(resp));
  }

  StatusOr<AddTypeEnumMemberResponse> AddTypeEnumMember(
      const std::string& type_id_or_path, const std::string& name,
      std::int64_t value) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<AddTypeEnumMemberResponse>();
    if (name.empty()) {
      return StatusOr<AddTypeEnumMemberResponse>::FromError(codes::kInvalidArgument, "enum member name is required");
    }
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.addTypeEnumMember(type_id_or_path, name, value); });
    if (!written.ok()) return error<AddTypeEnumMemberResponse>(written);
    revision_++;
    AddTypeEnumMemberResponse resp;
    resp.updated = true;
    return StatusOr<AddTypeEnumMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteTypeEnumResponse> DeleteTypeEnum(const std::string& type_id_or_path) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteTypeEnumResponse>();
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.deleteTypeEnum(type_id_or_path); });
    if (!written.ok()) return error<DeleteTypeEnumResponse>(written);
    revision_++;
    DeleteTypeEnumResponse resp;
    resp.deleted = true;
    return StatusOr<DeleteTypeEnumResponse>::FromValue(std::move(resp));
  }

  // C declarations through the engine's own C grammar, all or nothing: any
  // error is parse_error and leaves no type behind (D10).
  StatusOr<ParseDeclarationsResponse> ParseDeclarations(const std::string& source_text) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ParseDeclarationsResponse>();
    if (trim(source_text).empty()) {
      return StatusOr<ParseDeclarationsResponse>::FromError(codes::kInvalidArgument,
                                                            "source text is required");
    }
    std::vector<std::string> names;
    bool first = true;
    Status parsed = adapterWrite([&](detail::ArchAdapter& a) {
      std::vector<std::string> created;
      WriteStatus st = a.parseDeclarations(source_text, created);
      if (first) names = std::move(created);
      first = false;
      return st;
    });
    if (!parsed.ok()) return error<ParseDeclarationsResponse>(parsed);
    revision_++;
    ParseDeclarationsResponse resp;
    resp.types_created = static_cast<int>(names.size());
    resp.type_names = std::move(names);
    return StatusOr<ParseDeclarationsResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteTypeResponse> DeleteType(
      const std::string& type_id_or_path) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteTypeResponse>();
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.deleteType(type_id_or_path); });
    if (!written.ok()) return error<DeleteTypeResponse>(written);
    revision_++;
    DeleteTypeResponse resp;
    resp.deleted = true;
    return StatusOr<DeleteTypeResponse>::FromValue(std::move(resp));
  }

  StatusOr<RenameTypeResponse> RenameType(
      const std::string& type_id_or_path,
      const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameTypeResponse>();
    if (new_name.empty()) {
      return StatusOr<RenameTypeResponse>::FromError(codes::kInvalidArgument, "new type name is required");
    }
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.renameType(type_id_or_path, new_name); });
    if (!written.ok()) return error<RenameTypeResponse>(written);
    revision_++;
    RenameTypeResponse resp;
    resp.updated = true;
    resp.name = new_name;
    return StatusOr<RenameTypeResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteTypeMemberResponse> DeleteTypeMember(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteTypeMemberResponse>();
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.deleteTypeMember(parent_type_id_or_path, ordinal); });
    if (!written.ok()) return error<DeleteTypeMemberResponse>(written);
    revision_++;
    DeleteTypeMemberResponse resp;
    resp.deleted = true;
    return StatusOr<DeleteTypeMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<RenameTypeMemberResponse> RenameTypeMember(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameTypeMemberResponse>();
    if (new_name.empty()) {
      return StatusOr<RenameTypeMemberResponse>::FromError(codes::kInvalidArgument, "member name is required");
    }
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.renameTypeMember(parent_type_id_or_path, ordinal, new_name); });
    if (!written.ok()) return error<RenameTypeMemberResponse>(written);
    revision_++;
    RenameTypeMemberResponse resp;
    resp.updated = true;
    return StatusOr<RenameTypeMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetTypeMemberTypeResponse> SetTypeMemberType(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& member_type) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetTypeMemberTypeResponse>();
    if (member_type.empty()) {
      return StatusOr<SetTypeMemberTypeResponse>::FromError(codes::kInvalidArgument, "member type is required");
    }
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.setTypeMemberType(parent_type_id_or_path, ordinal, member_type); });
    if (!written.ok()) return error<SetTypeMemberTypeResponse>(written);
    revision_++;
    SetTypeMemberTypeResponse resp;
    resp.updated = true;
    return StatusOr<SetTypeMemberTypeResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteTypeEnumMemberResponse> DeleteTypeEnumMember(
      const std::string& type_id_or_path,
      std::uint64_t ordinal) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteTypeEnumMemberResponse>();
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.deleteTypeEnumMember(type_id_or_path, ordinal); });
    if (!written.ok()) return error<DeleteTypeEnumMemberResponse>(written);
    revision_++;
    DeleteTypeEnumMemberResponse resp;
    resp.deleted = true;
    return StatusOr<DeleteTypeEnumMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<RenameTypeEnumMemberResponse> RenameTypeEnumMember(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameTypeEnumMemberResponse>();
    if (new_name.empty()) {
      return StatusOr<RenameTypeEnumMemberResponse>::FromError(codes::kInvalidArgument, "enum member name is required");
    }
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.renameTypeEnumMember(type_id_or_path, ordinal, new_name); });
    if (!written.ok()) return error<RenameTypeEnumMemberResponse>(written);
    revision_++;
    RenameTypeEnumMemberResponse resp;
    resp.updated = true;
    return StatusOr<RenameTypeEnumMemberResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetTypeEnumMemberValueResponse> SetTypeEnumMemberValue(
      const std::string& type_id_or_path,
      std::uint64_t ordinal,
      std::int64_t value) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetTypeEnumMemberValueResponse>();
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.setTypeEnumMemberValue(type_id_or_path, ordinal, value); });
    if (!written.ok()) return error<SetTypeEnumMemberValueResponse>(written);
    revision_++;
    SetTypeEnumMemberValueResponse resp;
    resp.updated = true;
    return StatusOr<SetTypeEnumMemberValueResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (signatures) -----------------------------------------------

  StatusOr<GetFunctionSignatureResponse> GetFunctionSignature(
      std::uint64_t address) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<GetFunctionSignatureResponse>();

    // The prototype is read directly: a saved signature is installed locked at
    // load, and anything a decompile infers is discarded by clearAnalysis, so
    // decompiling first cannot change the answer.
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
    sigs.reserve(funcs.size());
    for (const auto& f : funcs) {
      auto sig = pool_->primaryAdapter().getFunctionSignature(f.entry_address);
      if (sig) sigs.push_back(std::move(*sig));
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

    RangeStatus status = RangeStatus::kOk;
    auto data = pool_->primaryAdapter().readBytes(address, length, status);
    switch (status) {
      case RangeStatus::kUnmapped:
        return StatusOr<ReadBytesResponse>::FromError(
            codes::kUnmappedAddress, "no memory block contains " + hex(address));
      case RangeStatus::kUninitialized:
        return StatusOr<ReadBytesResponse>::FromError(
            codes::kUninitializedMemory, "the block at " + hex(address) + " holds no bytes");
      case RangeStatus::kUnavailable:
        return StatusOr<ReadBytesResponse>::FromError(
            codes::kNotSupported,
            "the offline image holds no bytes for the block at " + hex(address));
      default:
        break;
    }
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
  // IClient's honest not_supported for it — this is a capability boundary, not a TODO.

  StatusOr<GetCommentsResponse> GetComments(std::uint64_t range_start,
                                            std::uint64_t range_end,
                                            int limit, int offset) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<GetCommentsResponse>();

    auto all = paginate(
        pool_->primary().comments(range_start, range_end_of(range_end)),
        limit, offset);

    GetCommentsResponse resp;
    for (const auto& c : all) {
      CommentRecord rec;
      rec.address = c.address;
      rec.kind = static_cast<CommentKind>(c.type + 1);  // CommentType ordinal -> CommentKind
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
    if (kind == CommentKind::kUnspecified) {
      return StatusOr<SetCommentResponse>::FromError(codes::kInvalidArgument,
                                                     "unsupported comment kind");
    }
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<SetCommentResponse>(mapped);
    // A comment attaches to the start of a code unit; one inside an
    // instruction would be stored where no listing shows it.
    if (auto start = pool_->primaryAdapter().insideInstruction(address)) {
      return StatusOr<SetCommentResponse>::FromError(
          codes::kInvalidArgument, hex(address) + " is inside the instruction at " + hex(*start) +
                                       "; comments attach to the start of a code unit");
    }

    pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) {
      d.setComment(address, static_cast<int>(kind) - 1, text);
      return true;
    });
    revision_++;

    SetCommentResponse resp;
    resp.updated = true;
    return StatusOr<SetCommentResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteCommentResponse> DeleteComment(std::uint64_t address,
                                                CommentKind kind) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteCommentResponse>();
    if (kind == CommentKind::kUnspecified) {
      return StatusOr<DeleteCommentResponse>::FromError(codes::kInvalidArgument,
                                                        "unsupported comment kind");
    }
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<DeleteCommentResponse>(mapped);

    bool ok = pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) {
      return d.deleteComment(address, static_cast<int>(kind) - 1);
    });
    if (!ok) {
      return StatusOr<DeleteCommentResponse>::FromError(
          codes::kNotFound, "no comment of that kind at " + hex(address));
    }
    revision_++;
    DeleteCommentResponse resp;
    resp.deleted = true;
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
    if (alias_name.empty()) {
      return StatusOr<CreateTypeAliasResponse>::FromError(codes::kInvalidArgument, "alias name is required");
    }
    if (target_name.empty()) {
      return StatusOr<CreateTypeAliasResponse>::FromError(codes::kInvalidArgument, "alias target type is required");
    }
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.createTypeAlias(alias_name, target_name); });
    if (!written.ok()) return error<CreateTypeAliasResponse>(written);
    revision_++;
    CreateTypeAliasResponse resp;
    resp.updated = true;
    return StatusOr<CreateTypeAliasResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteTypeAliasResponse> DeleteTypeAlias(
      const std::string& alias_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteTypeAliasResponse>();
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.deleteTypeAlias(alias_name); });
    if (!written.ok()) return error<DeleteTypeAliasResponse>(written);
    revision_++;
    DeleteTypeAliasResponse resp;
    resp.deleted = true;
    return StatusOr<DeleteTypeAliasResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetTypeAliasTargetResponse> SetTypeAliasTarget(
      const std::string& alias_name,
      const std::string& new_target_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetTypeAliasTargetResponse>();
    if (new_target_name.empty()) {
      return StatusOr<SetTypeAliasTargetResponse>::FromError(codes::kInvalidArgument, "alias target type is required");
    }
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.setTypeAliasTarget(alias_name, new_target_name); });
    if (!written.ok()) return error<SetTypeAliasTargetResponse>(written);
    revision_++;
    SetTypeAliasTargetResponse resp;
    resp.updated = true;
    return StatusOr<SetTypeAliasTargetResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (type member comments) -----------------------------------

  StatusOr<SetTypeMemberCommentResponse> SetTypeMemberComment(
      const std::string& parent_type_id_or_path,
      std::uint64_t ordinal,
      const std::string& comment) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetTypeMemberCommentResponse>();
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.setTypeMemberComment(parent_type_id_or_path, ordinal, comment); });
    if (!written.ok()) return error<SetTypeMemberCommentResponse>(written);
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
    Status written = adapterWrite([&](detail::ArchAdapter& a) { return a.setTypeEnumMemberComment(type_id_or_path, ordinal, comment); });
    if (!written.ok()) return error<SetTypeEnumMemberCommentResponse>(written);
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
    if (new_name.empty()) {
      return StatusOr<RenameDataItemResponse>::FromError(codes::kInvalidArgument,
                                                         "data item name is required");
    }
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<RenameDataItemResponse>(mapped);
    if (!pool_->primary().hasDataAt(address)) {
      return StatusOr<RenameDataItemResponse>::FromError(codes::kNotFound,
                                                         "no data item at " + hex(address));
    }
    // The item's primary symbol is renamed, or a label created (the host's rule).
    Status renamed = decompilerWrite([&](ghidra_standalone::Decompiler& d) {
      return d.renameSymbolAt(address, std::nullopt, new_name);
    });
    if (!renamed.ok()) return error<RenameDataItemResponse>(renamed);
    revision_++;
    RenameDataItemResponse resp;
    resp.updated = true;
    resp.name = new_name;
    return StatusOr<RenameDataItemResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteDataItemResponse> DeleteDataItem(std::uint64_t address) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteDataItemResponse>();
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<DeleteDataItemResponse>(mapped);

    bool ok = pool_->applyDecompilerMutationAllSlots(
        [&](ghidra_standalone::Decompiler& d) { return d.clearData(address); });
    if (!ok) {
      return StatusOr<DeleteDataItemResponse>::FromError(codes::kNotFound,
                                                         "no data item at " + hex(address));
    }
    revision_++;
    DeleteDataItemResponse resp;
    resp.deleted = true;
    return StatusOr<DeleteDataItemResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (function parameter mutations) ---------------------------

  StatusOr<RenameFunctionParameterResponse> RenameFunctionParameter(
      std::uint64_t address, int ordinal,
      const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameFunctionParameterResponse>();
    if (new_name.empty()) {
      return StatusOr<RenameFunctionParameterResponse>::FromError(
          codes::kInvalidArgument, "parameter name is required");
    }
    std::uint64_t entry = 0;
    Status found = requireParameter(address, ordinal, entry);
    if (!found.ok()) return error<RenameFunctionParameterResponse>(found);

    Status set = decompilerWrite([&](ghidra_standalone::Decompiler& d) {
      return d.setParameterName(entry, ordinal, new_name);
    });
    if (!set.ok()) return error<RenameFunctionParameterResponse>(set);
    revision_++;

    RenameFunctionParameterResponse resp;
    resp.updated = true;
    resp.name = new_name;
    return StatusOr<RenameFunctionParameterResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetFunctionParameterTypeResponse> SetFunctionParameterType(
      std::uint64_t address, int ordinal,
      const std::string& new_type) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetFunctionParameterTypeResponse>();
    if (new_type.empty()) {
      return StatusOr<SetFunctionParameterTypeResponse>::FromError(
          codes::kInvalidArgument, "parameter type is required");
    }
    std::uint64_t entry = 0;
    Status found = requireParameter(address, ordinal, entry);
    if (!found.ok()) return error<SetFunctionParameterTypeResponse>(found);

    Status set = decompilerWrite([&](ghidra_standalone::Decompiler& d) {
      return d.setParameterType(entry, ordinal, new_type);
    });
    if (!set.ok()) return error<SetFunctionParameterTypeResponse>(set);
    revision_++;

    SetFunctionParameterTypeResponse resp;
    resp.updated = true;
    resp.data_type = new_type;
    return StatusOr<SetFunctionParameterTypeResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (ApplyDataType) ------------------------------------------

  StatusOr<ApplyDataTypeResponse> ApplyDataType(
      std::uint64_t address, const std::string& data_type) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ApplyDataTypeResponse>();
    if (data_type.empty()) {
      return StatusOr<ApplyDataTypeResponse>::FromError(codes::kInvalidArgument,
                                                        "data type is required");
    }
    Status applied = adapterWrite([&](detail::ArchAdapter& a) {
      return a.applyDataType(address, data_type);
    });
    if (!applied.ok()) return error<ApplyDataTypeResponse>(applied);
    revision_++;

    ApplyDataTypeResponse resp;
    resp.updated = true;
    resp.data_type = data_type;
    return StatusOr<ApplyDataTypeResponse>::FromValue(std::move(resp));
  }

  // -- ITypesClient (function local mutations) -------------------------------

  StatusOr<RenameFunctionLocalResponse> RenameFunctionLocal(
      std::uint64_t address, const std::string& local_id,
      const std::string& new_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<RenameFunctionLocalResponse>();
    if (local_id.empty() || new_name.empty()) {
      return StatusOr<RenameFunctionLocalResponse>::FromError(
          codes::kInvalidArgument, "local id and new local name are required");
    }
    std::uint64_t entry = 0;
    Status found = requireFunction(address, entry);
    if (!found.ok()) return error<RenameFunctionLocalResponse>(found);

    // Apply the rename to the decompiler scope on every slot (name-locked so it
    // survives re-decompilation).
    Status renamed = localStatus(pool_->applyLocalRenameAllSlots(entry, local_id, new_name),
                                 entry, local_id, "");
    if (!renamed.ok()) return error<RenameFunctionLocalResponse>(renamed);
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
    if (local_id.empty() || new_type.empty()) {
      return StatusOr<SetFunctionLocalTypeResponse>::FromError(
          codes::kInvalidArgument, "local id and local type are required");
    }
    std::uint64_t entry = 0;
    Status found = requireFunction(address, entry);
    if (!found.ok()) return error<SetFunctionLocalTypeResponse>(found);

    // Apply the retype to the decompiler scope on every slot (type-locked).
    Status retyped = localStatus(pool_->applyLocalRetypeAllSlots(entry, local_id, new_type),
                                 entry, local_id, new_type);
    if (!retyped.ok()) return error<SetFunctionLocalTypeResponse>(retyped);
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
    if (data.empty()) {
      return StatusOr<WriteBytesResponse>::FromError(codes::kInvalidArgument,
                                                     "data is required");
    }
    Status writable = requireWritable(address, data.size(), "");
    if (!writable.ok()) return error<WriteBytesResponse>(writable);

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
    if (patches.empty()) {
      return StatusOr<PatchBytesBatchResponse>::FromError(codes::kInvalidArgument,
                                                          "patches are required");
    }
    // Every patch or none: check them all before writing any.
    for (std::size_t i = 0; i < patches.size(); ++i) {
      if (patches[i].data.empty()) {
        return StatusOr<PatchBytesBatchResponse>::FromError(
            codes::kInvalidArgument, "patch " + std::to_string(i) + " has no data");
      }
      Status writable = requireWritable(patches[i].address, patches[i].data.size(),
                                        "patch " + std::to_string(i) + ": ");
      if (!writable.ok()) {
        return StatusOr<PatchBytesBatchResponse>::FromError(
            writable.code, writable.message + "; no patch was written");
      }
    }

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

  // -- IListingClient (bookmarks and breakpoints) -----------------------------
  //
  // The project's own bookmarks (and breakpoints, which the host keeps as
  // bookmarks of type "GhidraAPI Breakpoint"), read from the program db and
  // edited in memory.

  StatusOr<ListBookmarksResponse> ListBookmarks(std::uint64_t range_start,
                                                std::uint64_t range_end, int limit, int offset,
                                                const std::string& type_filter,
                                                const std::string& category_filter) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListBookmarksResponse>();
    const std::uint64_t end = range_end_of(range_end);
    const std::string type = trim(type_filter), category = trim(category_filter);
    std::vector<BookmarkRecord> all;
    for (const auto& b : pool_->primary().bookmarks()) {
      if (b.address < range_start || b.address > end) continue;
      if (!type.empty() && b.type != type) continue;
      if (!category.empty() && b.category != category) continue;
      all.push_back({b.address, b.type, b.category, b.comment});
    }
    ListBookmarksResponse resp;
    resp.bookmarks = paginate(all, limit, offset);
    return StatusOr<ListBookmarksResponse>::FromValue(std::move(resp));
  }

  StatusOr<AddBookmarkResponse> AddBookmark(std::uint64_t address, const std::string& type,
                                            const std::string& category,
                                            const std::string& comment) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<AddBookmarkResponse>();
    const std::string t = trim(type), c = trim(category);
    if (t.empty()) {
      return StatusOr<AddBookmarkResponse>::FromError(codes::kInvalidArgument,
                                                      "bookmark type is required");
    }
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<AddBookmarkResponse>(mapped);
    pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) {
      d.setBookmark(address, t, c, comment);
      return true;
    });
    revision_++;
    AddBookmarkResponse resp;
    resp.updated = true;
    return StatusOr<AddBookmarkResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteBookmarkResponse> DeleteBookmark(std::uint64_t address, const std::string& type,
                                                  const std::string& category) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteBookmarkResponse>();
    const std::string t = trim(type), c = trim(category);
    if (t.empty()) {
      return StatusOr<DeleteBookmarkResponse>::FromError(codes::kInvalidArgument,
                                                         "bookmark type is required");
    }
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<DeleteBookmarkResponse>(mapped);
    const bool removed = pool_->applyDecompilerMutationAllSlots(
        [&](ghidra_standalone::Decompiler& d) { return d.removeBookmark(address, t, c); });
    if (!removed) {
      return StatusOr<DeleteBookmarkResponse>::FromError(
          codes::kNotFound, "no '" + t + "' bookmark in category '" + c + "' at " + hex(address));
    }
    revision_++;
    DeleteBookmarkResponse resp;
    resp.deleted = true;
    return StatusOr<DeleteBookmarkResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListBreakpointsResponse> ListBreakpoints(std::uint64_t range_start,
                                                    std::uint64_t range_end, int limit, int offset,
                                                    const std::string& kind_filter,
                                                    const std::string& group_filter) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListBreakpointsResponse>();
    const std::uint64_t end = range_end_of(range_end);
    const std::string kind = lower(trim(kind_filter)), group = lower(trim(group_filter));
    std::vector<BreakpointRecord> all;
    for (const auto& b : pool_->primary().bookmarks()) {
      if (b.type != kBreakpointType) continue;
      BreakpointRecord row = breakpoint_from(b);
      if (row.address < range_start || row.address > end) continue;
      if (!kind.empty() && lower(trim(row.kind)) != kind) continue;
      if (!group.empty() && lower(trim(row.group)) != group) continue;
      all.push_back(std::move(row));
    }
    ListBreakpointsResponse resp;
    resp.breakpoints = paginate(all, limit, offset);
    return StatusOr<ListBreakpointsResponse>::FromValue(std::move(resp));
  }

  StatusOr<AddBreakpointResponse> AddBreakpoint(std::uint64_t address, const std::string& kind,
                                                std::uint64_t size, bool enabled,
                                                const std::string& condition,
                                                const std::string& group) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<AddBreakpointResponse>();
    BreakpointRecord row;
    row.kind = trim(kind).empty() ? "software" : trim(kind);
    if (!breakpoint_kind_ok(row.kind)) {
      return StatusOr<AddBreakpointResponse>::FromError(
          codes::kInvalidArgument, "unknown breakpoint kind '" + row.kind +
                                       "'; expected one of software, hardware, read, write, access");
    }
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<AddBreakpointResponse>(mapped);
    row.address = address;
    row.enabled = enabled;
    row.size = std::max<std::uint64_t>(1, size);
    row.condition = condition;
    row.group = trim(group);
    putBreakpoint(row);
    revision_++;
    AddBreakpointResponse resp;
    resp.updated = true;
    return StatusOr<AddBreakpointResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetBreakpointEnabledResponse> SetBreakpointEnabled(std::uint64_t address,
                                                              bool enabled) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetBreakpointEnabledResponse>();
    Status edited = editBreakpoint(address, [&](BreakpointRecord& r) { r.enabled = enabled; });
    if (!edited.ok()) return error<SetBreakpointEnabledResponse>(edited);
    SetBreakpointEnabledResponse resp;
    resp.updated = true;
    return StatusOr<SetBreakpointEnabledResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetBreakpointKindResponse> SetBreakpointKind(std::uint64_t address,
                                                        const std::string& kind) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetBreakpointKindResponse>();
    const std::string k = trim(kind);
    if (k.empty()) {
      return StatusOr<SetBreakpointKindResponse>::FromError(codes::kInvalidArgument,
                                                            "breakpoint kind is required");
    }
    if (!breakpoint_kind_ok(k)) {
      return StatusOr<SetBreakpointKindResponse>::FromError(
          codes::kInvalidArgument, "unknown breakpoint kind '" + k +
                                       "'; expected one of software, hardware, read, write, access");
    }
    Status edited = editBreakpoint(address, [&](BreakpointRecord& r) { r.kind = k; });
    if (!edited.ok()) return error<SetBreakpointKindResponse>(edited);
    SetBreakpointKindResponse resp;
    resp.updated = true;
    return StatusOr<SetBreakpointKindResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetBreakpointSizeResponse> SetBreakpointSize(std::uint64_t address,
                                                        std::uint64_t size) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetBreakpointSizeResponse>();
    if (size == 0) {
      return StatusOr<SetBreakpointSizeResponse>::FromError(codes::kInvalidArgument,
                                                            "breakpoint size must be > 0");
    }
    Status edited = editBreakpoint(address, [&](BreakpointRecord& r) { r.size = size; });
    if (!edited.ok()) return error<SetBreakpointSizeResponse>(edited);
    SetBreakpointSizeResponse resp;
    resp.updated = true;
    return StatusOr<SetBreakpointSizeResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetBreakpointConditionResponse> SetBreakpointCondition(
      std::uint64_t address, const std::string& condition) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetBreakpointConditionResponse>();
    Status edited = editBreakpoint(address, [&](BreakpointRecord& r) { r.condition = condition; });
    if (!edited.ok()) return error<SetBreakpointConditionResponse>(edited);
    SetBreakpointConditionResponse resp;
    resp.updated = true;
    return StatusOr<SetBreakpointConditionResponse>::FromValue(std::move(resp));
  }

  StatusOr<SetBreakpointGroupResponse> SetBreakpointGroup(std::uint64_t address,
                                                          const std::string& group) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<SetBreakpointGroupResponse>();
    Status edited = editBreakpoint(address, [&](BreakpointRecord& r) { r.group = trim(group); });
    if (!edited.ok()) return error<SetBreakpointGroupResponse>(edited);
    SetBreakpointGroupResponse resp;
    resp.updated = true;
    return StatusOr<SetBreakpointGroupResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteBreakpointResponse> DeleteBreakpoint(std::uint64_t address) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteBreakpointResponse>();
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return error<DeleteBreakpointResponse>(mapped);
    const bool removed = pool_->applyDecompilerMutationAllSlots(
        [&](ghidra_standalone::Decompiler& d) { return d.removeBookmarks(address, kBreakpointType); });
    if (!removed) {
      return StatusOr<DeleteBreakpointResponse>::FromError(codes::kNotFound,
                                                           "no breakpoint at " + hex(address));
    }
    revision_++;
    DeleteBreakpointResponse resp;
    resp.deleted = true;
    return StatusOr<DeleteBreakpointResponse>::FromValue(std::move(resp));
  }

  // -- IFunctionsClient (function tags) ------------------------------------------

  StatusOr<ListFunctionTagsResponse> ListFunctionTags() override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListFunctionTagsResponse>();
    ListFunctionTagsResponse resp;
    for (const auto& t : pool_->primary().functionTags()) resp.tags.push_back({t.name, t.comment});
    return StatusOr<ListFunctionTagsResponse>::FromValue(std::move(resp));
  }

  StatusOr<CreateFunctionTagResponse> CreateFunctionTag(const std::string& name,
                                                        const std::string& comment) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<CreateFunctionTagResponse>();
    const std::string n = trim(name);
    if (n.empty()) {
      return StatusOr<CreateFunctionTagResponse>::FromError(codes::kInvalidArgument,
                                                            "tag name is required");
    }
    if (pool_->primary().hasFunctionTag(n)) {
      return StatusOr<CreateFunctionTagResponse>::FromError(
          codes::kDuplicateName, "function tag '" + n + "' already exists");
    }
    pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) {
      d.createFunctionTag(n, comment);
      return true;
    });
    revision_++;
    CreateFunctionTagResponse resp;
    resp.created = true;
    return StatusOr<CreateFunctionTagResponse>::FromValue(std::move(resp));
  }

  StatusOr<DeleteFunctionTagResponse> DeleteFunctionTag(const std::string& name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<DeleteFunctionTagResponse>();
    const std::string n = trim(name);
    if (n.empty()) {
      return StatusOr<DeleteFunctionTagResponse>::FromError(codes::kInvalidArgument,
                                                            "tag name is required");
    }
    const bool removed = pool_->applyDecompilerMutationAllSlots(
        [&](ghidra_standalone::Decompiler& d) { return d.deleteFunctionTag(n); });
    if (!removed) {
      return StatusOr<DeleteFunctionTagResponse>::FromError(codes::kNotFound,
                                                            "no function tag named '" + n + "'");
    }
    revision_++;
    DeleteFunctionTagResponse resp;
    resp.deleted = true;
    return StatusOr<DeleteFunctionTagResponse>::FromValue(std::move(resp));
  }

  StatusOr<ListFunctionTagMappingsResponse> ListFunctionTagMappings(
      std::uint64_t function_entry) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<ListFunctionTagMappingsResponse>();
    ListFunctionTagMappingsResponse resp;
    for (const auto& [entry, tag] : pool_->primary().functionTagMappings(function_entry))
      resp.mappings.push_back({entry, tag});
    return StatusOr<ListFunctionTagMappingsResponse>::FromValue(std::move(resp));
  }

  // Tags the function at, or containing, the address; a missing tag is created.
  StatusOr<TagFunctionResponse> TagFunction(std::uint64_t function_entry,
                                            const std::string& tag_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<TagFunctionResponse>();
    const std::string n = trim(tag_name);
    if (n.empty()) {
      return StatusOr<TagFunctionResponse>::FromError(codes::kInvalidArgument,
                                                      "tag name is required");
    }
    std::uint64_t entry = 0;
    Status found = requireFunction(function_entry, entry);
    if (!found.ok()) return error<TagFunctionResponse>(found);
    pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) {
      d.tagFunction(entry, n);
      return true;
    });
    revision_++;
    TagFunctionResponse resp;
    resp.updated = true;
    return StatusOr<TagFunctionResponse>::FromValue(std::move(resp));
  }

  StatusOr<UntagFunctionResponse> UntagFunction(std::uint64_t function_entry,
                                                const std::string& tag_name) override {
    std::lock_guard<std::mutex> req_lock(req_mu_);
    if (!ensure_loaded()) return not_loaded<UntagFunctionResponse>();
    const std::string n = trim(tag_name);
    if (n.empty()) {
      return StatusOr<UntagFunctionResponse>::FromError(codes::kInvalidArgument,
                                                        "tag name is required");
    }
    std::uint64_t entry = 0;
    Status found = requireFunction(function_entry, entry);
    if (!found.ok()) return error<UntagFunctionResponse>(found);
    if (!pool_->primary().hasFunctionTag(n)) {
      return StatusOr<UntagFunctionResponse>::FromError(codes::kNotFound,
                                                        "no function tag named '" + n + "'");
    }
    if (!pool_->primary().functionHasTag(entry, n)) {
      return StatusOr<UntagFunctionResponse>::FromError(
          codes::kNotFound, "tag '" + n + "' is not applied to the function at " + hex(entry));
    }
    pool_->applyDecompilerMutationAllSlots(
        [&](ghidra_standalone::Decompiler& d) { return d.untagFunction(entry, n); });
    revision_++;
    UntagFunctionResponse resp;
    resp.updated = true;
    return StatusOr<UntagFunctionResponse>::FromValue(std::move(resp));
  }

 private:
  /// Replace the breakpoint at row.address (BreakpointBookmarkStore.upsert).
  void putBreakpoint(const BreakpointRecord& row) {
    pool_->applyDecompilerMutationAllSlots([&](ghidra_standalone::Decompiler& d) {
      d.removeBookmarks(row.address, kBreakpointType);
      d.setBookmark(row.address, kBreakpointType, breakpoint_category(row.group),
                    breakpoint_comment(row));
      return true;
    });
  }

  /// Edit the breakpoint at a mapped address; not_found when there is none.
  Status editBreakpoint(std::uint64_t address, const std::function<void(BreakpointRecord&)>& edit) {
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return mapped;
    for (const auto& b : pool_->primary().bookmarks()) {
      if (b.type != kBreakpointType || b.address != address) continue;
      BreakpointRecord row = breakpoint_from(b);
      row.address = address;
      edit(row);
      putBreakpoint(row);
      revision_++;
      return Status::Ok();
    }
    return Status::Error(codes::kNotFound, "no breakpoint at " + hex(address));
  }

  bool ensure_loaded() const {
    return program_loaded_ && pool_ && pool_->primaryAdapter().valid();
  }

  template <typename T>
  StatusOr<T> not_loaded() const {
    return StatusOr<T>::FromError(codes::kNotLoaded, "no program loaded; call OpenProgram first");
  }

  template <typename T>
  static StatusOr<T> error(const Status& status) {
    return StatusOr<T>::FromError(status.code, status.message);
  }

  /// Load `request`'s program into every pool slot (OpenProgram and
  /// DiscardProgram), then the configured state file.
  Status loadLocked(const OpenProgramRequest& request) {
    namespace fs = std::filesystem;
    if (!request.project_path.empty()) {
      std::error_code ec;
      if (!fs::exists(request.project_path, ec)) {
        return Status::Error(codes::kNotFound, "no project at " + request.project_path);
      }
      // The project's program the request names (program_path), or its only one.
      if (!pool_->loadProject(request.project_path, request.program_path)) {
        return Status::Error(engine_code(pool_->getErrorKind()), pool_->getError());
      }
    } else if (!request.program_path.empty()) {
      std::error_code ec;
      if (!fs::exists(request.program_path, ec)) {
        return Status::Error(codes::kNotFound, "no file at " + request.program_path);
      }
      // Always pass the full Sleigh spec id ("processor:endian:size:variant:
      // compiler") so the language is unambiguous: Ghidra's
      // BfdArchitecture::resolveArchitecture maps every elf64 to
      // x86:LE:64:default:gcc, so letting BFD auto-detect loaded an aarch64 ELF
      // as x86. The patched bfd_arch.cc::buildLoader sees a colon-bearing target
      // and lets bfd_check_format detect the file format while archid keeps
      // the Sleigh id; raw_arch (no BFD on macOS/Windows) needs exactly that id.
      std::string arch;
      if (request.language_id.empty()) {
        arch = opts_.default_arch;
      } else if (!request.compiler_spec_id.empty()) {
        arch = request.language_id + ":" + request.compiler_spec_id;
      } else {
        arch = request.language_id;
      }
      if (!pool_->loadBinary(request.program_path, arch, request.base_address,
                             request.format)) {
        return Status::Error(codes::kInvalidArgument,
                             "cannot load " + request.program_path + ": " + pool_->getError());
      }
    } else {
      return Status::Error(codes::kInvalidArgument, "program_path or project_path required");
    }
    // Auto-load state if configured and file exists (best-effort, primary only)
    if (!opts_.state_path.empty()) {
      pool_->loadState(opts_.state_path);
    }
    return Status::Ok();
  }

  /// `address` lies in the program's memory (unmapped_address otherwise).
  Status requireMapped(std::uint64_t address) {
    if (!pool_->primaryAdapter().isMapped(address)) {
      return Status::Error(codes::kUnmappedAddress, "no memory block contains " + hex(address));
    }
    return Status::Ok();
  }

  /// The function a function-scoped write acts on: the one that starts at, or
  /// contains, `address` -- the rule the reads use. unmapped_address when
  /// no block contains it, not_found when no function does. Never creates one.
  Status requireFunction(std::uint64_t address, std::uint64_t& entry) {
    Status mapped = requireMapped(address);
    if (!mapped.ok()) return mapped;
    const std::optional<std::uint64_t> found =
        pool_->primaryAdapter().functionEntryFor(address);
    if (!found) return Status::Error(codes::kNotFound, "no function at " + hex(address));
    entry = *found;
    return Status::Ok();
  }

  /// requireFunction, then a parameter `ordinal` of its signature.
  Status requireParameter(std::uint64_t address, int ordinal, std::uint64_t& entry) {
    Status found = requireFunction(address, entry);
    if (!found.ok()) return found;
    if (ordinal < 0) {
      return Status::Error(codes::kInvalidArgument, "parameter ordinal must be >= 0");
    }
    auto sig = pool_->primaryAdapter().getFunctionSignature(entry);
    const std::size_t count = sig ? sig->parameters.size() : 0;
    if (static_cast<std::size_t>(ordinal) >= count) {
      return Status::Error(codes::kNotFound,
                           "function " + (sig ? sig->function_name : hex(entry)) +
                               " has no parameter " + std::to_string(ordinal) + " (it has " +
                               std::to_string(count) + ")");
    }
    return Status::Ok();
  }

  /// `length` bytes from `address` can be written.
  Status requireWritable(std::uint64_t address, std::uint64_t length, const std::string& what) {
    switch (pool_->primaryAdapter().checkWritable(address, length)) {
      case RangeStatus::kOk:
        return Status::Ok();
      case RangeStatus::kUnmapped:
        return Status::Error(codes::kUnmappedAddress,
                             what + "no memory block contains " + hex(address));
      case RangeStatus::kPastMapped:
        return Status::Error(codes::kAccessConflict,
                             what + "the write at " + hex(address) + " runs past mapped memory");
      case RangeStatus::kUninitialized:
        return Status::Error(codes::kAccessConflict,
                             what + "the write at " + hex(address) +
                                 " reaches a block that holds no bytes");
      case RangeStatus::kUnavailable:
        return Status::Error(codes::kNotSupported,
                             what + "the offline image holds no bytes at " + hex(address));
    }
    return Status::Error(codes::kInternalError, what + "unknown range status");
  }

  /// A name a new type may take (duplicate_name otherwise).
  Status requireNewTypeName(const std::string& name) {
    if (pool_->primaryAdapter().typeNameTaken(name)) {
      return Status::Error(codes::kDuplicateName, "a type named '" + name + "' already exists");
    }
    return Status::Ok();
  }

  /// Run an engine write on every slot; the primary slot's failure decides the code.
  Status decompilerWrite(const std::function<bool(ghidra_standalone::Decompiler&)>& apply) {
    if (pool_->applyDecompilerMutationAllSlots(apply)) return Status::Ok();
    if (pool_->getErrorKind() == EngineError::kNone) {
      return Status::Error(codes::kInternalError, "the write did not apply on every decompiler slot");
    }
    return Status::Error(engine_code(pool_->getErrorKind()), pool_->getError());
  }

  /// Run an adapter write on every slot. Slot 0 runs first and validates; a
  /// refusal there leaves every slot untouched (they hold the same state).
  Status adapterWrite(const std::function<WriteStatus(detail::ArchAdapter&)>& apply) {
    std::optional<WriteStatus> first;
    const bool all = pool_->applyMutationAllSlots([&](detail::ArchAdapter& a) {
      WriteStatus st = apply(a);
      if (!first) first = st;
      return st.ok();
    });
    if (!first) return Status::Error(codes::kInternalError, "no decompiler slot");
    if (!first->ok()) return Status::Error(first->code, first->message);
    if (!all) {
      return Status::Error(codes::kInternalError, "the write did not apply on every decompiler slot");
    }
    return Status::Ok();
  }

  /// The vocabulary answer for a local rename/retype.
  static Status localStatus(detail::LocalMutationStatus status, std::uint64_t entry,
                            const std::string& local_id, const std::string& new_type) {
    switch (status) {
      case detail::LocalMutationStatus::kOk:
        return Status::Ok();
      case detail::LocalMutationStatus::kNotFound:
        return Status::Error(codes::kNotFound, "no local matching id '" + local_id +
                                                   "' in function at " + hex(entry));
      case detail::LocalMutationStatus::kInvalidType:
        return Status::Error(codes::kUnknownType, "unknown data type '" + new_type + "'");
      case detail::LocalMutationStatus::kRetypeRejected:
        return Status::Error(
            codes::kInvalidArgument,
            "the decompiler cannot retype local '" + local_id + "' to '" + new_type +
                "': its size can only change when it is a single fixed storage "
                "location (a stack slot), not a register temporary");
      case detail::LocalMutationStatus::kDecompileFailed:
        return Status::Error(codes::kInternalError,
                             "could not decompile the function at " + hex(entry));
    }
    return Status::Error(codes::kInternalError, "unknown local mutation status");
  }

  /// Non-locking body of CloseProgram(). The caller MUST already hold req_mu_.
  /// Extracted so Shutdown() (which holds the lock) can close the program
  /// without re-entering the non-recursive req_mu_ (which would self-deadlock).
  StatusOr<CloseProgramResponse> closeProgramLocked(ShutdownPolicy policy) {
    if (!program_loaded_) {
      return StatusOr<CloseProgramResponse>::FromError(codes::kNotLoaded,
                                                       "no program loaded");
    }

    const bool should_save = policy == ShutdownPolicy::kSave;
    if (should_save && !opts_.state_path.empty() &&
        !pool_->saveState(opts_.state_path)) {
      return StatusOr<CloseProgramResponse>::FromError(codes::kInternalError,
                                                       pool_->getError());
    }

    pool_->resetAdapters();
    program_loaded_ = false;
    perf_benchmarks_.clear();

    CloseProgramResponse resp;
    resp.closed = true;
    return StatusOr<CloseProgramResponse>::FromValue(std::move(resp));
  }

  LocalClientOptions opts_;
  std::unique_ptr<detail::DecompilerPool> pool_;
  bool program_loaded_ = false;
  // What OpenProgram loaded, for DiscardProgram to load again.
  OpenProgramRequest open_request_;
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
