// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "libghidra/http.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <google/protobuf/any.pb.h>

#include <httplib.h>

#include "libghidra/common.pb.h"
#include "libghidra/decompiler.pb.h"
#include "libghidra/functions.pb.h"
#include "libghidra/health.pb.h"
#include "libghidra/listing.pb.h"
#include "libghidra/memory.pb.h"
#include "libghidra/rpc.pb.h"
#include "libghidra/session.pb.h"
#include "libghidra/symbols.pb.h"
#include "libghidra/types.pb.h"
#include "libghidra/xrefs.pb.h"

namespace libghidra::client {

namespace {

struct ParsedBaseUrl {
  std::string host;
  int port = 80;
};

std::string trim(std::string s) {
  auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
  s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
  return s;
}

StatusOr<ParsedBaseUrl> parse_base_url(const std::string& base_url) {
  std::string raw = trim(base_url);
  if (raw.empty()) {
    return StatusOr<ParsedBaseUrl>::FromError("config_error", "base_url is empty");
  }

  if (raw.rfind("http://", 0) == 0) {
    raw.erase(0, std::strlen("http://"));
  } else if (raw.rfind("https://", 0) == 0) {
    return StatusOr<ParsedBaseUrl>::FromError(
        "config_error",
        "https base_url is not supported in bootstrap HTTP transport");
  }

  const std::size_t slash = raw.find('/');
  if (slash != std::string::npos && slash + 1 < raw.size()) {
    return StatusOr<ParsedBaseUrl>::FromError(
        "config_error",
        "base_url must not include a path segment");
  }
  if (slash != std::string::npos) {
    raw = raw.substr(0, slash);
  }

  ParsedBaseUrl parsed;
  const std::size_t colon = raw.rfind(':');
  if (colon == std::string::npos) {
    parsed.host = raw;
    parsed.port = 80;
  } else {
    parsed.host = raw.substr(0, colon);
    const std::string port_text = raw.substr(colon + 1);
    int port = 0;
    const auto begin = port_text.data();
    const auto end = port_text.data() + port_text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, port);
    if (ec != std::errc() || ptr != end || port <= 0 || port > 65535) {
      return StatusOr<ParsedBaseUrl>::FromError(
          "config_error",
          "invalid port in base_url: " + port_text);
    }
    parsed.port = port;
  }

  if (parsed.host.empty()) {
    return StatusOr<ParsedBaseUrl>::FromError("config_error", "base_url host is empty");
  }
  return StatusOr<ParsedBaseUrl>::FromValue(std::move(parsed));
}

std::pair<time_t, time_t> to_sec_usec(std::chrono::milliseconds ms) {
  if (ms.count() < 0) {
    ms = std::chrono::milliseconds(0);
  }
  const auto sec = std::chrono::duration_cast<std::chrono::seconds>(ms);
  const auto usec = std::chrono::duration_cast<std::chrono::microseconds>(ms - sec);
  return {static_cast<time_t>(sec.count()), static_cast<time_t>(usec.count())};
}

libghidra::ShutdownPolicy to_proto_shutdown_policy(ShutdownPolicy policy) {
  switch (policy) {
    case ShutdownPolicy::kSave:
      return libghidra::SHUTDOWN_POLICY_SAVE;
    case ShutdownPolicy::kDiscard:
      return libghidra::SHUTDOWN_POLICY_DISCARD;
    case ShutdownPolicy::kNone:
      return libghidra::SHUTDOWN_POLICY_NONE;
    case ShutdownPolicy::kUnspecified:
    default:
      return libghidra::SHUTDOWN_POLICY_UNSPECIFIED;
  }
}

libghidra::CommentKind to_proto_comment_kind(CommentKind kind) {
  switch (kind) {
    case CommentKind::kEol:
      return libghidra::COMMENT_KIND_EOL;
    case CommentKind::kPre:
      return libghidra::COMMENT_KIND_PRE;
    case CommentKind::kPost:
      return libghidra::COMMENT_KIND_POST;
    case CommentKind::kPlate:
      return libghidra::COMMENT_KIND_PLATE;
    case CommentKind::kRepeatable:
      return libghidra::COMMENT_KIND_REPEATABLE;
    case CommentKind::kUnspecified:
    default:
      return libghidra::COMMENT_KIND_UNSPECIFIED;
  }
}

CommentKind from_proto_comment_kind(libghidra::CommentKind kind) {
  switch (kind) {
    case libghidra::COMMENT_KIND_EOL:
      return CommentKind::kEol;
    case libghidra::COMMENT_KIND_PRE:
      return CommentKind::kPre;
    case libghidra::COMMENT_KIND_POST:
      return CommentKind::kPost;
    case libghidra::COMMENT_KIND_PLATE:
      return CommentKind::kPlate;
    case libghidra::COMMENT_KIND_REPEATABLE:
      return CommentKind::kRepeatable;
    case libghidra::COMMENT_KIND_UNSPECIFIED:
    default:
      return CommentKind::kUnspecified;
  }
}

TypeRecord from_proto_type_record(const libghidra::TypeRecord& row) {
  TypeRecord out;
  out.type_id = row.type_id();
  out.name = row.name();
  out.path_name = row.path_name();
  out.category_path = row.category_path();
  out.display_name = row.display_name();
  out.kind = row.kind();
  out.length = row.length();
  out.is_not_yet_defined = row.is_not_yet_defined();
  out.source_archive = row.source_archive();
  out.universal_id = row.universal_id();
  return out;
}

TypeAliasRecord from_proto_type_alias_record(const libghidra::TypeAliasRecord& row) {
  TypeAliasRecord out;
  out.type_id = row.type_id();
  out.path_name = row.path_name();
  out.name = row.name();
  out.target_type = row.target_type();
  out.declaration = row.declaration();
  return out;
}

TypeUnionRecord from_proto_type_union_record(const libghidra::TypeUnionRecord& row) {
  TypeUnionRecord out;
  out.type_id = row.type_id();
  out.path_name = row.path_name();
  out.name = row.name();
  out.size = row.size();
  out.declaration = row.declaration();
  return out;
}

TypeEnumRecord from_proto_type_enum_record(const libghidra::TypeEnumRecord& row) {
  TypeEnumRecord out;
  out.type_id = row.type_id();
  out.path_name = row.path_name();
  out.name = row.name();
  out.width = row.width();
  out.is_signed = row.signed_();
  out.declaration = row.declaration();
  return out;
}

TypeEnumMemberRecord from_proto_type_enum_member_record(
    const libghidra::TypeEnumMemberRecord& row) {
  TypeEnumMemberRecord out;
  out.type_id = row.type_id();
  out.type_path_name = row.type_path_name();
  out.type_name = row.type_name();
  out.ordinal = row.ordinal();
  out.name = row.name();
  out.value = row.value();
  out.comment = row.comment();
  return out;
}

TypeMemberRecord from_proto_type_member_record(const libghidra::TypeMemberRecord& row) {
  TypeMemberRecord out;
  out.parent_type_id = row.parent_type_id();
  out.parent_type_path_name = row.parent_type_path_name();
  out.parent_type_name = row.parent_type_name();
  out.ordinal = row.ordinal();
  out.name = row.name();
  out.member_type = row.member_type();
  out.offset = row.offset();
  out.size = row.size();
  out.comment = row.comment();
  return out;
}

ParameterRecord from_proto_parameter_record(const libghidra::ParameterRecord& row) {
  ParameterRecord out;
  out.ordinal = row.ordinal();
  out.name = row.name();
  out.data_type = row.data_type();
  out.formal_data_type = row.formal_data_type();
  out.is_auto_parameter = row.is_auto_parameter();
  out.is_forced_indirect = row.is_forced_indirect();
  return out;
}

FunctionSignatureRecord from_proto_signature_record(const libghidra::FunctionSignatureRecord& row) {
  FunctionSignatureRecord out;
  out.function_entry_address = row.function_entry_address();
  out.function_name = row.function_name();
  out.prototype = row.prototype();
  out.return_type = row.return_type();
  out.has_var_args = row.has_var_args();
  out.calling_convention = row.calling_convention();
  out.parameters.reserve(static_cast<std::size_t>(row.parameters_size()));
  for (const auto& param : row.parameters()) {
    out.parameters.push_back(from_proto_parameter_record(param));
  }
  return out;
}

FunctionRecord from_proto_function_record(const libghidra::FunctionRecord& row) {
  FunctionRecord out;
  out.entry_address = row.entry_address();
  out.name = row.name();
  out.start_address = row.start_address();
  out.end_address = row.end_address();
  out.size = row.size();
  out.namespace_name = row.namespace_name();
  out.prototype = row.prototype();
  out.is_thunk = row.is_thunk();
  out.parameter_count = row.parameter_count();
  return out;
}

SymbolRecord from_proto_symbol_record(const libghidra::SymbolRecord& row) {
  SymbolRecord out;
  out.symbol_id = row.symbol_id();
  out.address = row.address();
  out.name = row.name();
  out.full_name = row.full_name();
  out.type = row.type();
  out.namespace_name = row.namespace_name();
  out.source = row.source();
  out.is_primary = row.is_primary();
  out.is_external = row.is_external();
  out.is_dynamic = row.is_dynamic();
  return out;
}

XrefRecord from_proto_xref_record(const libghidra::XrefRecord& row) {
  XrefRecord out;
  out.from_address = row.from_address();
  out.to_address = row.to_address();
  out.operand_index = row.operand_index();
  out.ref_type = row.ref_type();
  out.is_primary = row.is_primary();
  out.source = row.source();
  out.symbol_id = row.symbol_id();
  out.is_external = row.is_external();
  out.is_memory = row.is_memory();
  out.is_flow = row.is_flow();
  return out;
}

DecompilationRecord from_proto_decompilation_record(const libghidra::DecompileRecord& row) {
  DecompilationRecord out;
  out.function_entry_address = row.function_entry_address();
  out.function_name = row.function_name();
  out.prototype = row.prototype();
  out.pseudocode = row.pseudocode();
  out.completed = row.completed();
  out.is_fallback = row.is_fallback();
  out.error_message = row.error_message();
  out.locals.reserve(static_cast<std::size_t>(row.locals_size()));
  for (const auto& local : row.locals()) {
    DecompileLocalRecord mapped;
    mapped.local_id = local.local_id();
    switch (local.kind()) {
      case libghidra::DECOMPILE_LOCAL_KIND_PARAM:
        mapped.kind = DecompileLocalKind::kParam;
        break;
      case libghidra::DECOMPILE_LOCAL_KIND_LOCAL:
        mapped.kind = DecompileLocalKind::kLocal;
        break;
      case libghidra::DECOMPILE_LOCAL_KIND_TEMP:
        mapped.kind = DecompileLocalKind::kTemp;
        break;
      case libghidra::DECOMPILE_LOCAL_KIND_UNSPECIFIED:
      default:
        mapped.kind = DecompileLocalKind::kUnspecified;
        break;
    }
    mapped.name = local.name();
    mapped.data_type = local.data_type();
    mapped.storage = local.storage();
    mapped.ordinal = local.ordinal();
    out.locals.push_back(std::move(mapped));
  }
  out.tokens.reserve(static_cast<std::size_t>(row.tokens_size()));
  for (const auto& token : row.tokens()) {
    DecompileTokenRecord mapped;
    mapped.text = token.text();
    switch (token.kind()) {
      case libghidra::DECOMPILE_TOKEN_KIND_KEYWORD:
        mapped.kind = DecompileTokenKind::kKeyword; break;
      case libghidra::DECOMPILE_TOKEN_KIND_COMMENT:
        mapped.kind = DecompileTokenKind::kComment; break;
      case libghidra::DECOMPILE_TOKEN_KIND_TYPE:
        mapped.kind = DecompileTokenKind::kType; break;
      case libghidra::DECOMPILE_TOKEN_KIND_FUNCTION:
        mapped.kind = DecompileTokenKind::kFunction; break;
      case libghidra::DECOMPILE_TOKEN_KIND_VARIABLE:
        mapped.kind = DecompileTokenKind::kVariable; break;
      case libghidra::DECOMPILE_TOKEN_KIND_CONST:
        mapped.kind = DecompileTokenKind::kConst; break;
      case libghidra::DECOMPILE_TOKEN_KIND_PARAMETER:
        mapped.kind = DecompileTokenKind::kParameter; break;
      case libghidra::DECOMPILE_TOKEN_KIND_GLOBAL:
        mapped.kind = DecompileTokenKind::kGlobal; break;
      case libghidra::DECOMPILE_TOKEN_KIND_DEFAULT:
        mapped.kind = DecompileTokenKind::kDefault; break;
      case libghidra::DECOMPILE_TOKEN_KIND_ERROR:
        mapped.kind = DecompileTokenKind::kError; break;
      case libghidra::DECOMPILE_TOKEN_KIND_SPECIAL:
        mapped.kind = DecompileTokenKind::kSpecial; break;
      case libghidra::DECOMPILE_TOKEN_KIND_UNSPECIFIED:
      default:
        mapped.kind = DecompileTokenKind::kUnspecified; break;
    }
    mapped.line_number = token.line_number();
    mapped.column_offset = token.column_offset();
    mapped.var_name = token.var_name();
    mapped.var_type = token.var_type();
    mapped.var_storage = token.var_storage();
    out.tokens.push_back(std::move(mapped));
  }
  return out;
}

InstructionRecord from_proto_instruction_record(const libghidra::InstructionRecord& row) {
  InstructionRecord out;
  out.address = row.address();
  out.mnemonic = row.mnemonic();
  out.operand_text = row.operand_text();
  out.disassembly = row.disassembly();
  out.length = row.length();
  return out;
}

CommentRecord from_proto_comment_record(const libghidra::CommentRecord& row) {
  CommentRecord out;
  out.address = row.address();
  out.kind = from_proto_comment_kind(row.kind());
  out.text = row.text();
  return out;
}

DataItemRecord from_proto_data_item_record(const libghidra::DataItemRecord& row) {
  DataItemRecord out;
  out.address = row.address();
  out.end_address = row.end_address();
  out.name = row.name();
  out.data_type = row.data_type();
  out.size = row.size();
  out.value_repr = row.value_repr();
  return out;
}

BookmarkRecord from_proto_bookmark_record(const libghidra::BookmarkRecord& row) {
  BookmarkRecord out;
  out.address = row.address();
  out.type = row.type();
  out.category = row.category();
  out.comment = row.comment();
  return out;
}

BreakpointRecord from_proto_breakpoint_record(const libghidra::BreakpointRecord& row) {
  BreakpointRecord out;
  out.address = row.address();
  out.enabled = row.enabled();
  out.kind = row.kind();
  out.size = row.size();
  out.condition = row.condition();
  out.group = row.group();
  return out;
}

std::string map_http_status(int status) {
  switch (status) {
    case 400: return "bad_request";
    case 401: return "unauthorized";
    case 403: return "forbidden";
    case 404: return "not_found";
    case 409: return "conflict";
    case 429: return "too_many_requests";
    case 500: return "internal_error";
    case 502: return "bad_gateway";
    case 503: return "service_unavailable";
    case 504: return "gateway_timeout";
    default:  return "http_error";
  }
}

std::string map_transport_error(httplib::Error err) {
  switch (err) {
    case httplib::Error::Connection:
      return "connection_failed";
    case httplib::Error::ConnectionTimeout:
    case httplib::Error::Read:
    case httplib::Error::Write:
      return "timeout";
    default:
      return "transport_error";
  }
}

bool is_retryable(const std::string& code) {
  return code == "connection_failed" ||
         code == "timeout" ||
         code == "too_many_requests" ||
         code == "internal_error" ||
         code == "bad_gateway" ||
         code == "service_unavailable" ||
         code == "gateway_timeout";
}

std::chrono::milliseconds compute_backoff(int attempt,
                                          std::chrono::milliseconds initial,
                                          std::chrono::milliseconds max_backoff,
                                          bool jitter) {
  auto base = initial * (1 << attempt);
  if (base > max_backoff) base = max_backoff;
  if (jitter) {
    thread_local std::mt19937 rng{std::random_device{}()};
    auto lo = base * 3 / 4;
    auto hi = base * 5 / 4;
    std::uniform_int_distribution<long long> dist(lo.count(), hi.count());
    base = std::chrono::milliseconds(dist(rng));
    if (base > max_backoff) base = max_backoff;
  }
  return base;
}

}  // namespace

class HttpClient::Impl {
 public:
  explicit Impl(HttpClientOptions options) : options_(std::move(options)) {}

  Status init() {
    auto parsed = parse_base_url(options_.base_url);
    if (!parsed.ok()) {
      return parsed.status;
    }

    host_ = parsed.value->host;
    port_ = parsed.value->port;
    client_ = std::make_unique<httplib::Client>(host_, port_);
    auto [csec, cusec] = to_sec_usec(options_.connect_timeout);
    auto [rsec, rusec] = to_sec_usec(options_.read_timeout);
    auto [wsec, wusec] = to_sec_usec(options_.write_timeout);
    client_->set_connection_timeout(csec, cusec);
    client_->set_read_timeout(rsec, rusec);
    client_->set_write_timeout(wsec, wusec);
    return Status::Ok();
  }

  template <typename TRequest, typename TResponse>
  StatusOr<TResponse> call_rpc(const std::string& method, const TRequest& request) {
    libghidra::RpcRequest rpc_request;
    rpc_request.set_method(method);
    rpc_request.mutable_payload()->PackFrom(request);
    std::string encoded;
    if (!rpc_request.SerializeToString(&encoded)) {
      return StatusOr<TResponse>::FromError("encode_error", "failed to encode RpcRequest");
    }

    const int max_attempts = options_.max_retries + 1;
    StatusOr<std::string> raw;
    for (int attempt = 0; attempt < max_attempts; ++attempt) {
      raw = request_bytes("POST", "/rpc", encoded, "application/x-protobuf");
      if (raw.ok() || !is_retryable(raw.status.code) || attempt + 1 >= max_attempts) {
        break;
      }
      std::this_thread::sleep_for(compute_backoff(
          attempt, options_.initial_backoff, options_.max_backoff, options_.jitter));
    }
    if (!raw.ok()) {
      return StatusOr<TResponse>::FromError(raw.status.code, raw.status.message);
    }

    libghidra::RpcResponse rpc_response;
    if (!rpc_response.ParseFromString(raw.value.value())) {
      return StatusOr<TResponse>::FromError("parse_error", "failed to parse RpcResponse");
    }
    if (!rpc_response.success()) {
      const std::string message =
          rpc_response.error_message().empty() ? "RPC returned success=false"
                                               : rpc_response.error_message();
      return StatusOr<TResponse>::FromError(
          rpc_response.error_code().empty() ? "api_error" : rpc_response.error_code(),
          message);
    }
    TResponse response;
    if (rpc_response.has_payload() && !rpc_response.payload().UnpackTo(&response)) {
      return StatusOr<TResponse>::FromError(
          "parse_error",
          "failed to unpack RPC payload for method " + method);
    }
    return StatusOr<TResponse>::FromValue(std::move(response));
  }

 private:
  StatusOr<std::string> request_bytes(const std::string& method,
                                      const std::string& path,
                                      const std::string& body,
                                      const std::string& content_type) {
    if (!client_) {
      return StatusOr<std::string>::FromError("config_error", "HTTP client is not initialized");
    }

    httplib::Headers headers;
    if (!options_.auth_token.empty()) {
      headers.emplace("Authorization", "Bearer " + options_.auth_token);
    }

    httplib::Result result;
    if (method == "GET") {
      result = client_->Get(path.c_str(), headers);
    } else {
      result = client_->Post(path.c_str(), headers, body, content_type.c_str());
    }
    if (!result) {
      const auto err_code = map_transport_error(result.error());
      return StatusOr<std::string>::FromError(
          err_code,
          "HTTP request failed for " + path + " (" +
              std::to_string(static_cast<int>(result.error())) + ")");
    }
    const auto& response = *result;
    if (response.status < 200 || response.status >= 300) {
      return StatusOr<std::string>::FromError(
          map_http_status(response.status),
          "HTTP status " + std::to_string(response.status) + " for " + path);
    }
    return StatusOr<std::string>::FromValue(response.body);
  }

  HttpClientOptions options_;
  std::unique_ptr<httplib::Client> client_;
  std::string host_;
  int port_ = 80;
};

HttpClient::HttpClient(HttpClientOptions options)
    : impl_(std::make_unique<Impl>(std::move(options))) {
  const Status status = impl_->init();
  if (!status.ok()) {
    throw std::runtime_error("HttpClient init failed: " + status.message);
  }
}

HttpClient::~HttpClient() = default;
HttpClient::HttpClient(HttpClient&&) noexcept = default;
HttpClient& HttpClient::operator=(HttpClient&&) noexcept = default;

StatusOr<HealthStatus> HttpClient::GetStatus() {
  auto rpc = impl_->call_rpc<libghidra::HealthStatusRequest, libghidra::HealthStatusResponse>(
      "libghidra.HealthService/GetStatus",
      libghidra::HealthStatusRequest{});
  if (!rpc.ok()) {
    return StatusOr<HealthStatus>::FromError(rpc.status.code, rpc.status.message);
  }
  HealthStatus out;
  out.ok = rpc.value->ok();
  out.service_name = rpc.value->service_name();
  out.service_version = rpc.value->service_version();
  out.host_mode = rpc.value->host_mode();
  out.program_revision = rpc.value->program_revision();
  out.warnings.reserve(static_cast<std::size_t>(rpc.value->warnings_size()));
  for (const auto& warning : rpc.value->warnings()) {
    out.warnings.push_back(warning);
  }
  return StatusOr<HealthStatus>::FromValue(std::move(out));
}

StatusOr<std::vector<Capability>> HttpClient::GetCapabilities() {
  auto rpc = impl_->call_rpc<libghidra::CapabilityRequest, libghidra::CapabilityResponse>(
      "libghidra.HealthService/GetCapabilities",
      libghidra::CapabilityRequest{});
  if (!rpc.ok()) {
    return StatusOr<std::vector<Capability>>::FromError(rpc.status.code, rpc.status.message);
  }
  std::vector<Capability> out;
  out.reserve(static_cast<std::size_t>(rpc.value->capabilities_size()));
  for (const auto& cap : rpc.value->capabilities()) {
    Capability row;
    row.id = cap.id();
    row.status = cap.status();
    row.note = cap.note();
    out.push_back(std::move(row));
  }
  return StatusOr<std::vector<Capability>>::FromValue(std::move(out));
}

StatusOr<OpenProgramResponse> HttpClient::OpenProgram(const OpenProgramRequest& request) {
  libghidra::OpenProgramRequest rpc_request;
  rpc_request.set_project_path(request.project_path);
  rpc_request.set_project_name(request.project_name);
  rpc_request.set_program_path(request.program_path);
  rpc_request.set_analyze(request.analyze);
  rpc_request.set_read_only(request.read_only);

  auto rpc = impl_->call_rpc<libghidra::OpenProgramRequest, libghidra::OpenProgramResponse>(
      "libghidra.SessionService/OpenProgram",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<OpenProgramResponse>::FromError(rpc.status.code, rpc.status.message);
  }

  OpenProgramResponse out;
  out.program_name = rpc.value->program_name();
  out.language_id = rpc.value->language_id();
  out.compiler_spec = rpc.value->compiler_spec();
  out.image_base = rpc.value->image_base();
  return StatusOr<OpenProgramResponse>::FromValue(std::move(out));
}

StatusOr<CloseProgramResponse> HttpClient::CloseProgram(ShutdownPolicy policy) {
  libghidra::CloseProgramRequest rpc_request;
  rpc_request.set_shutdown_policy(to_proto_shutdown_policy(policy));

  auto rpc = impl_->call_rpc<libghidra::CloseProgramRequest, libghidra::CloseProgramResponse>(
      "libghidra.SessionService/CloseProgram",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<CloseProgramResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  CloseProgramResponse out;
  out.closed = rpc.value->closed();
  return StatusOr<CloseProgramResponse>::FromValue(out);
}

StatusOr<SaveProgramResponse> HttpClient::SaveProgram() {
  libghidra::SaveProgramRequest rpc_request;
  auto rpc = impl_->call_rpc<libghidra::SaveProgramRequest, libghidra::SaveProgramResponse>(
      "libghidra.SessionService/SaveProgram",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SaveProgramResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SaveProgramResponse out;
  out.saved = rpc.value->saved();
  return StatusOr<SaveProgramResponse>::FromValue(out);
}

StatusOr<DiscardProgramResponse> HttpClient::DiscardProgram() {
  libghidra::DiscardProgramRequest rpc_request;
  auto rpc =
      impl_->call_rpc<libghidra::DiscardProgramRequest, libghidra::DiscardProgramResponse>(
          "libghidra.SessionService/DiscardProgram",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DiscardProgramResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DiscardProgramResponse out;
  out.discarded = rpc.value->discarded();
  return StatusOr<DiscardProgramResponse>::FromValue(out);
}

StatusOr<RevisionResponse> HttpClient::GetRevision() {
  libghidra::GetRevisionRequest rpc_request;
  auto rpc = impl_->call_rpc<libghidra::GetRevisionRequest, libghidra::GetRevisionResponse>(
      "libghidra.SessionService/GetRevision",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<RevisionResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  RevisionResponse out;
  out.revision = rpc.value->revision();
  return StatusOr<RevisionResponse>::FromValue(out);
}

StatusOr<ShutdownResponse> HttpClient::Shutdown(ShutdownPolicy policy) {
  libghidra::ShutdownRequest rpc_request;
  rpc_request.set_shutdown_policy(to_proto_shutdown_policy(policy));
  auto rpc = impl_->call_rpc<libghidra::ShutdownRequest, libghidra::ShutdownResponse>(
      "libghidra.SessionService/Shutdown",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ShutdownResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ShutdownResponse out;
  out.accepted = rpc.value->accepted();
  return StatusOr<ShutdownResponse>::FromValue(out);
}

StatusOr<ReadBytesResponse> HttpClient::ReadBytes(std::uint64_t address, std::uint32_t length) {
  libghidra::ReadBytesRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_length(length);
  auto rpc = impl_->call_rpc<libghidra::ReadBytesRequest, libghidra::ReadBytesResponse>(
      "libghidra.MemoryService/ReadBytes",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ReadBytesResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ReadBytesResponse out;
  out.data.assign(rpc.value->data().begin(), rpc.value->data().end());
  return StatusOr<ReadBytesResponse>::FromValue(std::move(out));
}

StatusOr<WriteBytesResponse> HttpClient::WriteBytes(std::uint64_t address,
                                                    const std::vector<std::uint8_t>& data) {
  libghidra::WriteBytesRequest rpc_request;
  rpc_request.set_address(address);
  if (!data.empty()) {
    rpc_request.set_data(std::string(reinterpret_cast<const char*>(data.data()), data.size()));
  }
  auto rpc = impl_->call_rpc<libghidra::WriteBytesRequest, libghidra::WriteBytesResponse>(
      "libghidra.MemoryService/WriteBytes",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<WriteBytesResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  WriteBytesResponse out;
  out.bytes_written = rpc.value->bytes_written();
  return StatusOr<WriteBytesResponse>::FromValue(out);
}

StatusOr<PatchBytesBatchResponse> HttpClient::PatchBytesBatch(
    const std::vector<BytePatch>& patches) {
  libghidra::PatchBytesBatchRequest rpc_request;
  for (const auto& patch : patches) {
    auto* proto_patch = rpc_request.add_patches();
    proto_patch->set_address(patch.address);
    if (!patch.data.empty()) {
      proto_patch->set_data(
          std::string(reinterpret_cast<const char*>(patch.data.data()), patch.data.size()));
    }
  }
  auto rpc = impl_->call_rpc<libghidra::PatchBytesBatchRequest,
                             libghidra::PatchBytesBatchResponse>(
      "libghidra.MemoryService/PatchBytesBatch",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<PatchBytesBatchResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  PatchBytesBatchResponse out;
  out.patch_count = rpc.value->patch_count();
  out.bytes_written = rpc.value->bytes_written();
  return StatusOr<PatchBytesBatchResponse>::FromValue(out);
}

StatusOr<ListMemoryBlocksResponse> HttpClient::ListMemoryBlocks(int limit, int offset) {
  libghidra::ListMemoryBlocksRequest rpc_request;
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListMemoryBlocksRequest,
                             libghidra::ListMemoryBlocksResponse>(
      "libghidra.MemoryService/ListMemoryBlocks",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListMemoryBlocksResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListMemoryBlocksResponse out;
  out.blocks.reserve(static_cast<std::size_t>(rpc.value->blocks_size()));
  for (const auto& row : rpc.value->blocks()) {
    MemoryBlockRecord rec;
    rec.name = row.name();
    rec.start_address = row.start_address();
    rec.end_address = row.end_address();
    rec.size = row.size();
    rec.is_read = row.is_read();
    rec.is_write = row.is_write();
    rec.is_execute = row.is_execute();
    rec.is_volatile = row.is_volatile();
    rec.is_initialized = row.is_initialized();
    rec.source_name = row.source_name();
    rec.comment = row.comment();
    out.blocks.push_back(std::move(rec));
  }
  return StatusOr<ListMemoryBlocksResponse>::FromValue(std::move(out));
}

StatusOr<GetFunctionResponse> HttpClient::GetFunction(std::uint64_t address) {
  libghidra::GetFunctionRequest rpc_request;
  rpc_request.set_address(address);
  auto rpc = impl_->call_rpc<libghidra::GetFunctionRequest, libghidra::GetFunctionResponse>(
      "libghidra.FunctionsService/GetFunction",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<GetFunctionResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  GetFunctionResponse out;
  bool needs_list_fallback = false;
  if (rpc.value->has_function()) {
    auto mapped = from_proto_function_record(rpc.value->function());
    const bool looks_default =
        mapped.entry_address == 0 &&
        mapped.name.empty() &&
        mapped.start_address == 0 &&
        mapped.end_address == 0 &&
        mapped.size == 0 &&
        mapped.namespace_name.empty() &&
        mapped.prototype.empty() &&
        !mapped.is_thunk &&
        mapped.parameter_count == 0;
    if (!looks_default) {
      out.function = std::move(mapped);
      needs_list_fallback = out.function->name.empty();
    } else {
      needs_list_fallback = true;
    }
  }
  if (!rpc.value->has_function()) {
    needs_list_fallback = true;
  }
  if (needs_list_fallback) {
    constexpr int kPageSize = 2048;
    for (int offset = 0;; offset += kPageSize) {
      auto listed = ListFunctions(0, std::numeric_limits<std::uint64_t>::max(), kPageSize, offset);
      if (!listed.ok()) {
        return StatusOr<GetFunctionResponse>::FromError(listed.status.code, listed.status.message);
      }
      const auto& rows = listed.value->functions;
      for (const auto& row : rows) {
        if (row.entry_address == address) {
          out.function = row;
          break;
        }
      }
      if (out.function.has_value() || rows.size() < static_cast<std::size_t>(kPageSize)) {
        break;
      }
    }
  }
  return StatusOr<GetFunctionResponse>::FromValue(std::move(out));
}

StatusOr<ListFunctionsResponse> HttpClient::ListFunctions(std::uint64_t range_start,
                                                          std::uint64_t range_end,
                                                          int limit,
                                                          int offset) {
  libghidra::ListFunctionsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListFunctionsRequest, libghidra::ListFunctionsResponse>(
      "libghidra.FunctionsService/ListFunctions",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListFunctionsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListFunctionsResponse out;
  out.functions.reserve(static_cast<std::size_t>(rpc.value->functions_size()));
  for (const auto& row : rpc.value->functions()) {
    out.functions.push_back(from_proto_function_record(row));
  }
  return StatusOr<ListFunctionsResponse>::FromValue(std::move(out));
}

StatusOr<RenameFunctionResponse> HttpClient::RenameFunction(std::uint64_t address,
                                                            const std::string& new_name) {
  libghidra::RenameFunctionRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_new_name(new_name);
  auto rpc = impl_->call_rpc<libghidra::RenameFunctionRequest,
                             libghidra::RenameFunctionResponse>(
      "libghidra.FunctionsService/RenameFunction",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<RenameFunctionResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  RenameFunctionResponse out;
  out.renamed = rpc.value->renamed();
  out.name = rpc.value->name();
  return StatusOr<RenameFunctionResponse>::FromValue(std::move(out));
}

StatusOr<ListBasicBlocksResponse> HttpClient::ListBasicBlocks(std::uint64_t range_start,
                                                              std::uint64_t range_end,
                                                              int limit,
                                                              int offset) {
  libghidra::ListBasicBlocksRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListBasicBlocksRequest,
                             libghidra::ListBasicBlocksResponse>(
      "libghidra.FunctionsService/ListBasicBlocks",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListBasicBlocksResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListBasicBlocksResponse out;
  out.blocks.reserve(static_cast<std::size_t>(rpc.value->blocks_size()));
  for (const auto& row : rpc.value->blocks()) {
    BasicBlockRecord rec;
    rec.function_entry = row.function_entry();
    rec.start_address = row.start_address();
    rec.end_address = row.end_address();
    rec.in_degree = row.in_degree();
    rec.out_degree = row.out_degree();
    out.blocks.push_back(std::move(rec));
  }
  return StatusOr<ListBasicBlocksResponse>::FromValue(std::move(out));
}

StatusOr<ListCFGEdgesResponse> HttpClient::ListCFGEdges(std::uint64_t range_start,
                                                        std::uint64_t range_end,
                                                        int limit,
                                                        int offset) {
  libghidra::ListCFGEdgesRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListCFGEdgesRequest,
                             libghidra::ListCFGEdgesResponse>(
      "libghidra.FunctionsService/ListCFGEdges",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListCFGEdgesResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListCFGEdgesResponse out;
  out.edges.reserve(static_cast<std::size_t>(rpc.value->edges_size()));
  for (const auto& row : rpc.value->edges()) {
    CFGEdgeRecord rec;
    rec.function_entry = row.function_entry();
    rec.src_block_start = row.src_block_start();
    rec.dst_block_start = row.dst_block_start();
    rec.edge_kind = row.edge_kind();
    out.edges.push_back(std::move(rec));
  }
  return StatusOr<ListCFGEdgesResponse>::FromValue(std::move(out));
}

StatusOr<ListSwitchTablesResponse> HttpClient::ListSwitchTables(std::uint64_t range_start,
                                                                std::uint64_t range_end,
                                                                int limit,
                                                                int offset) {
  libghidra::ListSwitchTablesRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListSwitchTablesRequest,
                             libghidra::ListSwitchTablesResponse>(
      "libghidra.FunctionsService/ListSwitchTables",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListSwitchTablesResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListSwitchTablesResponse out;
  out.switch_tables.reserve(static_cast<std::size_t>(rpc.value->switch_tables_size()));
  for (const auto& row : rpc.value->switch_tables()) {
    SwitchTableRecord rec;
    rec.function_entry = row.function_entry();
    rec.switch_address = row.switch_address();
    rec.case_count = row.case_count();
    rec.default_address = row.default_address();
    rec.cases.reserve(static_cast<std::size_t>(row.cases_size()));
    for (const auto& c : row.cases()) {
      SwitchCaseRecord cr;
      cr.value = c.value();
      cr.target_address = c.target_address();
      rec.cases.push_back(std::move(cr));
    }
    out.switch_tables.push_back(std::move(rec));
  }
  return StatusOr<ListSwitchTablesResponse>::FromValue(std::move(out));
}

StatusOr<ListDominatorsResponse> HttpClient::ListDominators(std::uint64_t range_start,
                                                            std::uint64_t range_end,
                                                            int limit,
                                                            int offset) {
  libghidra::ListDominatorsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListDominatorsRequest,
                             libghidra::ListDominatorsResponse>(
      "libghidra.FunctionsService/ListDominators",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListDominatorsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListDominatorsResponse out;
  out.dominators.reserve(static_cast<std::size_t>(rpc.value->dominators_size()));
  for (const auto& row : rpc.value->dominators()) {
    DominatorRecord rec;
    rec.function_entry = row.function_entry();
    rec.block_address = row.block_address();
    rec.idom_address = row.idom_address();
    rec.depth = row.depth();
    rec.is_entry = row.is_entry();
    out.dominators.push_back(std::move(rec));
  }
  return StatusOr<ListDominatorsResponse>::FromValue(std::move(out));
}

StatusOr<ListPostDominatorsResponse> HttpClient::ListPostDominators(std::uint64_t range_start,
                                                                    std::uint64_t range_end,
                                                                    int limit,
                                                                    int offset) {
  libghidra::ListPostDominatorsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListPostDominatorsRequest,
                             libghidra::ListPostDominatorsResponse>(
      "libghidra.FunctionsService/ListPostDominators",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListPostDominatorsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListPostDominatorsResponse out;
  out.post_dominators.reserve(static_cast<std::size_t>(rpc.value->post_dominators_size()));
  for (const auto& row : rpc.value->post_dominators()) {
    PostDominatorRecord rec;
    rec.function_entry = row.function_entry();
    rec.block_address = row.block_address();
    rec.ipdom_address = row.ipdom_address();
    rec.depth = row.depth();
    rec.is_exit = row.is_exit();
    out.post_dominators.push_back(std::move(rec));
  }
  return StatusOr<ListPostDominatorsResponse>::FromValue(std::move(out));
}

StatusOr<ListLoopsResponse> HttpClient::ListLoops(std::uint64_t range_start,
                                                  std::uint64_t range_end,
                                                  int limit,
                                                  int offset) {
  libghidra::ListLoopsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListLoopsRequest,
                             libghidra::ListLoopsResponse>(
      "libghidra.FunctionsService/ListLoops",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListLoopsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListLoopsResponse out;
  out.loops.reserve(static_cast<std::size_t>(rpc.value->loops_size()));
  for (const auto& row : rpc.value->loops()) {
    LoopRecord rec;
    rec.function_entry = row.function_entry();
    rec.header_address = row.header_address();
    rec.back_edge_source = row.back_edge_source();
    rec.loop_kind = row.loop_kind();
    rec.block_count = row.block_count();
    rec.depth = row.depth();
    out.loops.push_back(std::move(rec));
  }
  return StatusOr<ListLoopsResponse>::FromValue(std::move(out));
}

// -- Function tags --------------------------------------------------------

StatusOr<ListFunctionTagsResponse> HttpClient::ListFunctionTags() {
  libghidra::ListFunctionTagsRequest rpc_request;
  auto rpc = impl_->call_rpc<libghidra::ListFunctionTagsRequest,
                             libghidra::ListFunctionTagsResponse>(
      "libghidra.FunctionsService/ListFunctionTags", rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListFunctionTagsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListFunctionTagsResponse out;
  out.tags.reserve(static_cast<std::size_t>(rpc.value->tags_size()));
  for (const auto& row : rpc.value->tags()) {
    FunctionTagRecord rec;
    rec.name = row.name();
    rec.comment = row.comment();
    out.tags.push_back(std::move(rec));
  }
  return StatusOr<ListFunctionTagsResponse>::FromValue(std::move(out));
}

StatusOr<CreateFunctionTagResponse> HttpClient::CreateFunctionTag(
    const std::string& name, const std::string& comment) {
  libghidra::CreateFunctionTagRequest rpc_request;
  rpc_request.set_name(name);
  rpc_request.set_comment(comment);
  auto rpc = impl_->call_rpc<libghidra::CreateFunctionTagRequest,
                             libghidra::CreateFunctionTagResponse>(
      "libghidra.FunctionsService/CreateFunctionTag", rpc_request);
  if (!rpc.ok()) {
    return StatusOr<CreateFunctionTagResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  CreateFunctionTagResponse out;
  out.created = rpc.value->created();
  return StatusOr<CreateFunctionTagResponse>::FromValue(out);
}

StatusOr<DeleteFunctionTagResponse> HttpClient::DeleteFunctionTag(const std::string& name) {
  libghidra::DeleteFunctionTagRequest rpc_request;
  rpc_request.set_name(name);
  auto rpc = impl_->call_rpc<libghidra::DeleteFunctionTagRequest,
                             libghidra::DeleteFunctionTagResponse>(
      "libghidra.FunctionsService/DeleteFunctionTag", rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteFunctionTagResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteFunctionTagResponse out;
  out.deleted = rpc.value->deleted();
  return StatusOr<DeleteFunctionTagResponse>::FromValue(out);
}

StatusOr<ListFunctionTagMappingsResponse> HttpClient::ListFunctionTagMappings(
    std::uint64_t function_entry) {
  libghidra::ListFunctionTagMappingsRequest rpc_request;
  rpc_request.set_function_entry(function_entry);
  auto rpc = impl_->call_rpc<libghidra::ListFunctionTagMappingsRequest,
                             libghidra::ListFunctionTagMappingsResponse>(
      "libghidra.FunctionsService/ListFunctionTagMappings", rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListFunctionTagMappingsResponse>::FromError(rpc.status.code,
                                                                 rpc.status.message);
  }
  ListFunctionTagMappingsResponse out;
  out.mappings.reserve(static_cast<std::size_t>(rpc.value->mappings_size()));
  for (const auto& row : rpc.value->mappings()) {
    FunctionTagMappingRecord rec;
    rec.function_entry = row.function_entry();
    rec.tag_name = row.tag_name();
    out.mappings.push_back(std::move(rec));
  }
  return StatusOr<ListFunctionTagMappingsResponse>::FromValue(std::move(out));
}

StatusOr<TagFunctionResponse> HttpClient::TagFunction(std::uint64_t function_entry,
                                                       const std::string& tag_name) {
  libghidra::TagFunctionRequest rpc_request;
  rpc_request.set_function_entry(function_entry);
  rpc_request.set_tag_name(tag_name);
  auto rpc = impl_->call_rpc<libghidra::TagFunctionRequest,
                             libghidra::TagFunctionResponse>(
      "libghidra.FunctionsService/TagFunction", rpc_request);
  if (!rpc.ok()) {
    return StatusOr<TagFunctionResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  TagFunctionResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<TagFunctionResponse>::FromValue(out);
}

StatusOr<UntagFunctionResponse> HttpClient::UntagFunction(std::uint64_t function_entry,
                                                           const std::string& tag_name) {
  libghidra::UntagFunctionRequest rpc_request;
  rpc_request.set_function_entry(function_entry);
  rpc_request.set_tag_name(tag_name);
  auto rpc = impl_->call_rpc<libghidra::UntagFunctionRequest,
                             libghidra::UntagFunctionResponse>(
      "libghidra.FunctionsService/UntagFunction", rpc_request);
  if (!rpc.ok()) {
    return StatusOr<UntagFunctionResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  UntagFunctionResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<UntagFunctionResponse>::FromValue(out);
}

StatusOr<GetSymbolResponse> HttpClient::GetSymbol(std::uint64_t address) {
  libghidra::GetSymbolRequest rpc_request;
  rpc_request.set_address(address);
  auto rpc = impl_->call_rpc<libghidra::GetSymbolRequest, libghidra::GetSymbolResponse>(
      "libghidra.SymbolsService/GetSymbol",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<GetSymbolResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  GetSymbolResponse out;
  if (rpc.value->has_symbol()) {
    out.symbol = from_proto_symbol_record(rpc.value->symbol());
  }
  return StatusOr<GetSymbolResponse>::FromValue(std::move(out));
}

StatusOr<ListSymbolsResponse> HttpClient::ListSymbols(std::uint64_t range_start,
                                                      std::uint64_t range_end,
                                                      int limit,
                                                      int offset) {
  libghidra::ListSymbolsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListSymbolsRequest, libghidra::ListSymbolsResponse>(
      "libghidra.SymbolsService/ListSymbols",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListSymbolsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListSymbolsResponse out;
  out.symbols.reserve(static_cast<std::size_t>(rpc.value->symbols_size()));
  for (const auto& row : rpc.value->symbols()) {
    out.symbols.push_back(from_proto_symbol_record(row));
  }
  return StatusOr<ListSymbolsResponse>::FromValue(std::move(out));
}

StatusOr<RenameSymbolResponse> HttpClient::RenameSymbol(std::uint64_t address,
                                                        const std::string& new_name) {
  libghidra::RenameSymbolRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_new_name(new_name);
  auto rpc = impl_->call_rpc<libghidra::RenameSymbolRequest, libghidra::RenameSymbolResponse>(
      "libghidra.SymbolsService/RenameSymbol",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<RenameSymbolResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  RenameSymbolResponse out;
  out.renamed = rpc.value->renamed();
  out.name = rpc.value->name();
  return StatusOr<RenameSymbolResponse>::FromValue(std::move(out));
}

StatusOr<DeleteSymbolResponse> HttpClient::DeleteSymbol(std::uint64_t address,
                                                        const std::string& name_filter) {
  libghidra::DeleteSymbolRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_name(name_filter);
  auto rpc = impl_->call_rpc<libghidra::DeleteSymbolRequest, libghidra::DeleteSymbolResponse>(
      "libghidra.SymbolsService/DeleteSymbol",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteSymbolResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteSymbolResponse out;
  out.deleted = rpc.value->deleted();
  out.deleted_count = rpc.value->deleted_count();
  return StatusOr<DeleteSymbolResponse>::FromValue(std::move(out));
}

StatusOr<ListXrefsResponse> HttpClient::ListXrefs(std::uint64_t range_start,
                                                  std::uint64_t range_end,
                                                  int limit,
                                                  int offset) {
  libghidra::ListXrefsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListXrefsRequest, libghidra::ListXrefsResponse>(
      "libghidra.XrefsService/ListXrefs",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListXrefsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListXrefsResponse out;
  out.xrefs.reserve(static_cast<std::size_t>(rpc.value->xrefs_size()));
  for (const auto& row : rpc.value->xrefs()) {
    out.xrefs.push_back(from_proto_xref_record(row));
  }
  return StatusOr<ListXrefsResponse>::FromValue(std::move(out));
}

StatusOr<GetTypeResponse> HttpClient::GetType(const std::string& path_value) {
  libghidra::GetTypeRequest rpc_request;
  rpc_request.set_path(path_value);
  auto rpc = impl_->call_rpc<libghidra::GetTypeRequest, libghidra::GetTypeResponse>(
      "libghidra.TypesService/GetType",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<GetTypeResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  GetTypeResponse out;
  if (rpc.value->has_type()) {
    out.type = from_proto_type_record(rpc.value->type());
  }
  return StatusOr<GetTypeResponse>::FromValue(std::move(out));
}

StatusOr<ListTypesResponse> HttpClient::ListTypes(const std::string& query,
                                                  int limit,
                                                  int offset) {
  libghidra::ListTypesRequest rpc_request;
  rpc_request.set_query(query);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListTypesRequest, libghidra::ListTypesResponse>(
      "libghidra.TypesService/ListTypes",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListTypesResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListTypesResponse out;
  out.types.reserve(static_cast<std::size_t>(rpc.value->types_size()));
  for (const auto& row : rpc.value->types()) {
    out.types.push_back(from_proto_type_record(row));
  }
  return StatusOr<ListTypesResponse>::FromValue(std::move(out));
}

StatusOr<ListTypeAliasesResponse> HttpClient::ListTypeAliases(const std::string& query,
                                                              int limit,
                                                              int offset) {
  libghidra::ListTypeAliasesRequest rpc_request;
  rpc_request.set_query(query);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc =
      impl_->call_rpc<libghidra::ListTypeAliasesRequest, libghidra::ListTypeAliasesResponse>(
          "libghidra.TypesService/ListTypeAliases",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListTypeAliasesResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListTypeAliasesResponse out;
  out.aliases.reserve(static_cast<std::size_t>(rpc.value->aliases_size()));
  for (const auto& row : rpc.value->aliases()) {
    out.aliases.push_back(from_proto_type_alias_record(row));
  }
  return StatusOr<ListTypeAliasesResponse>::FromValue(std::move(out));
}

StatusOr<ListTypeUnionsResponse> HttpClient::ListTypeUnions(const std::string& query,
                                                            int limit,
                                                            int offset) {
  libghidra::ListTypeUnionsRequest rpc_request;
  rpc_request.set_query(query);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc =
      impl_->call_rpc<libghidra::ListTypeUnionsRequest, libghidra::ListTypeUnionsResponse>(
          "libghidra.TypesService/ListTypeUnions",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListTypeUnionsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListTypeUnionsResponse out;
  out.unions.reserve(static_cast<std::size_t>(rpc.value->unions_size()));
  for (const auto& row : rpc.value->unions()) {
    out.unions.push_back(from_proto_type_union_record(row));
  }
  return StatusOr<ListTypeUnionsResponse>::FromValue(std::move(out));
}

StatusOr<ListTypeEnumsResponse> HttpClient::ListTypeEnums(const std::string& query,
                                                          int limit,
                                                          int offset) {
  libghidra::ListTypeEnumsRequest rpc_request;
  rpc_request.set_query(query);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc =
      impl_->call_rpc<libghidra::ListTypeEnumsRequest, libghidra::ListTypeEnumsResponse>(
          "libghidra.TypesService/ListTypeEnums",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListTypeEnumsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListTypeEnumsResponse out;
  out.enums.reserve(static_cast<std::size_t>(rpc.value->enums_size()));
  for (const auto& row : rpc.value->enums()) {
    out.enums.push_back(from_proto_type_enum_record(row));
  }
  return StatusOr<ListTypeEnumsResponse>::FromValue(std::move(out));
}

StatusOr<ListTypeEnumMembersResponse> HttpClient::ListTypeEnumMembers(
    const std::string& type_id_or_path,
    int limit,
    int offset) {
  libghidra::ListTypeEnumMembersRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_
                 ->call_rpc<libghidra::ListTypeEnumMembersRequest,
                            libghidra::ListTypeEnumMembersResponse>(
                     "libghidra.TypesService/ListTypeEnumMembers",
                     rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListTypeEnumMembersResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListTypeEnumMembersResponse out;
  out.members.reserve(static_cast<std::size_t>(rpc.value->members_size()));
  for (const auto& row : rpc.value->members()) {
    out.members.push_back(from_proto_type_enum_member_record(row));
  }
  return StatusOr<ListTypeEnumMembersResponse>::FromValue(std::move(out));
}

StatusOr<ListTypeMembersResponse> HttpClient::ListTypeMembers(const std::string& type_id_or_path,
                                                              int limit,
                                                              int offset) {
  libghidra::ListTypeMembersRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc =
      impl_->call_rpc<libghidra::ListTypeMembersRequest, libghidra::ListTypeMembersResponse>(
          "libghidra.TypesService/ListTypeMembers",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListTypeMembersResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListTypeMembersResponse out;
  out.members.reserve(static_cast<std::size_t>(rpc.value->members_size()));
  for (const auto& row : rpc.value->members()) {
    out.members.push_back(from_proto_type_member_record(row));
  }
  return StatusOr<ListTypeMembersResponse>::FromValue(std::move(out));
}

StatusOr<GetFunctionSignatureResponse> HttpClient::GetFunctionSignature(std::uint64_t address) {
  libghidra::GetFunctionSignatureRequest rpc_request;
  rpc_request.set_address(address);
  auto rpc = impl_->call_rpc<libghidra::GetFunctionSignatureRequest,
                             libghidra::GetFunctionSignatureResponse>(
      "libghidra.TypesService/GetFunctionSignature",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<GetFunctionSignatureResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  GetFunctionSignatureResponse out;
  if (rpc.value->has_signature()) {
    out.signature = from_proto_signature_record(rpc.value->signature());
  }
  return StatusOr<GetFunctionSignatureResponse>::FromValue(std::move(out));
}

StatusOr<ListFunctionSignaturesResponse> HttpClient::ListFunctionSignatures(
    std::uint64_t range_start,
    std::uint64_t range_end,
    int limit,
    int offset) {
  libghidra::ListFunctionSignaturesRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc =
      impl_->call_rpc<libghidra::ListFunctionSignaturesRequest,
                      libghidra::ListFunctionSignaturesResponse>(
          "libghidra.TypesService/ListFunctionSignatures",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListFunctionSignaturesResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListFunctionSignaturesResponse out;
  out.signatures.reserve(static_cast<std::size_t>(rpc.value->signatures_size()));
  for (const auto& row : rpc.value->signatures()) {
    out.signatures.push_back(from_proto_signature_record(row));
  }
  return StatusOr<ListFunctionSignaturesResponse>::FromValue(std::move(out));
}

StatusOr<SetFunctionSignatureResponse> HttpClient::SetFunctionSignature(
    std::uint64_t address,
    const std::string& prototype) {
  libghidra::SetFunctionSignatureRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_prototype(prototype);
  auto rpc = impl_->call_rpc<libghidra::SetFunctionSignatureRequest,
                             libghidra::SetFunctionSignatureResponse>(
      "libghidra.TypesService/SetFunctionSignature",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetFunctionSignatureResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetFunctionSignatureResponse out;
  out.updated = rpc.value->updated();
  out.function_name = rpc.value->function_name();
  out.prototype = rpc.value->prototype();
  return StatusOr<SetFunctionSignatureResponse>::FromValue(std::move(out));
}

StatusOr<RenameFunctionParameterResponse> HttpClient::RenameFunctionParameter(
    std::uint64_t address,
    int ordinal,
    const std::string& new_name) {
  libghidra::RenameFunctionParameterRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_ordinal(ordinal);
  rpc_request.set_new_name(new_name);
  auto rpc = impl_->call_rpc<libghidra::RenameFunctionParameterRequest,
                             libghidra::RenameFunctionParameterResponse>(
      "libghidra.TypesService/RenameFunctionParameter",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<RenameFunctionParameterResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  RenameFunctionParameterResponse out;
  out.updated = rpc.value->updated();
  out.name = rpc.value->name();
  return StatusOr<RenameFunctionParameterResponse>::FromValue(std::move(out));
}

StatusOr<SetFunctionParameterTypeResponse> HttpClient::SetFunctionParameterType(
    std::uint64_t address,
    int ordinal,
    const std::string& data_type) {
  libghidra::SetFunctionParameterTypeRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_ordinal(ordinal);
  rpc_request.set_data_type(data_type);
  auto rpc = impl_->call_rpc<libghidra::SetFunctionParameterTypeRequest,
                             libghidra::SetFunctionParameterTypeResponse>(
      "libghidra.TypesService/SetFunctionParameterType",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetFunctionParameterTypeResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetFunctionParameterTypeResponse out;
  out.updated = rpc.value->updated();
  out.data_type = rpc.value->data_type();
  return StatusOr<SetFunctionParameterTypeResponse>::FromValue(std::move(out));
}

StatusOr<RenameFunctionLocalResponse> HttpClient::RenameFunctionLocal(
    std::uint64_t address,
    const std::string& local_id,
    const std::string& new_name) {
  libghidra::RenameFunctionLocalRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_local_id(local_id);
  rpc_request.set_new_name(new_name);
  auto rpc = impl_->call_rpc<libghidra::RenameFunctionLocalRequest,
                             libghidra::RenameFunctionLocalResponse>(
      "libghidra.TypesService/RenameFunctionLocal",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<RenameFunctionLocalResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  RenameFunctionLocalResponse out;
  out.updated = rpc.value->updated();
  out.local_id = rpc.value->local_id();
  out.name = rpc.value->name();
  return StatusOr<RenameFunctionLocalResponse>::FromValue(std::move(out));
}

StatusOr<SetFunctionLocalTypeResponse> HttpClient::SetFunctionLocalType(
    std::uint64_t address,
    const std::string& local_id,
    const std::string& data_type) {
  libghidra::SetFunctionLocalTypeRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_local_id(local_id);
  rpc_request.set_data_type(data_type);
  auto rpc = impl_->call_rpc<libghidra::SetFunctionLocalTypeRequest,
                             libghidra::SetFunctionLocalTypeResponse>(
      "libghidra.TypesService/SetFunctionLocalType",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetFunctionLocalTypeResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetFunctionLocalTypeResponse out;
  out.updated = rpc.value->updated();
  out.local_id = rpc.value->local_id();
  out.data_type = rpc.value->data_type();
  return StatusOr<SetFunctionLocalTypeResponse>::FromValue(std::move(out));
}

StatusOr<ApplyDataTypeResponse> HttpClient::ApplyDataType(std::uint64_t address,
                                                          const std::string& data_type) {
  libghidra::ApplyDataTypeRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_data_type(data_type);
  auto rpc =
      impl_->call_rpc<libghidra::ApplyDataTypeRequest, libghidra::ApplyDataTypeResponse>(
          "libghidra.TypesService/ApplyDataType",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ApplyDataTypeResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ApplyDataTypeResponse out;
  out.updated = rpc.value->updated();
  out.data_type = rpc.value->data_type();
  return StatusOr<ApplyDataTypeResponse>::FromValue(std::move(out));
}

StatusOr<CreateTypeResponse> HttpClient::CreateType(const std::string& name,
                                                    const std::string& kind,
                                                    std::uint64_t size) {
  libghidra::CreateTypeRequest rpc_request;
  rpc_request.set_name(name);
  rpc_request.set_kind(kind);
  rpc_request.set_size(size);
  auto rpc = impl_->call_rpc<libghidra::CreateTypeRequest, libghidra::CreateTypeResponse>(
      "libghidra.TypesService/CreateType",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<CreateTypeResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  CreateTypeResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<CreateTypeResponse>::FromValue(out);
}

StatusOr<DeleteTypeResponse> HttpClient::DeleteType(const std::string& type_id_or_path) {
  libghidra::DeleteTypeRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  auto rpc = impl_->call_rpc<libghidra::DeleteTypeRequest, libghidra::DeleteTypeResponse>(
      "libghidra.TypesService/DeleteType",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteTypeResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteTypeResponse out;
  out.deleted = rpc.value->deleted();
  return StatusOr<DeleteTypeResponse>::FromValue(out);
}

StatusOr<RenameTypeResponse> HttpClient::RenameType(const std::string& type_id_or_path,
                                                    const std::string& new_name) {
  libghidra::RenameTypeRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  rpc_request.set_new_name(new_name);
  auto rpc = impl_->call_rpc<libghidra::RenameTypeRequest, libghidra::RenameTypeResponse>(
      "libghidra.TypesService/RenameType",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<RenameTypeResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  RenameTypeResponse out;
  out.updated = rpc.value->updated();
  out.name = rpc.value->name();
  return StatusOr<RenameTypeResponse>::FromValue(std::move(out));
}

StatusOr<CreateTypeAliasResponse> HttpClient::CreateTypeAlias(const std::string& name,
                                                              const std::string& target_type) {
  libghidra::CreateTypeAliasRequest rpc_request;
  rpc_request.set_name(name);
  rpc_request.set_target_type(target_type);
  auto rpc =
      impl_->call_rpc<libghidra::CreateTypeAliasRequest, libghidra::CreateTypeAliasResponse>(
          "libghidra.TypesService/CreateTypeAlias",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<CreateTypeAliasResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  CreateTypeAliasResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<CreateTypeAliasResponse>::FromValue(out);
}

StatusOr<DeleteTypeAliasResponse> HttpClient::DeleteTypeAlias(const std::string& type_id_or_path) {
  libghidra::DeleteTypeAliasRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  auto rpc =
      impl_->call_rpc<libghidra::DeleteTypeAliasRequest, libghidra::DeleteTypeAliasResponse>(
          "libghidra.TypesService/DeleteTypeAlias",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteTypeAliasResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteTypeAliasResponse out;
  out.deleted = rpc.value->deleted();
  return StatusOr<DeleteTypeAliasResponse>::FromValue(out);
}

StatusOr<SetTypeAliasTargetResponse> HttpClient::SetTypeAliasTarget(
    const std::string& type_id_or_path,
    const std::string& target_type) {
  libghidra::SetTypeAliasTargetRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  rpc_request.set_target_type(target_type);
  auto rpc = impl_->call_rpc<libghidra::SetTypeAliasTargetRequest,
                             libghidra::SetTypeAliasTargetResponse>(
      "libghidra.TypesService/SetTypeAliasTarget",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetTypeAliasTargetResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetTypeAliasTargetResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetTypeAliasTargetResponse>::FromValue(out);
}

StatusOr<CreateTypeEnumResponse> HttpClient::CreateTypeEnum(const std::string& name,
                                                            std::uint64_t width,
                                                            bool is_signed) {
  libghidra::CreateTypeEnumRequest rpc_request;
  rpc_request.set_name(name);
  rpc_request.set_width(width);
  rpc_request.set_signed_(is_signed);
  auto rpc = impl_->call_rpc<libghidra::CreateTypeEnumRequest, libghidra::CreateTypeEnumResponse>(
      "libghidra.TypesService/CreateTypeEnum",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<CreateTypeEnumResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  CreateTypeEnumResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<CreateTypeEnumResponse>::FromValue(out);
}

StatusOr<DeleteTypeEnumResponse> HttpClient::DeleteTypeEnum(const std::string& type_id_or_path) {
  libghidra::DeleteTypeEnumRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  auto rpc =
      impl_->call_rpc<libghidra::DeleteTypeEnumRequest, libghidra::DeleteTypeEnumResponse>(
          "libghidra.TypesService/DeleteTypeEnum",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteTypeEnumResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteTypeEnumResponse out;
  out.deleted = rpc.value->deleted();
  return StatusOr<DeleteTypeEnumResponse>::FromValue(out);
}

StatusOr<AddTypeEnumMemberResponse> HttpClient::AddTypeEnumMember(const std::string& type_id_or_path,
                                                                  const std::string& name,
                                                                  std::int64_t value) {
  libghidra::AddTypeEnumMemberRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  rpc_request.set_name(name);
  rpc_request.set_value(value);
  auto rpc = impl_->call_rpc<libghidra::AddTypeEnumMemberRequest,
                             libghidra::AddTypeEnumMemberResponse>(
      "libghidra.TypesService/AddTypeEnumMember",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<AddTypeEnumMemberResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  AddTypeEnumMemberResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<AddTypeEnumMemberResponse>::FromValue(out);
}

StatusOr<DeleteTypeEnumMemberResponse> HttpClient::DeleteTypeEnumMember(
    const std::string& type_id_or_path,
    std::uint64_t ordinal) {
  libghidra::DeleteTypeEnumMemberRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  rpc_request.set_ordinal(ordinal);
  auto rpc = impl_->call_rpc<libghidra::DeleteTypeEnumMemberRequest,
                             libghidra::DeleteTypeEnumMemberResponse>(
      "libghidra.TypesService/DeleteTypeEnumMember",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteTypeEnumMemberResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteTypeEnumMemberResponse out;
  out.deleted = rpc.value->deleted();
  return StatusOr<DeleteTypeEnumMemberResponse>::FromValue(out);
}

StatusOr<RenameTypeEnumMemberResponse> HttpClient::RenameTypeEnumMember(
    const std::string& type_id_or_path,
    std::uint64_t ordinal,
    const std::string& new_name) {
  libghidra::RenameTypeEnumMemberRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  rpc_request.set_ordinal(ordinal);
  rpc_request.set_new_name(new_name);
  auto rpc = impl_->call_rpc<libghidra::RenameTypeEnumMemberRequest,
                             libghidra::RenameTypeEnumMemberResponse>(
      "libghidra.TypesService/RenameTypeEnumMember",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<RenameTypeEnumMemberResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  RenameTypeEnumMemberResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<RenameTypeEnumMemberResponse>::FromValue(out);
}

StatusOr<SetTypeEnumMemberValueResponse> HttpClient::SetTypeEnumMemberValue(
    const std::string& type_id_or_path,
    std::uint64_t ordinal,
    std::int64_t value) {
  libghidra::SetTypeEnumMemberValueRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  rpc_request.set_ordinal(ordinal);
  rpc_request.set_value(value);
  auto rpc = impl_->call_rpc<libghidra::SetTypeEnumMemberValueRequest,
                             libghidra::SetTypeEnumMemberValueResponse>(
      "libghidra.TypesService/SetTypeEnumMemberValue",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetTypeEnumMemberValueResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetTypeEnumMemberValueResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetTypeEnumMemberValueResponse>::FromValue(out);
}

StatusOr<AddTypeMemberResponse> HttpClient::AddTypeMember(
    const std::string& parent_type_id_or_path,
    const std::string& member_name,
    const std::string& member_type,
    std::uint64_t size) {
  libghidra::AddTypeMemberRequest rpc_request;
  rpc_request.set_type(parent_type_id_or_path);
  rpc_request.set_name(member_name);
  rpc_request.set_member_type(member_type);
  rpc_request.set_size(size);
  auto rpc =
      impl_->call_rpc<libghidra::AddTypeMemberRequest, libghidra::AddTypeMemberResponse>(
          "libghidra.TypesService/AddTypeMember",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<AddTypeMemberResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  AddTypeMemberResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<AddTypeMemberResponse>::FromValue(out);
}

StatusOr<DeleteTypeMemberResponse> HttpClient::DeleteTypeMember(
    const std::string& parent_type_id_or_path,
    std::uint64_t ordinal) {
  libghidra::DeleteTypeMemberRequest rpc_request;
  rpc_request.set_type(parent_type_id_or_path);
  rpc_request.set_ordinal(ordinal);
  auto rpc =
      impl_->call_rpc<libghidra::DeleteTypeMemberRequest, libghidra::DeleteTypeMemberResponse>(
          "libghidra.TypesService/DeleteTypeMember",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteTypeMemberResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteTypeMemberResponse out;
  out.deleted = rpc.value->deleted();
  return StatusOr<DeleteTypeMemberResponse>::FromValue(out);
}

StatusOr<RenameTypeMemberResponse> HttpClient::RenameTypeMember(
    const std::string& parent_type_id_or_path,
    std::uint64_t ordinal,
    const std::string& new_name) {
  libghidra::RenameTypeMemberRequest rpc_request;
  rpc_request.set_type(parent_type_id_or_path);
  rpc_request.set_ordinal(ordinal);
  rpc_request.set_new_name(new_name);
  auto rpc =
      impl_->call_rpc<libghidra::RenameTypeMemberRequest, libghidra::RenameTypeMemberResponse>(
          "libghidra.TypesService/RenameTypeMember",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<RenameTypeMemberResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  RenameTypeMemberResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<RenameTypeMemberResponse>::FromValue(out);
}

StatusOr<SetTypeMemberTypeResponse> HttpClient::SetTypeMemberType(
    const std::string& parent_type_id_or_path,
    std::uint64_t ordinal,
    const std::string& member_type) {
  libghidra::SetTypeMemberTypeRequest rpc_request;
  rpc_request.set_type(parent_type_id_or_path);
  rpc_request.set_ordinal(ordinal);
  rpc_request.set_member_type(member_type);
  auto rpc =
      impl_->call_rpc<libghidra::SetTypeMemberTypeRequest, libghidra::SetTypeMemberTypeResponse>(
          "libghidra.TypesService/SetTypeMemberType",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetTypeMemberTypeResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetTypeMemberTypeResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetTypeMemberTypeResponse>::FromValue(out);
}

StatusOr<SetTypeMemberCommentResponse> HttpClient::SetTypeMemberComment(
    const std::string& parent_type_id_or_path,
    std::uint64_t ordinal,
    const std::string& comment) {
  libghidra::SetTypeMemberCommentRequest rpc_request;
  rpc_request.set_type(parent_type_id_or_path);
  rpc_request.set_ordinal(ordinal);
  rpc_request.set_comment(comment);
  auto rpc =
      impl_->call_rpc<libghidra::SetTypeMemberCommentRequest, libghidra::SetTypeMemberCommentResponse>(
          "libghidra.TypesService/SetTypeMemberComment",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetTypeMemberCommentResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetTypeMemberCommentResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetTypeMemberCommentResponse>::FromValue(out);
}

StatusOr<SetTypeEnumMemberCommentResponse> HttpClient::SetTypeEnumMemberComment(
    const std::string& type_id_or_path,
    std::uint64_t ordinal,
    const std::string& comment) {
  libghidra::SetTypeEnumMemberCommentRequest rpc_request;
  rpc_request.set_type(type_id_or_path);
  rpc_request.set_ordinal(ordinal);
  rpc_request.set_comment(comment);
  auto rpc =
      impl_->call_rpc<libghidra::SetTypeEnumMemberCommentRequest, libghidra::SetTypeEnumMemberCommentResponse>(
          "libghidra.TypesService/SetTypeEnumMemberComment",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetTypeEnumMemberCommentResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetTypeEnumMemberCommentResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetTypeEnumMemberCommentResponse>::FromValue(out);
}

StatusOr<ParseDeclarationsResponse> HttpClient::ParseDeclarations(
    const std::string& source_text) {
  libghidra::ParseDeclarationsRequest rpc_request;
  rpc_request.set_source_text(source_text);
  auto rpc =
      impl_->call_rpc<libghidra::ParseDeclarationsRequest, libghidra::ParseDeclarationsResponse>(
          "libghidra.TypesService/ParseDeclarations",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ParseDeclarationsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ParseDeclarationsResponse out;
  out.types_created = rpc.value->types_created();
  out.type_names.reserve(static_cast<std::size_t>(rpc.value->type_names_size()));
  for (const auto& name : rpc.value->type_names()) {
    out.type_names.push_back(name);
  }
  out.errors.reserve(static_cast<std::size_t>(rpc.value->errors_size()));
  for (const auto& err : rpc.value->errors()) {
    out.errors.push_back(err);
  }
  return StatusOr<ParseDeclarationsResponse>::FromValue(std::move(out));
}

StatusOr<GetDecompilationResponse> HttpClient::GetDecompilation(std::uint64_t address,
                                                                int timeout_ms) {
  libghidra::DecompileFunctionRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_timeout_ms(timeout_ms > 0 ? static_cast<std::uint32_t>(timeout_ms) : 0);
  auto rpc =
      impl_->call_rpc<libghidra::DecompileFunctionRequest, libghidra::DecompileFunctionResponse>(
          "libghidra.DecompilerService/DecompileFunction",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<GetDecompilationResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  GetDecompilationResponse out;
  if (rpc.value->has_decompilation()) {
    out.decompilation = from_proto_decompilation_record(rpc.value->decompilation());
  }
  return StatusOr<GetDecompilationResponse>::FromValue(std::move(out));
}

StatusOr<ListDecompilationsResponse> HttpClient::ListDecompilations(std::uint64_t range_start,
                                                                    std::uint64_t range_end,
                                                                    int limit,
                                                                    int offset,
                                                                    int timeout_ms) {
  libghidra::ListDecompilationsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  rpc_request.set_timeout_ms(timeout_ms > 0 ? static_cast<std::uint32_t>(timeout_ms) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListDecompilationsRequest,
                             libghidra::ListDecompilationsResponse>(
      "libghidra.DecompilerService/ListDecompilations",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListDecompilationsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListDecompilationsResponse out;
  out.decompilations.reserve(static_cast<std::size_t>(rpc.value->decompilations_size()));
  for (const auto& row : rpc.value->decompilations()) {
    out.decompilations.push_back(from_proto_decompilation_record(row));
  }
  return StatusOr<ListDecompilationsResponse>::FromValue(std::move(out));
}

StatusOr<GetInstructionResponse> HttpClient::GetInstruction(std::uint64_t address) {
  libghidra::GetInstructionRequest rpc_request;
  rpc_request.set_address(address);
  auto rpc = impl_->call_rpc<libghidra::GetInstructionRequest, libghidra::GetInstructionResponse>(
      "libghidra.ListingService/GetInstruction",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<GetInstructionResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  GetInstructionResponse out;
  if (rpc.value->has_instruction()) {
    out.instruction = from_proto_instruction_record(rpc.value->instruction());
  }
  return StatusOr<GetInstructionResponse>::FromValue(std::move(out));
}

StatusOr<ListInstructionsResponse> HttpClient::ListInstructions(std::uint64_t range_start,
                                                                std::uint64_t range_end,
                                                                int limit,
                                                                int offset) {
  libghidra::ListInstructionsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListInstructionsRequest, libghidra::ListInstructionsResponse>(
      "libghidra.ListingService/ListInstructions",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListInstructionsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListInstructionsResponse out;
  out.instructions.reserve(static_cast<std::size_t>(rpc.value->instructions_size()));
  for (const auto& row : rpc.value->instructions()) {
    out.instructions.push_back(from_proto_instruction_record(row));
  }
  return StatusOr<ListInstructionsResponse>::FromValue(std::move(out));
}

StatusOr<GetCommentsResponse> HttpClient::GetComments(std::uint64_t range_start,
                                                      std::uint64_t range_end,
                                                      int limit,
                                                      int offset) {
  libghidra::GetCommentsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::GetCommentsRequest, libghidra::GetCommentsResponse>(
      "libghidra.ListingService/GetComments",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<GetCommentsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  GetCommentsResponse out;
  out.comments.reserve(static_cast<std::size_t>(rpc.value->comments_size()));
  for (const auto& row : rpc.value->comments()) {
    out.comments.push_back(from_proto_comment_record(row));
  }
  return StatusOr<GetCommentsResponse>::FromValue(std::move(out));
}

StatusOr<SetCommentResponse> HttpClient::SetComment(std::uint64_t address,
                                                    CommentKind kind,
                                                    const std::string& text) {
  libghidra::SetCommentRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_kind(to_proto_comment_kind(kind));
  rpc_request.set_text(text);
  auto rpc = impl_->call_rpc<libghidra::SetCommentRequest, libghidra::SetCommentResponse>(
      "libghidra.ListingService/SetComment",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetCommentResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetCommentResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetCommentResponse>::FromValue(out);
}

StatusOr<DeleteCommentResponse> HttpClient::DeleteComment(std::uint64_t address, CommentKind kind) {
  libghidra::DeleteCommentRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_kind(to_proto_comment_kind(kind));
  auto rpc = impl_->call_rpc<libghidra::DeleteCommentRequest, libghidra::DeleteCommentResponse>(
      "libghidra.ListingService/DeleteComment",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteCommentResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteCommentResponse out;
  out.deleted = rpc.value->deleted();
  return StatusOr<DeleteCommentResponse>::FromValue(out);
}

StatusOr<RenameDataItemResponse> HttpClient::RenameDataItem(std::uint64_t address,
                                                            const std::string& new_name) {
  libghidra::RenameDataItemRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_new_name(new_name);
  auto rpc = impl_->call_rpc<libghidra::RenameDataItemRequest, libghidra::RenameDataItemResponse>(
      "libghidra.ListingService/RenameDataItem",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<RenameDataItemResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  RenameDataItemResponse out;
  out.updated = rpc.value->updated();
  out.name = rpc.value->name();
  return StatusOr<RenameDataItemResponse>::FromValue(std::move(out));
}

StatusOr<DeleteDataItemResponse> HttpClient::DeleteDataItem(std::uint64_t address) {
  libghidra::DeleteDataItemRequest rpc_request;
  rpc_request.set_address(address);
  auto rpc = impl_->call_rpc<libghidra::DeleteDataItemRequest, libghidra::DeleteDataItemResponse>(
      "libghidra.ListingService/DeleteDataItem",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteDataItemResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteDataItemResponse out;
  out.deleted = rpc.value->deleted();
  return StatusOr<DeleteDataItemResponse>::FromValue(out);
}

StatusOr<ListDataItemsResponse> HttpClient::ListDataItems(std::uint64_t range_start,
                                                          std::uint64_t range_end,
                                                          int limit,
                                                          int offset) {
  libghidra::ListDataItemsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListDataItemsRequest, libghidra::ListDataItemsResponse>(
      "libghidra.ListingService/ListDataItems",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListDataItemsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListDataItemsResponse out;
  out.data_items.reserve(static_cast<std::size_t>(rpc.value->data_items_size()));
  for (const auto& row : rpc.value->data_items()) {
    out.data_items.push_back(from_proto_data_item_record(row));
  }
  return StatusOr<ListDataItemsResponse>::FromValue(std::move(out));
}

StatusOr<ListBookmarksResponse> HttpClient::ListBookmarks(std::uint64_t range_start,
                                                          std::uint64_t range_end,
                                                          int limit,
                                                          int offset,
                                                          const std::string& type_filter,
                                                          const std::string& category_filter) {
  libghidra::ListBookmarksRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  rpc_request.set_type_filter(type_filter);
  rpc_request.set_category_filter(category_filter);
  auto rpc = impl_->call_rpc<libghidra::ListBookmarksRequest, libghidra::ListBookmarksResponse>(
      "libghidra.ListingService/ListBookmarks",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListBookmarksResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListBookmarksResponse out;
  out.bookmarks.reserve(static_cast<std::size_t>(rpc.value->bookmarks_size()));
  for (const auto& row : rpc.value->bookmarks()) {
    out.bookmarks.push_back(from_proto_bookmark_record(row));
  }
  return StatusOr<ListBookmarksResponse>::FromValue(std::move(out));
}

StatusOr<AddBookmarkResponse> HttpClient::AddBookmark(std::uint64_t address,
                                                      const std::string& type,
                                                      const std::string& category,
                                                      const std::string& comment) {
  libghidra::AddBookmarkRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_type(type);
  rpc_request.set_category(category);
  rpc_request.set_comment(comment);
  auto rpc = impl_->call_rpc<libghidra::AddBookmarkRequest, libghidra::AddBookmarkResponse>(
      "libghidra.ListingService/AddBookmark",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<AddBookmarkResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  AddBookmarkResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<AddBookmarkResponse>::FromValue(out);
}

StatusOr<DeleteBookmarkResponse> HttpClient::DeleteBookmark(std::uint64_t address,
                                                            const std::string& type,
                                                            const std::string& category) {
  libghidra::DeleteBookmarkRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_type(type);
  rpc_request.set_category(category);
  auto rpc = impl_->call_rpc<libghidra::DeleteBookmarkRequest, libghidra::DeleteBookmarkResponse>(
      "libghidra.ListingService/DeleteBookmark",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteBookmarkResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteBookmarkResponse out;
  out.deleted = rpc.value->deleted();
  return StatusOr<DeleteBookmarkResponse>::FromValue(out);
}

StatusOr<ListBreakpointsResponse> HttpClient::ListBreakpoints(std::uint64_t range_start,
                                                              std::uint64_t range_end,
                                                              int limit,
                                                              int offset,
                                                              const std::string& kind_filter,
                                                              const std::string& group_filter) {
  libghidra::ListBreakpointsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  rpc_request.set_kind_filter(kind_filter);
  rpc_request.set_group_filter(group_filter);
  auto rpc =
      impl_->call_rpc<libghidra::ListBreakpointsRequest, libghidra::ListBreakpointsResponse>(
          "libghidra.ListingService/ListBreakpoints",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListBreakpointsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListBreakpointsResponse out;
  out.breakpoints.reserve(static_cast<std::size_t>(rpc.value->breakpoints_size()));
  for (const auto& row : rpc.value->breakpoints()) {
    out.breakpoints.push_back(from_proto_breakpoint_record(row));
  }
  return StatusOr<ListBreakpointsResponse>::FromValue(std::move(out));
}

StatusOr<AddBreakpointResponse> HttpClient::AddBreakpoint(std::uint64_t address,
                                                          const std::string& kind,
                                                          std::uint64_t size,
                                                          bool enabled,
                                                          const std::string& condition,
                                                          const std::string& group) {
  libghidra::AddBreakpointRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_kind(kind);
  rpc_request.set_size(size);
  rpc_request.set_enabled(enabled);
  rpc_request.set_condition(condition);
  rpc_request.set_group(group);
  auto rpc = impl_->call_rpc<libghidra::AddBreakpointRequest, libghidra::AddBreakpointResponse>(
      "libghidra.ListingService/AddBreakpoint",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<AddBreakpointResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  AddBreakpointResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<AddBreakpointResponse>::FromValue(out);
}

StatusOr<SetBreakpointEnabledResponse> HttpClient::SetBreakpointEnabled(std::uint64_t address,
                                                                        bool enabled) {
  libghidra::SetBreakpointEnabledRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_enabled(enabled);
  auto rpc =
      impl_->call_rpc<libghidra::SetBreakpointEnabledRequest,
                      libghidra::SetBreakpointEnabledResponse>(
          "libghidra.ListingService/SetBreakpointEnabled",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetBreakpointEnabledResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetBreakpointEnabledResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetBreakpointEnabledResponse>::FromValue(out);
}

StatusOr<SetBreakpointKindResponse> HttpClient::SetBreakpointKind(std::uint64_t address,
                                                                  const std::string& kind) {
  libghidra::SetBreakpointKindRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_kind(kind);
  auto rpc =
      impl_->call_rpc<libghidra::SetBreakpointKindRequest, libghidra::SetBreakpointKindResponse>(
          "libghidra.ListingService/SetBreakpointKind",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetBreakpointKindResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetBreakpointKindResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetBreakpointKindResponse>::FromValue(out);
}

StatusOr<SetBreakpointSizeResponse> HttpClient::SetBreakpointSize(std::uint64_t address,
                                                                  std::uint64_t size) {
  libghidra::SetBreakpointSizeRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_size(size);
  auto rpc =
      impl_->call_rpc<libghidra::SetBreakpointSizeRequest, libghidra::SetBreakpointSizeResponse>(
          "libghidra.ListingService/SetBreakpointSize",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetBreakpointSizeResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetBreakpointSizeResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetBreakpointSizeResponse>::FromValue(out);
}

StatusOr<SetBreakpointConditionResponse> HttpClient::SetBreakpointCondition(
    std::uint64_t address,
    const std::string& condition) {
  libghidra::SetBreakpointConditionRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_condition(condition);
  auto rpc = impl_->call_rpc<libghidra::SetBreakpointConditionRequest,
                             libghidra::SetBreakpointConditionResponse>(
      "libghidra.ListingService/SetBreakpointCondition",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetBreakpointConditionResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetBreakpointConditionResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetBreakpointConditionResponse>::FromValue(out);
}

StatusOr<SetBreakpointGroupResponse> HttpClient::SetBreakpointGroup(std::uint64_t address,
                                                                    const std::string& group) {
  libghidra::SetBreakpointGroupRequest rpc_request;
  rpc_request.set_address(address);
  rpc_request.set_group(group);
  auto rpc =
      impl_->call_rpc<libghidra::SetBreakpointGroupRequest, libghidra::SetBreakpointGroupResponse>(
          "libghidra.ListingService/SetBreakpointGroup",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<SetBreakpointGroupResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  SetBreakpointGroupResponse out;
  out.updated = rpc.value->updated();
  return StatusOr<SetBreakpointGroupResponse>::FromValue(out);
}

StatusOr<DeleteBreakpointResponse> HttpClient::DeleteBreakpoint(std::uint64_t address) {
  libghidra::DeleteBreakpointRequest rpc_request;
  rpc_request.set_address(address);
  auto rpc =
      impl_->call_rpc<libghidra::DeleteBreakpointRequest, libghidra::DeleteBreakpointResponse>(
          "libghidra.ListingService/DeleteBreakpoint",
          rpc_request);
  if (!rpc.ok()) {
    return StatusOr<DeleteBreakpointResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  DeleteBreakpointResponse out;
  out.deleted = rpc.value->deleted();
  return StatusOr<DeleteBreakpointResponse>::FromValue(out);
}

StatusOr<ListDefinedStringsResponse> HttpClient::ListDefinedStrings(
    std::uint64_t range_start,
    std::uint64_t range_end,
    int limit,
    int offset) {
  libghidra::ListDefinedStringsRequest rpc_request;
  rpc_request.mutable_range()->set_start(range_start);
  rpc_request.mutable_range()->set_end(range_end);
  rpc_request.mutable_page()->set_limit(limit > 0 ? static_cast<std::uint32_t>(limit) : 0);
  rpc_request.mutable_page()->set_offset(offset > 0 ? static_cast<std::uint32_t>(offset) : 0);
  auto rpc = impl_->call_rpc<libghidra::ListDefinedStringsRequest,
                             libghidra::ListDefinedStringsResponse>(
      "libghidra.ListingService/ListDefinedStrings",
      rpc_request);
  if (!rpc.ok()) {
    return StatusOr<ListDefinedStringsResponse>::FromError(rpc.status.code, rpc.status.message);
  }
  ListDefinedStringsResponse out;
  out.strings.reserve(static_cast<std::size_t>(rpc.value->strings_size()));
  for (const auto& row : rpc.value->strings()) {
    DefinedStringRecord rec;
    rec.address = row.address();
    rec.value = row.value();
    rec.length = row.length();
    rec.data_type = row.data_type();
    rec.encoding = row.encoding();
    out.strings.push_back(std::move(rec));
  }
  return StatusOr<ListDefinedStringsResponse>::FromValue(std::move(out));
}

std::unique_ptr<IClient> CreateHttpClient(HttpClientOptions options) {
  return std::make_unique<HttpClient>(std::move(options));
}

}  // namespace libghidra::client
