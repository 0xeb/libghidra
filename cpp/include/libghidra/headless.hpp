// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Launch headless Ghidra and return a connected IClient.

#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "libghidra/api.hpp"

namespace libghidra::client {

struct HeadlessOptions {
  std::string ghidra_dir;       // Path to Ghidra distribution
  std::string binary;           // Path to binary to import (empty if using program)
  std::string program;          // Reopen existing program (mutually exclusive with binary)
  int port = 18080;
  std::string bind = "127.0.0.1";  // Bind address for the headless server
  std::string project_dir;     // Empty = temp dir (auto-cleaned)
  std::string project_name = "HeadlessProject";
  bool analyze = true;
  bool overwrite = true;
  std::string shutdown = "save";   // "save"|"discard"|"none"
  std::string auth_token;          // Bearer auth token
  int max_runtime_seconds = 0;     // 0 = no limit (forwarded as max_runtime_ms)
  std::string script_dir;          // Override auto-detected script dir
  std::vector<std::string> extra_script_args;  // Additional script args
  std::vector<std::string> extra_headless_args;  // Passed verbatim to analyzeHeadless (after '--')
  std::chrono::seconds startup_timeout{300};
  std::chrono::milliseconds read_timeout{300000};

  // Called for each line of Ghidra output (optional).
  std::function<void(const std::string&)> on_output;
};

/// A connected client backed by a headless Ghidra process.
///
/// Provides smart-pointer-style access to IClient via operator-> / operator*,
/// so API calls use the same arrow syntax as unique_ptr<IClient>:
///
///   auto h = LaunchHeadless({...});
///   h->ListFunctions(...);   // operator-> → IClient*
///   h.close(true);           // lifecycle (dot)
///
/// Move-only; not copyable.
class HeadlessClient {
 public:
  HeadlessClient(HeadlessClient&&) noexcept;
  HeadlessClient& operator=(HeadlessClient&&) noexcept;
  ~HeadlessClient();

  HeadlessClient(const HeadlessClient&) = delete;
  HeadlessClient& operator=(const HeadlessClient&) = delete;

  /// Smart-pointer access to IClient — same semantics as unique_ptr<IClient>.
  IClient* operator->();
  const IClient* operator->() const;
  IClient& operator*();
  const IClient& operator*() const;

  /// Explicit client access (for passing IClient& to functions).
  IClient& client();
  const IClient& client() const;

  /// The base URL the client is connected to.
  const std::string& base_url() const;

  /// Release the process handle without killing it (suppress kill-on-destruct).
  /// After detach(), the destructor and close() become no-ops for the process.
  void detach();

  /// Wait for the process to exit (after shutdown).  Returns exit code.
  int wait();

  /// Shut down the host, wait, and clean up.
  int close(bool save = true);

 private:
  friend HeadlessClient LaunchHeadless(HeadlessOptions);
  struct Impl;
  explicit HeadlessClient(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

/// Launch headless Ghidra, wait for readiness, return a connected client.
HeadlessClient LaunchHeadless(HeadlessOptions opts);

}  // namespace libghidra::client
