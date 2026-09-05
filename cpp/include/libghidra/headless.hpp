// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
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

struct HeadlessProjectOptions {
  std::string ghidra_dir;       // Path to Ghidra distribution
  int port = 18080;
  std::string bind = "127.0.0.1";  // Bind address for the headless server
  std::string project_dir;     // Empty = temp dir (auto-cleaned)
  std::string project_name = "HeadlessProject";
  // Generic launcher default; owning applications select persistence.
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
///   auto h = LaunchHeadlessProject({...});
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
  ///
  /// The Shutdown RPC and the output-pipe drain are issued in detached
  /// worker threads so a wedged Java host can't block close() indefinitely.
  /// If the child process has not exited within `timeout`, it is
  /// force-killed via a Windows Job Object or POSIX process-group SIGKILL. A
  /// force-kill is reported as exit code -2 (distinguishable from a clean -1
  /// timeout).
  ///
  /// Default timeout is 60 seconds, which is long enough for a healthy
  /// save+exit on a normal program. Pass a smaller value for tests or a
  /// larger value when expecting very long save flushes.
  int close(ShutdownPolicy policy,
            std::chrono::milliseconds timeout = std::chrono::seconds(60));

  /// Compatibility shorthand for an explicit save or discard choice.
  int close(bool save,
            std::chrono::milliseconds timeout = std::chrono::seconds(60)) {
    return close(save ? ShutdownPolicy::kSave : ShutdownPolicy::kDiscard,
                 timeout);
  }

 private:
  friend HeadlessClient LaunchHeadlessProject(HeadlessProjectOptions);
  struct Impl;
  explicit HeadlessClient(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

/// Launch a project-scoped headless Ghidra host and return a connected client.
HeadlessClient LaunchHeadlessProject(HeadlessProjectOptions opts);

}  // namespace libghidra::client
