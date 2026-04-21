// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Launch headless Ghidra via analyzeHeadless, wait for
// LIBGHIDRA_HEADLESS_READY, then return a connected HttpClient.

#include "libghidra/headless.hpp"
#include "libghidra/http.hpp"

#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <signal.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace libghidra::client {

static constexpr const char* READY_BANNER = "LIBGHIDRA_HEADLESS_READY";

// ---------------------------------------------------------------------------
// Platform-specific process handle
// ---------------------------------------------------------------------------

#ifdef _WIN32

class ProcessHandle {
 public:
  ProcessHandle() = default;
  ~ProcessHandle() { close_handles(); }

  ProcessHandle(const ProcessHandle&) = delete;
  ProcessHandle& operator=(const ProcessHandle&) = delete;

  bool launch(const std::string& cmd_line, HANDLE read_pipe) {
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = read_pipe;
    si.hStdError = read_pipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    // CreateProcess needs a mutable buffer
    cmd_buf_ = cmd_line;
    BOOL ok = CreateProcessA(
        nullptr, cmd_buf_.data(), nullptr, nullptr,
        TRUE,  // inherit handles
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi_);
    if (!ok) return false;
    alive_ = true;
    return true;
  }

  bool alive() const { return alive_; }

  int wait(DWORD timeout_ms = INFINITE) {
    if (!alive_) return exit_code_;
    DWORD result = WaitForSingleObject(pi_.hProcess, timeout_ms);
    if (result == WAIT_TIMEOUT) return -1;
    DWORD code = 0;
    GetExitCodeProcess(pi_.hProcess, &code);
    exit_code_ = static_cast<int>(code);
    alive_ = false;
    return exit_code_;
  }

  void terminate() {
    if (alive_) {
      TerminateProcess(pi_.hProcess, 1);
      wait(10000);
    }
  }

 private:
  void close_handles() {
    if (pi_.hProcess) CloseHandle(pi_.hProcess);
    if (pi_.hThread) CloseHandle(pi_.hThread);
  }

  PROCESS_INFORMATION pi_{};
  std::string cmd_buf_;
  int exit_code_ = 0;
  bool alive_ = false;
};

#else  // POSIX

class ProcessHandle {
 public:
  ProcessHandle() = default;
  ~ProcessHandle() = default;

  ProcessHandle(const ProcessHandle&) = delete;
  ProcessHandle& operator=(const ProcessHandle&) = delete;

  bool launch(const std::vector<std::string>& args, int write_fd) {
    pid_ = fork();
    if (pid_ < 0) return false;
    if (pid_ == 0) {
      // Child
      dup2(write_fd, STDOUT_FILENO);
      dup2(write_fd, STDERR_FILENO);
      close(write_fd);
      std::vector<char*> argv;
      for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
      argv.push_back(nullptr);
      execvp(argv[0], argv.data());
      _exit(127);
    }
    alive_ = true;
    return true;
  }

  bool alive() const { return alive_; }

  int wait(int timeout_ms = -1) {
    if (!alive_) return exit_code_;
    int status = 0;
    if (timeout_ms < 0) {
      waitpid(pid_, &status, 0);
    } else {
      // Poll with timeout
      auto deadline = std::chrono::steady_clock::now() +
                      std::chrono::milliseconds(timeout_ms);
      while (std::chrono::steady_clock::now() < deadline) {
        int r = waitpid(pid_, &status, WNOHANG);
        if (r > 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
    exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    alive_ = false;
    return exit_code_;
  }

  void terminate() {
    if (alive_) {
      kill(pid_, SIGTERM);
      wait(10000);
    }
  }

 private:
  pid_t pid_ = -1;
  int exit_code_ = 0;
  bool alive_ = false;
};

#endif

// ---------------------------------------------------------------------------
// Pipe reader (reads lines from a pipe/handle)
// ---------------------------------------------------------------------------

class PipeReader {
 public:
#ifdef _WIN32
  explicit PipeReader(HANDLE h) : handle_(h) {}
  ~PipeReader() { if (handle_) CloseHandle(handle_); }

  bool read_line(std::string& out) {
    out.clear();
    char ch;
    DWORD n;
    while (ReadFile(handle_, &ch, 1, &n, nullptr) && n == 1) {
      if (ch == '\n') {
        while (!out.empty() && out.back() == '\r') out.pop_back();
        return true;
      }
      out += ch;
    }
    return !out.empty();  // partial line at EOF
  }
#else
  explicit PipeReader(int fd) : fd_(fd) {}
  ~PipeReader() { if (fd_ >= 0) ::close(fd_); }

  bool read_line(std::string& out) {
    out.clear();
    char ch;
    while (::read(fd_, &ch, 1) == 1) {
      if (ch == '\n') return true;
      out += ch;
    }
    return !out.empty();
  }
#endif

 private:
#ifdef _WIN32
  HANDLE handle_ = nullptr;
#else
  int fd_ = -1;
#endif
};

// ---------------------------------------------------------------------------
// HeadlessClient::Impl
// ---------------------------------------------------------------------------

struct HeadlessClient::Impl {
  std::unique_ptr<IClient> client;
  std::unique_ptr<ProcessHandle> proc;
  std::unique_ptr<PipeReader> pipe;
  std::string base_url;
  fs::path project_dir;
  bool owns_project;
  bool detached = false;
  std::function<void(const std::string&)> on_output;
};

// ---------------------------------------------------------------------------
// HeadlessClient — pImpl forwarding
// ---------------------------------------------------------------------------

HeadlessClient::HeadlessClient(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

HeadlessClient::HeadlessClient(HeadlessClient&&) noexcept = default;
HeadlessClient& HeadlessClient::operator=(HeadlessClient&&) noexcept = default;
HeadlessClient::~HeadlessClient() = default;

IClient* HeadlessClient::operator->() { return impl_->client.get(); }
const IClient* HeadlessClient::operator->() const { return impl_->client.get(); }
IClient& HeadlessClient::operator*() { return *impl_->client; }
const IClient& HeadlessClient::operator*() const { return *impl_->client; }
IClient& HeadlessClient::client() { return *impl_->client; }
const IClient& HeadlessClient::client() const { return *impl_->client; }

const std::string& HeadlessClient::base_url() const { return impl_->base_url; }

void HeadlessClient::detach() {
  impl_->detached = true;
  impl_->owns_project = false;
}

int HeadlessClient::wait() {
  if (impl_->detached) return 0;
  return impl_->proc->wait();
}

int HeadlessClient::close(bool save) {
  if (impl_->detached) return 0;

  // Shut down the host
  impl_->client->Shutdown(save ? ShutdownPolicy::kSave
                               : ShutdownPolicy::kDiscard);

  // Drain output
  if (impl_->pipe) {
    std::string line;
    while (impl_->pipe->read_line(line)) {
      if (!line.empty() && impl_->on_output) impl_->on_output(line);
    }
    impl_->pipe.reset();
  }

  int code = impl_->proc->wait(60000);
  if (impl_->proc->alive()) impl_->proc->terminate();

  if (impl_->owns_project) {
    std::error_code ec;
    fs::remove_all(impl_->project_dir, ec);
  }
  return code;
}

// ---------------------------------------------------------------------------
// Path discovery
// ---------------------------------------------------------------------------

static fs::path find_launcher(const fs::path& ghidra_dir) {
#ifdef _WIN32
  auto p = ghidra_dir / "support" / "analyzeHeadless.bat";
#else
  auto p = ghidra_dir / "support" / "analyzeHeadless";
#endif
  if (!fs::exists(p))
    throw std::runtime_error("analyzeHeadless not found at " + p.string());
  return p;
}

static fs::path find_script_dir(const fs::path& ghidra_dir) {
  auto d = ghidra_dir / "Ghidra" / "Extensions" / "LibGhidraHost" /
           "ghidra_scripts";
  if (!fs::exists(d))
    throw std::runtime_error(
        "LibGhidraHost extension not installed at " + d.parent_path().string());
  return d;
}

static std::string infer_imported_program_name(const fs::path& binary) {
  auto name = binary.filename().string();
  if (name.empty()) {
    throw std::runtime_error("Unable to infer imported program name from " +
                             binary.string());
  }
  return name;
}

#ifdef _WIN32
static std::string build_command_line(const std::vector<std::string>& args) {
  std::string cmd_line;
  for (const auto& a : args) {
    if (!cmd_line.empty()) cmd_line += ' ';
    if (a.find(' ') != std::string::npos) {
      cmd_line += "\"" + a + "\"";
    } else {
      cmd_line += a;
    }
  }
  return cmd_line;
}
#endif

static std::string run_import_stage(
    const fs::path& launcher, const fs::path& project_dir,
    const std::string& project_name, const fs::path& binary, bool overwrite,
    bool analyze, const std::function<void(const std::string&)>& on_output) {
  std::vector<std::string> args = {
      launcher.string(),
      project_dir.string(),
      project_name,
      "-import",
      binary.string(),
  };
  if (overwrite) args.push_back("-overwrite");
  if (!analyze) args.push_back("-noanalysis");

  auto proc = std::make_unique<ProcessHandle>();
  std::unique_ptr<PipeReader> reader;
  std::deque<std::string> tail;

#ifdef _WIN32
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  HANDLE pipe_read = nullptr, pipe_write = nullptr;
  if (!CreatePipe(&pipe_read, &pipe_write, &sa, 0))
    throw std::runtime_error("CreatePipe failed");
  SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0);

  std::string cmd_line = build_command_line(args);
  if (!proc->launch(cmd_line, pipe_write)) {
    CloseHandle(pipe_read);
    CloseHandle(pipe_write);
    throw std::runtime_error("CreateProcess failed");
  }
  CloseHandle(pipe_write);
  reader = std::make_unique<PipeReader>(pipe_read);
#else
  int pipefd[2];
  if (pipe(pipefd) < 0) throw std::runtime_error("pipe() failed");
  if (!proc->launch(args, pipefd[1])) {
    ::close(pipefd[0]);
    ::close(pipefd[1]);
    throw std::runtime_error("fork() failed");
  }
  ::close(pipefd[1]);
  reader = std::make_unique<PipeReader>(pipefd[0]);
#endif

  std::string line;
  while (reader->read_line(line)) {
    if (!line.empty() && on_output) on_output(line);
    if (!line.empty()) {
      if (tail.size() == 200) tail.pop_front();
      tail.push_back(line);
    }
  }

  int exit_code = proc->wait();
  if (proc->alive()) proc->terminate();
  if (exit_code != 0) {
    std::string tail_text;
    for (const auto& entry : tail) {
      if (!tail_text.empty()) tail_text += '\n';
      tail_text += entry;
    }
    throw std::runtime_error("Import stage failed with exit code " +
                             std::to_string(exit_code) + "\n" + tail_text);
  }

  return infer_imported_program_name(binary);
}

// ---------------------------------------------------------------------------
// LaunchHeadless
// ---------------------------------------------------------------------------

HeadlessClient LaunchHeadless(HeadlessOptions opts) {
  auto ghidra_dir = fs::absolute(opts.ghidra_dir);

  // Validate: need either binary or program
  bool has_binary = !opts.binary.empty();
  bool has_program = !opts.program.empty();
  if (!has_binary && !has_program)
    throw std::runtime_error("HeadlessOptions: either binary or program must be set");
  if (has_binary && has_program)
    throw std::runtime_error("HeadlessOptions: binary and program are mutually exclusive");

  fs::path binary;
  if (has_binary) {
    binary = fs::absolute(opts.binary);
    if (!fs::exists(binary))
      throw std::runtime_error("Binary not found: " + binary.string());
  }

  auto launcher = find_launcher(ghidra_dir);
  auto script_dir = opts.script_dir.empty()
                        ? find_script_dir(ghidra_dir)
                        : fs::path(opts.script_dir);

  bool owns_project = opts.project_dir.empty();
  fs::path project_dir =
      owns_project ? fs::temp_directory_path() / "ghidra_headless_cpp"
                   : fs::path(opts.project_dir);
  fs::create_directories(project_dir);

  std::string managed_program = opts.program;
  if (has_binary) {
    try {
      managed_program =
          run_import_stage(launcher, project_dir, opts.project_name, binary,
                           opts.overwrite, opts.analyze, opts.on_output);
    } catch (...) {
      if (owns_project) {
        std::error_code ec;
        fs::remove_all(project_dir, ec);
      }
      throw;
    }
  }

  // Build argument list
  std::vector<std::string> args = {
      launcher.string(),
      project_dir.string(),
      opts.project_name,
  };
  args.push_back("-process");
  args.push_back(managed_program);
  args.push_back("-noanalysis");

  // Pass-through args for analyzeHeadless (from '--' separator).
  for (const auto& arg : opts.extra_headless_args)
    args.push_back(arg);

  args.push_back("-scriptPath");
  args.push_back(script_dir.string());
  args.push_back("-postScript");
  args.push_back("LibGhidraHeadlessServer.java");
  args.push_back("bind=" + opts.bind);
  args.push_back("port=" + std::to_string(opts.port));
  args.push_back("shutdown=" + opts.shutdown);
  if (!opts.auth_token.empty())
    args.push_back("auth=" + opts.auth_token);
  if (opts.max_runtime_seconds > 0)
    args.push_back("max_runtime_ms=" +
                    std::to_string(
                        static_cast<long long>(opts.max_runtime_seconds) * 1000));
  for (const auto& extra : opts.extra_script_args)
    args.push_back(extra);

  // Create pipe
  auto proc = std::make_unique<ProcessHandle>();
  std::unique_ptr<PipeReader> reader;

#ifdef _WIN32
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  HANDLE pipe_read = nullptr, pipe_write = nullptr;
  if (!CreatePipe(&pipe_read, &pipe_write, &sa, 0))
    throw std::runtime_error("CreatePipe failed");
  SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0);

  // Build command line string for CreateProcess
  std::string cmd_line = build_command_line(args);

  if (!proc->launch(cmd_line, pipe_write)) {
    CloseHandle(pipe_read);
    CloseHandle(pipe_write);
    throw std::runtime_error("CreateProcess failed");
  }
  CloseHandle(pipe_write);  // parent doesn't write
  reader = std::make_unique<PipeReader>(pipe_read);
#else
  int pipefd[2];
  if (pipe(pipefd) < 0) throw std::runtime_error("pipe() failed");
  if (!proc->launch(args, pipefd[1])) {
    ::close(pipefd[0]);
    ::close(pipefd[1]);
    throw std::runtime_error("fork() failed");
  }
  ::close(pipefd[1]);  // parent doesn't write
  reader = std::make_unique<PipeReader>(pipefd[0]);
#endif

  // Wait for LIBGHIDRA_HEADLESS_READY
  int actual_port = opts.port;
  auto deadline = std::chrono::steady_clock::now() + opts.startup_timeout;
  std::string line;
  bool ready = false;
  int consecutive_eof = 0;

  while (std::chrono::steady_clock::now() < deadline) {
    if (!reader->read_line(line)) {
      ++consecutive_eof;
      // If we've hit EOF multiple times, the process likely exited
      if (consecutive_eof >= 3) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }
    consecutive_eof = 0;
    if (!line.empty() && opts.on_output) opts.on_output(line);

    if (line.find(READY_BANNER) != std::string::npos) {
      // Parse port=NNNNN
      auto pos = line.find("port=");
      if (pos != std::string::npos)
        actual_port = std::atoi(line.c_str() + pos + 5);
      ready = true;
      break;
    }
  }

  if (!ready) {
    int exit_code = proc->wait(5000);
    proc->terminate();
    if (owns_project) {
      std::error_code ec;
      fs::remove_all(project_dir, ec);
    }
    if (consecutive_eof >= 3) {
      throw std::runtime_error(
          "Ghidra exited before becoming ready (exit code " +
          std::to_string(exit_code) + ")");
    }
    throw std::runtime_error("Timed out waiting for Ghidra to start");
  }

  // Connect
  std::string base_url = "http://" + opts.bind + ":" + std::to_string(actual_port);
  HttpClientOptions http_opts;
  http_opts.base_url = base_url;
  http_opts.read_timeout = opts.read_timeout;
  if (!opts.auth_token.empty())
    http_opts.auth_token = opts.auth_token;
  auto client = CreateHttpClient(std::move(http_opts));

  auto impl = std::make_unique<HeadlessClient::Impl>();
  impl->client = std::move(client);
  impl->proc = std::move(proc);
  impl->pipe = std::move(reader);
  impl->base_url = std::move(base_url);
  impl->project_dir = project_dir;
  impl->owns_project = owns_project;
  impl->on_output = std::move(opts.on_output);

  return HeadlessClient(std::move(impl));
}

}  // namespace libghidra::client
