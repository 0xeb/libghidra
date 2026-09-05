// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// Launch headless Ghidra via analyzeHeadless, wait for
// LIBGHIDRA_HEADLESS_READY, then return a connected HttpClient.

#include "libghidra/headless.hpp"
#include "libghidra/http.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <cerrno>
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

// Wraps a process plus a Job Object on Windows so the whole process tree
// (cmd.exe → analyzeHeadless.bat → java.exe) can be killed atomically.
// TerminateProcess only kills the immediate process; without a Job, the
// java.exe child outlives a `cmd /c` parent kill and keeps holding the
// HTTP socket and project lock files, defeating force-kill.
class ProcessHandle {
 public:
  ProcessHandle() {
    job_ = CreateJobObjectW(nullptr, nullptr);
    if (job_) {
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
      info.BasicLimitInformation.LimitFlags =
          JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      SetInformationJobObject(job_, JobObjectExtendedLimitInformation,
                              &info, sizeof(info));
    }
  }
  ~ProcessHandle() {
    close_handles();
    if (job_) {
      // Closing the job handle with KILL_ON_JOB_CLOSE causes the OS to
      // terminate every process still in the job. Belt-and-suspenders
      // safety net for the case where wait()/terminate() didn't run.
      CloseHandle(job_);
      job_ = nullptr;
    }
  }

  ProcessHandle(const ProcessHandle&) = delete;
  ProcessHandle& operator=(const ProcessHandle&) = delete;

  bool launch(const std::string& cmd_line, HANDLE read_pipe) {
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = read_pipe;
    si.hStdError = read_pipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    // The whole point of this dance is to guarantee the java.exe descendant
    // ends up inside *our* Job Object, so JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    // reaps the whole tree when this process exits or dies. A child that is
    // NOT in our job becomes a zombie: it broke away from the parent's job
    // (or never joined ours) and nothing reaps it → leaked JVM holding the
    // RPC port and project locks.
    //
    // Strategy (orphan-risk minimising):
    //   1. Try CreateProcess WITHOUT CREATE_BREAKAWAY_FROM_JOB. If we are not
    //      inside a restrictive outer job, the child is naturally created
    //      inside our job via the default nested-job inheritance, and the
    //      AssignProcessToJobObject below is a harmless no-op/confirmation.
    //   2. Only if the subsequent AssignProcessToJobObject fails with
    //      ERROR_ACCESS_DENIED (the "child is already in a job that disallows
    //      nesting" condition — a restrictive outer job) do we tear the child
    //      down and retry the whole create WITH CREATE_BREAKAWAY_FROM_JOB so
    //      it can leave that outer job and join ours instead.
    //
    // In EVERY path: if we cannot prove the child landed in our job, we do
    // NOT leave it running — we TerminateProcess it and fail the launch,
    // rather than leak an unmanaged orphan. CREATE_SUSPENDED → assign →
    // ResumeThread ordering is preserved: assigning before the first thread
    // runs is what guarantees the child's own descendants inherit the job.

    // Attempt a create with the given flags, then try to assign to our job.
    // Returns:
    //   0  = success (child created AND in our job, still suspended)
    //   1  = created but assign failed with ERROR_ACCESS_DENIED (caller may
    //        retry with breakaway); child has already been terminated+reaped
    //  -1  = hard failure (create failed, or assign failed for another reason
    //        and the orphan was terminated); do not retry
    auto try_launch = [&](DWORD flags) -> int {
      cmd_buf_ = cmd_line;  // CreateProcess needs a mutable buffer
      BOOL ok = CreateProcessA(
          nullptr, cmd_buf_.data(), nullptr, nullptr,
          TRUE,  // inherit handles
          flags, nullptr, nullptr, &si, &pi_);
      if (!ok) return -1;

      if (!job_) {
        // No job object at all (CreateJobObject failed in the ctor). We cannot
        // guarantee reaping via the job, but this is the same best-effort mode
        // the code has always fallen back to; keep the child and rely on
        // terminate()'s TerminateProcess path. Nothing to assign.
        return 0;
      }

      if (AssignProcessToJobObject(job_, pi_.hProcess)) {
        return 0;  // child is safely in our job
      }

      // Assign failed. The child is now an UNMANAGED ORPHAN candidate: if we
      // used CREATE_BREAKAWAY_FROM_JOB it has left the parent's job and joined
      // none; even without breakaway, a failed assign means we can't prove it
      // is in our job. Either way, never leave it running.
      DWORD err = GetLastError();
      TerminateProcess(pi_.hProcess, 1);
      WaitForSingleObject(pi_.hProcess, 5000);
      close_handles();
      pi_ = PROCESS_INFORMATION{};
      // ERROR_ACCESS_DENIED here means the child is already in an outer job
      // that disallows nesting → the caller can retry WITH breakaway.
      return (err == ERROR_ACCESS_DENIED) ? 1 : -1;
    };

    // Step 1: create WITHOUT breakaway (natural nested-job inheritance).
    int r = try_launch(CREATE_NO_WINDOW | CREATE_SUSPENDED);
    if (r == 1) {
      // Step 2: restrictive outer job → retry WITH breakaway so we can leave
      // it and join ours. Some sandboxes (Windows Containers) reject breakaway
      // entirely; that surfaces as a create failure (-1) below.
      r = try_launch(CREATE_NO_WINDOW | CREATE_SUSPENDED |
                     CREATE_BREAKAWAY_FROM_JOB);
    }
    if (r != 0) return false;  // hard failure; orphan (if any) already killed

    ResumeThread(pi_.hThread);
    alive_ = true;
    return true;
  }

  bool alive() const { return alive_; }

  // Counterpart to the POSIX detach(). HeadlessClient::detach() calls this from
  // common, un-ifdef'd code, so the member must exist on both platforms.
  //
  // Nothing to do here. The POSIX side needs an explicit guardian process
  // because it has no way to be told "kill this process tree when its owner
  // dies" -- it forks a watcher that blocks on a pipe and reaps on EOF. Windows
  // gets that from the kernel: the child is in a Job Object created with
  // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (see launch()), so the OS terminates the
  // whole tree when the last job handle closes, including on an abnormal exit
  // where no destructor runs. Detaching therefore means only "stop managing
  // it", which the caller's own bookkeeping already records.
  void detach() {}

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
      // TerminateJobObject kills every process in the job (cmd.exe,
      // analyzeHeadless.bat, java.exe, conhost.exe). TerminateProcess
      // by itself only kills the immediate child and would leave the
      // java.exe descendant alive, defeating the bounded close().
      if (job_) {
        TerminateJobObject(job_, 1);
      } else {
        TerminateProcess(pi_.hProcess, 1);
      }
      wait(10000);
    }
  }

 private:
  void close_handles() {
    if (pi_.hProcess) CloseHandle(pi_.hProcess);
    if (pi_.hThread) CloseHandle(pi_.hThread);
  }

  PROCESS_INFORMATION pi_{};
  HANDLE job_ = nullptr;
  std::string cmd_buf_;
  int exit_code_ = 0;
  bool alive_ = false;
};

#else  // POSIX

class ProcessHandle {
 public:
  ProcessHandle() = default;
  ~ProcessHandle() { finish_guardian(/*detach=*/false); }

  ProcessHandle(const ProcessHandle&) = delete;
  ProcessHandle& operator=(const ProcessHandle&) = delete;

  bool launch(const std::vector<std::string>& args, int write_fd) {
    int lifetime_pipe[2];
    if (pipe(lifetime_pipe) < 0) return false;

    pid_ = fork();
    if (pid_ < 0) {
      close(lifetime_pipe[0]);
      close(lifetime_pipe[1]);
      return false;
    }
    if (pid_ == 0) {
      // Only the C++ parent may retain the write end. A separate guardian
      // below blocks on the read end and treats EOF as proof that the parent
      // disappeared, including SIGKILL where no destructor can run.
      close(lifetime_pipe[0]);
      close(lifetime_pipe[1]);
      // Child. Lead a new process group so the whole tree
      // (analyzeHeadless -> launch.sh -> java) can be force-killed together
      // via kill(-pid_) in terminate() -- the POSIX analog of the Windows
      // Job Object above. Without this, signalling only pid_ orphans the java
      // grandchild, which keeps holding the HTTP socket and project locks and
      // defeats force-kill.
      setpgid(0, 0);
      dup2(write_fd, STDOUT_FILENO);
      dup2(write_fd, STDERR_FILENO);
      close(write_fd);
      std::vector<char*> argv;
      for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
      argv.push_back(nullptr);
      execvp(argv[0], argv.data());
      _exit(127);
    }
    // Parent: also make pid_ its own group leader so terminate()'s kill(-pid_)
    // can never race the child's own setpgid() -- whichever call runs first wins
    // and both are idempotent. Without this, a terminate() firing in the window
    // before the child reaches setpgid() would target a group that does not exist
    // yet (ESRCH) and miss the tree. EACCES here just means the child already
    // execvp'd and set the group first, which is fine.
    setpgid(pid_, pid_);

    // A process group makes explicit terminate() reliable, but it cannot act
    // when this parent is itself killed. Keep a tiny async-signal-safe
    // guardian outside the host's process group. It owns only the lifetime
    // pipe's read end; EOF means every copy of the parent's write end closed,
    // so it kills the entire analyzeHeadless -> launch.sh -> java group.
    guardian_pid_ = fork();
    if (guardian_pid_ < 0) {
      close(lifetime_pipe[0]);
      close(lifetime_pipe[1]);
      kill(-pid_, SIGKILL);
      int status = 0;
      while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
      }
      pid_ = -1;
      return false;
    }
    if (guardian_pid_ == 0) {
      close(lifetime_pipe[1]);
      char ignored = 0;
      ssize_t n;
      do {
        n = read(lifetime_pipe[0], &ignored, 1);
      } while (n < 0 && errno == EINTR);
      close(lifetime_pipe[0]);
      if (n == 0) {
        kill(-pid_, SIGKILL);
      }
      _exit(0);
    }

    close(lifetime_pipe[0]);
    lifetime_write_fd_ = lifetime_pipe[1];
    alive_ = true;
    return true;
  }

  bool alive() const { return alive_; }

  int wait(int timeout_ms = -1) {
    if (!alive_) return exit_code_;
    int status = 0;
    bool reaped = false;
    if (timeout_ms < 0) {
      int r;
      do {
        r = waitpid(pid_, &status, 0);
      } while (r < 0 && errno == EINTR);
      if (r < 0) {
        // waitpid failed for a non-EINTR reason (e.g. ECHILD: the child was
        // already reaped elsewhere). The child is gone -- mark not-alive and
        // return so a later terminate() does not kill(-pid_) and then poll
        // WNOHANG for the full timeout against a process that no longer exists.
        alive_ = false;
        finish_guardian(/*detach=*/false);
        return exit_code_;
      }
      reaped = (r > 0);
    } else {
      // Poll with timeout
      auto deadline = std::chrono::steady_clock::now() +
                      std::chrono::milliseconds(timeout_ms);
      while (std::chrono::steady_clock::now() < deadline) {
        int r = waitpid(pid_, &status, WNOHANG);
        if (r > 0) { reaped = true; break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
    if (!reaped) {
      // Timed out (or interrupted) without reaping: the child is still
      // running. Leave alive_ true so callers (e.g. close()) can escalate to
      // terminate() (force-kill). Mirrors the Windows WAIT_TIMEOUT path, which
      // returns -1 without clearing alive_. The previous code unconditionally
      // set alive_ = false here, so force-kill never fired on POSIX.
      return -1;
    }
    exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    alive_ = false;
    finish_guardian(/*detach=*/false);
    return exit_code_;
  }

  void terminate() {
    if (alive_) {
      // Kill the whole process group (analyzeHeadless -> launch.sh -> java),
      // the POSIX analog of the Windows Job Object. pid_ is its own group
      // leader (setpgid in launch()), so kill(-pid_) targets the entire tree.
      // SIGKILL because this is the force path: graceful shutdown was already
      // attempted via the Shutdown RPC. Killing java closes the HTTP socket,
      // which unblocks close()'s shutdown/drain joins.
      kill(-pid_, SIGKILL);
      wait(10000);
    }
  }

  void detach() { finish_guardian(/*detach=*/true); }

 private:
  void finish_guardian(bool detach) {
    if (guardian_pid_ <= 0 && lifetime_write_fd_ < 0) return;

    if (detach && guardian_pid_ > 0) {
      // detach() deliberately transfers lifecycle ownership to the caller's
      // environment. Stop the guardian before closing the pipe so EOF cannot
      // be mistaken for an abnormal parent exit.
      kill(guardian_pid_, SIGTERM);
    }
    if (lifetime_write_fd_ >= 0) {
      close(lifetime_write_fd_);
      lifetime_write_fd_ = -1;
    }
    if (guardian_pid_ > 0) {
      int status = 0;
      while (waitpid(guardian_pid_, &status, 0) < 0 && errno == EINTR) {
      }
      guardian_pid_ = -1;
    }
  }

  pid_t pid_ = -1;
  pid_t guardian_pid_ = -1;
  int lifetime_write_fd_ = -1;
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
  ~Impl() {
    if (detached) {
      if (drain_thread.joinable()) drain_thread.detach();
      return;
    }
    if (proc && proc->alive()) {
      proc->terminate();
    }
    if (drain_thread.joinable()) drain_thread.join();
  }

  std::unique_ptr<IClient> client;
  std::unique_ptr<ProcessHandle> proc;
  std::shared_ptr<PipeReader> pipe;
  std::thread drain_thread;
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
  impl_->proc->detach();
  impl_->detached = true;
  impl_->owns_project = false;
}

int HeadlessClient::wait() {
  if (impl_->detached) return 0;
  int code = impl_->proc->wait();
  if (impl_->drain_thread.joinable()) impl_->drain_thread.join();
  impl_->pipe.reset();
  return code;
}

int HeadlessClient::close(ShutdownPolicy policy,
                          std::chrono::milliseconds timeout) {
  if (impl_->detached) return 0;

  // The previous implementation blocked here on two unbounded waits:
  //   (1) client->Shutdown(...) — blocks up to read_timeout (5 min default)
  //       if Java doesn't ack;
  //   (2) joining the output-drain thread — blocks until the child closes stdout.
  // If Java was wedged on a stuck decompiler/parser, both waits stalled
  // and the wrapper hung indefinitely with the process tree intact (this
  // matches the symptom in the pain-points report Issue 6).
  //
  // The fix runs both in detached worker threads. The main thread waits
  // for the child up to `timeout`; if the child hasn't exited by then it
  // is force-killed. Killing the child closes both the HTTP socket
  // (unblocking the Shutdown thread) and the output pipe (unblocking the
  // drain thread), so we can join them cleanly afterwards.

  auto deadline = std::chrono::steady_clock::now() + timeout;

  // Worker: send the Shutdown RPC. May block on a wedged host; force-kill
  // below will close the socket and unblock it.
  std::thread shutdown_thread(
      [client = impl_->client.get(), policy] {
        try {
          client->Shutdown(policy);
        } catch (...) {
          // RPC may legitimately fail (timeout, connection reset on
          // force-kill); not our concern here.
        }
      });

  // Wait for the child to exit on its own up to the remaining budget.
  auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - std::chrono::steady_clock::now()).count();
  if (remaining < 1) remaining = 1;
  int code = impl_->proc->wait(static_cast<unsigned long>(remaining));

  bool force_killed = false;
  if (impl_->proc->alive()) {
    impl_->proc->terminate();
    force_killed = true;
    if (impl_->on_output) {
      impl_->on_output(
          "[libghidra] headless host did not exit within " +
          std::to_string(timeout.count()) + "ms; force-killed");
    }
  }

  // Both worker threads should now unblock: the drain via pipe EOF, the
  // Shutdown RPC via socket close. Join them before tearing down impl_
  // so the workers don't see freed memory.
  if (impl_->drain_thread.joinable()) impl_->drain_thread.join();
  if (shutdown_thread.joinable()) shutdown_thread.join();

  impl_->pipe.reset();

  if (impl_->owns_project) {
    std::error_code ec;
    fs::remove_all(impl_->project_dir, ec);
  }
  return force_killed ? -2 : code;
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

// ---------------------------------------------------------------------------
// LaunchHeadlessProject
// ---------------------------------------------------------------------------

HeadlessClient LaunchHeadlessProject(HeadlessProjectOptions opts) {
  auto ghidra_dir = fs::absolute(opts.ghidra_dir);

  auto launcher = find_launcher(ghidra_dir);
  auto script_dir = opts.script_dir.empty()
                        ? find_script_dir(ghidra_dir)
                        : fs::path(opts.script_dir);

  bool owns_project = opts.project_dir.empty();
  const auto unique_suffix =
      std::chrono::steady_clock::now().time_since_epoch().count();
  fs::path project_dir = owns_project
      ? fs::temp_directory_path() /
            ("ghidra_headless_cpp_" + std::to_string(unique_suffix))
      : fs::path(opts.project_dir);
  fs::create_directories(project_dir);

  // Build argument list. No -import and no -process: Ghidra creates/opens
  // the project, runs the server script without an active program, and the
  // caller drives ImportProgram/OpenProgram explicitly over RPC.
  std::vector<std::string> args = {
      launcher.string(),
      project_dir.string(),
      opts.project_name,
  };
  for (const auto& arg : opts.extra_headless_args) args.push_back(arg);
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
  std::shared_ptr<PipeReader> reader;

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
  reader = std::make_shared<PipeReader>(pipe_read);
#else
  int pipefd[2];
  if (pipe(pipefd) < 0) throw std::runtime_error("pipe() failed");
  if (!proc->launch(args, pipefd[1])) {
    ::close(pipefd[0]);
    ::close(pipefd[1]);
    throw std::runtime_error("fork() failed");
  }
  ::close(pipefd[1]);  // parent doesn't write
  reader = std::make_shared<PipeReader>(pipefd[0]);
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
  impl->drain_thread = std::thread(
      [reader = impl->pipe, on_output = impl->on_output] {
        std::string output_line;
        while (reader && reader->read_line(output_line)) {
          if (!output_line.empty() && on_output) on_output(output_line);
        }
      });

  return HeadlessClient(std::move(impl));
}

}  // namespace libghidra::client
