# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
"""Launch headless Ghidra and return a connected GhidraClient."""

from collections import deque
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional
from urllib.parse import urlparse

from .client import ClientOptions, GhidraClient

READY_BANNER = "LIBGHIDRA_HEADLESS_READY"


@dataclass
class HeadlessProjectOptions:
    """Options for launching a project-scoped headless Ghidra RPC host."""

    ghidra_dir: str = ""
    port: int = 18080
    bind: str = "127.0.0.1"          # bind address for the headless server
    project_dir: str = ""
    project_name: str = "HeadlessProject"
    shutdown: str = "save"            # "save", "discard", or "none"
    auth_token: str = ""              # bearer auth token
    max_runtime_seconds: int = 0      # 0 = no limit (forwarded as max_runtime_ms)
    bind_attempts: int = 1
    startup_timeout: float = 300.0
    read_timeout: float = 300.0
    script_dir: str = ""              # override script dir (empty = auto-detect)
    extra_script_args: List[str] = field(default_factory=list)
    extra_headless_args: List[str] = field(default_factory=list)
    on_output: Optional[Callable[[str], None]] = None


class HeadlessClient:
    """A GhidraClient backed by a headless Ghidra process.

    Use as a context manager or call close() when done.
    """

    def __init__(self, client: GhidraClient, proc: subprocess.Popen,
                 project_dir: Path, owns_project_dir: bool,
                 base_url: str,
                 shutdown_policy: int,
                 on_output: Optional[Callable[[str], None]] = None,
                 output_thread: Optional[threading.Thread] = None):
        self._client = client
        self._proc = proc
        self._project_dir = project_dir
        self._owns_project_dir = owns_project_dir
        self._base_url = base_url
        self._shutdown_policy = shutdown_policy
        self._on_output = on_output
        self._output_thread = output_thread

    @property
    def client(self) -> GhidraClient:
        return self._client

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def process(self) -> subprocess.Popen:
        return self._proc

    @property
    def project_dir(self) -> Path:
        return self._project_dir

    def detach(self) -> None:
        """Release the process handle without killing it.

        After detach(), close() and __exit__ become no-ops for the process.
        """
        self._proc = None
        self._owns_project_dir = False

    def close(self, save: bool | None = None) -> int:
        """Shut down the Ghidra host and wait for the process to exit."""
        if self._proc is None:
            return 0

        from .models import ShutdownPolicy
        shutdown_requested = False
        try:
            if save is None:
                policy = ShutdownPolicy(self._shutdown_policy)
            else:
                policy = ShutdownPolicy.SAVE if save else ShutdownPolicy.DISCARD
            self._client.shutdown(policy)
            shutdown_requested = True
        except Exception:
            pass

        if shutdown_requested:
            _wait_for_endpoint_closed(self._base_url, timeout=60.0)

        # Keep draining synchronously only for older callers without a drainer.
        if self._proc.stdout and self._output_thread is None:
            for line in self._proc.stdout:
                line = line.strip()
                if line and self._on_output:
                    self._on_output(line)

        try:
            self._proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=10)

        exit_code = self._proc.returncode
        if self._output_thread is not None:
            self._output_thread.join(timeout=5)

        if self._owns_project_dir:
            shutil.rmtree(self._project_dir, ignore_errors=True)

        return exit_code

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __getattr__(self, name):
        """Delegate all GhidraClient methods directly."""
        return getattr(self._client, name)


def _find_launcher(ghidra_dir: Path) -> Path:
    names = (
        ("support/analyzeHeadless.bat", "support/analyzeHeadless")
        if os.name == "nt"
        else ("support/analyzeHeadless", "support/analyzeHeadless.bat")
    )
    for name in names:
        p = ghidra_dir / name
        if p.exists():
            return p
    raise FileNotFoundError(
        f"analyzeHeadless not found in {ghidra_dir}/support/")


def _find_script_dir(ghidra_dir: Path) -> Path:
    d = ghidra_dir / "Ghidra" / "Extensions" / "LibGhidraHost" / "ghidra_scripts"
    if not d.exists():
        raise FileNotFoundError(
            f"LibGhidraHost extension not installed at {d.parent}\n"
            "Install it first: gradle installExtension -PGHIDRA_INSTALL_DIR=<dist>")
    return d


def _emit_output_line(line: str, on_output: Optional[Callable[[str], None]]) -> None:
    line = line.strip()
    if line and on_output:
        on_output(line)


def _start_output_drain(
        proc: subprocess.Popen,
        on_output: Optional[Callable[[str], None]] = None) -> Optional[threading.Thread]:
    if proc.stdout is None:
        return None

    def drain() -> None:
        try:
            for line in proc.stdout:
                _emit_output_line(line, on_output)
        except Exception:
            pass

    thread = threading.Thread(
        target=drain,
        name="libghidra-headless-output",
        daemon=True)
    thread.start()
    return thread


def _shutdown_policy_value(name: str) -> int:
    from .models import ShutdownPolicy
    normalized = name.strip().lower()
    if normalized == "save":
        return int(ShutdownPolicy.SAVE)
    if normalized == "discard":
        return int(ShutdownPolicy.DISCARD)
    if normalized == "none":
        return int(ShutdownPolicy.NONE)
    return int(ShutdownPolicy.UNSPECIFIED)


def _wait_for_endpoint_closed(base_url: str, timeout: float) -> bool:
    parsed = urlparse(base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                pass
        except OSError:
            return True
        time.sleep(0.2)

    return False


def _append_output_line(
        tail: deque[str],
        line: str,
        on_output: Optional[Callable[[str], None]] = None) -> None:
    line = line.strip()
    if not line:
        return
    tail.append(line)
    if on_output:
        on_output(line)


def _drain_remaining_output(
        proc: subprocess.Popen,
        tail: deque[str],
        on_output: Optional[Callable[[str], None]] = None) -> None:
    if proc.stdout is None or proc.poll() is None:
        return
    for line in proc.stdout.readlines():
        _append_output_line(tail, line, on_output)


def _format_tail(tail: deque[str] | list[str]) -> str:
    if not tail:
        return ""
    lines = list(tail)
    diagnostic_terms = ("ERROR", "Exception", "BindException", "Address already")
    diagnostic_lines = [
        line for line in lines
        if any(term in line for term in diagnostic_terms)
    ][-12:]
    recent_lines = lines[-40:]
    selected: list[str] = []
    seen: set[str] = set()
    for line in [*diagnostic_lines, *recent_lines]:
        if line in seen:
            continue
        seen.add(line)
        selected.append(line)
    return "\nRecent Ghidra output:\n" + "\n".join(f"  {line}" for line in selected)


def launch_headless_project(opts: HeadlessProjectOptions) -> HeadlessClient:
    """Launch a project-scoped headless Ghidra host and return a client.

    >>> import libghidra as ghidra
    >>> with ghidra.launch_headless_project(ghidra.HeadlessProjectOptions(
    ...     ghidra_dir="/path/to/ghidra_dist",
    ... )) as h:
    ...     imported = h.import_program(ghidra.ImportProgramRequest(
    ...         source_path="/path/to/target.exe", analyze=True, overwrite=True))
    ...     h.open_program(ghidra.OpenProgramRequest(
    ...         program_path=imported.primary_program_path))
    """
    ghidra_dir = Path(opts.ghidra_dir).resolve()

    launcher = _find_launcher(ghidra_dir)

    if opts.script_dir:
        script_dir = Path(opts.script_dir)
    else:
        script_dir = _find_script_dir(ghidra_dir)

    owns_project_dir = not opts.project_dir
    project_dir = Path(opts.project_dir) if opts.project_dir else Path(
        tempfile.mkdtemp(prefix="ghidra_headless_"))
    project_dir.mkdir(parents=True, exist_ok=True)

    on_output = opts.on_output

    # Start analyzeHeadless with scripts but without -import/-process. Ghidra
    # creates/opens the project and runs the script with no active program;
    # ImportProgram/OpenProgram RPCs drive the project after READY.
    cmd = [
        str(launcher),
        str(project_dir), opts.project_name,
    ]
    cmd.extend(opts.extra_headless_args)
    cmd += [
        "-scriptPath", str(script_dir),
        "-postScript", "LibGhidraHeadlessServer.java",
        f"bind={opts.bind}",
        f"port={opts.port}",
        f"shutdown={opts.shutdown}",
    ]
    if opts.auth_token:
        cmd.append(f"auth={opts.auth_token}")
    if opts.max_runtime_seconds > 0:
        cmd.append(f"max_runtime_ms={opts.max_runtime_seconds * 1000}")
    if opts.bind_attempts > 1:
        cmd.append(f"bind_attempts={opts.bind_attempts}")
    cmd.extend(opts.extra_script_args)

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1)

    # Wait for LIBGHIDRA_HEADLESS_READY banner
    actual_port = opts.port
    deadline = time.monotonic() + opts.startup_timeout
    tail: deque[str] = deque(maxlen=200)
    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                _drain_remaining_output(proc, tail, on_output)
                raise RuntimeError(
                    f"Ghidra exited prematurely (code={proc.returncode})"
                    f"{_format_tail(tail)}")
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            _append_output_line(tail, line, on_output)
            if READY_BANNER in line:
                for part in line.split():
                    if part.startswith("port="):
                        actual_port = int(part.split("=", 1)[1])
                break
        else:
            _drain_remaining_output(proc, tail, on_output)
            raise TimeoutError(
                f"Timed out after {opts.startup_timeout}s waiting for Ghidra"
                f"{_format_tail(tail)}")
    except BaseException:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if owns_project_dir:
            shutil.rmtree(project_dir, ignore_errors=True)
        raise

    # Connect
    base_url = f"http://{opts.bind}:{actual_port}"
    client_opts = ClientOptions(
        base_url=base_url,
        read_timeout=opts.read_timeout,
    )
    if opts.auth_token:
        client_opts.auth_token = opts.auth_token
    client = GhidraClient(client_opts)

    output_thread = _start_output_drain(proc, on_output)
    return HeadlessClient(client, proc, project_dir, owns_project_dir,
                          base_url, _shutdown_policy_value(opts.shutdown),
                          on_output, output_thread)
