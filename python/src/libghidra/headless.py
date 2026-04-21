# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Launch headless Ghidra and return a connected GhidraClient."""

from collections import deque
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from .client import ClientOptions, GhidraClient

READY_BANNER = "LIBGHIDRA_HEADLESS_READY"


@dataclass
class HeadlessOptions:
    """Options for launching headless Ghidra."""

    ghidra_dir: str = ""
    binary: str = ""
    program: str = ""                 # reopen existing (mutually exclusive with binary)
    port: int = 18080
    bind: str = "127.0.0.1"          # bind address for the headless server
    project_dir: str = ""
    project_name: str = "HeadlessProject"
    analyze: bool = True
    overwrite: bool = True
    shutdown: str = "save"            # "save", "discard", or "none"
    auth_token: str = ""              # bearer auth token
    max_runtime_seconds: int = 0      # 0 = no limit (forwarded as max_runtime_ms)
    bind_attempts: int = 1
    startup_timeout: float = 300.0
    read_timeout: float = 300.0
    script_dir: str = ""              # override script dir (empty = auto-detect)
    extra_script_args: List[str] = field(default_factory=list)
    on_output: Optional[Callable[[str], None]] = None


class HeadlessClient:
    """A GhidraClient backed by a headless Ghidra process.

    Use as a context manager or call close() when done.
    """

    def __init__(self, client: GhidraClient, proc: subprocess.Popen,
                 project_dir: Path, owns_project_dir: bool,
                 base_url: str,
                 on_output: Optional[Callable[[str], None]] = None):
        self._client = client
        self._proc = proc
        self._project_dir = project_dir
        self._owns_project_dir = owns_project_dir
        self._base_url = base_url
        self._on_output = on_output

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

    def close(self, save: bool = True) -> int:
        """Shut down the Ghidra host and wait for the process to exit."""
        from .models import ShutdownPolicy
        try:
            policy = ShutdownPolicy.SAVE if save else ShutdownPolicy.DISCARD
            self._client.shutdown(policy)
        except Exception:
            pass

        # Drain remaining output
        if self._proc.stdout:
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
    for name in ("support/analyzeHeadless.bat", "support/analyzeHeadless"):
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


def _infer_imported_program_name(binary: Path) -> str:
    return binary.name


def _stream_process_output(
        proc: subprocess.Popen,
        timeout: float,
        on_output: Optional[Callable[[str], None]] = None) -> list[str]:
    deadline = time.monotonic() + timeout
    tail: deque[str] = deque(maxlen=200)
    while True:
        line = proc.stdout.readline() if proc.stdout else ""
        if line:
            line = line.strip()
            if line:
                tail.append(line)
                if on_output:
                    on_output(line)
            continue
        if proc.poll() is not None:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Timed out after {timeout}s waiting for analyzeHeadless to finish")
        time.sleep(0.1)
    return list(tail)


def _run_import_stage(
        launcher: Path,
        project_dir: Path,
        project_name: str,
        binary: Path,
        overwrite: bool,
        analyze: bool,
        timeout: float,
        on_output: Optional[Callable[[str], None]] = None) -> str:
    cmd = [
        str(launcher),
        str(project_dir), project_name,
        "-import", str(binary),
    ]
    if overwrite:
        cmd.append("-overwrite")
    if not analyze:
        cmd.append("-noanalysis")

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1)
    try:
        tail = _stream_process_output(proc, timeout, on_output)
    except BaseException:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise

    if proc.wait() != 0:
        tail_text = "\n".join(tail[-20:])
        raise RuntimeError(
            f"Import stage failed with exit code {proc.returncode}\n{tail_text}")

    return _infer_imported_program_name(binary)


def launch_headless(opts: HeadlessOptions) -> HeadlessClient:
    """Launch headless Ghidra, wait for readiness, return a connected client.

    >>> import libghidra as ghidra
    >>> with ghidra.launch_headless(ghidra.HeadlessOptions(
    ...     ghidra_dir="/path/to/ghidra_dist",
    ...     binary="/path/to/target.exe",
    ... )) as h:
    ...     funcs = h.list_functions()
    """
    ghidra_dir = Path(opts.ghidra_dir).resolve()

    # Validate: need either binary or program
    has_binary = bool(opts.binary)
    has_program = bool(opts.program)
    if not has_binary and not has_program:
        raise ValueError("HeadlessOptions: either binary or program must be set")
    if has_binary and has_program:
        raise ValueError("HeadlessOptions: binary and program are mutually exclusive")

    if has_binary:
        binary = Path(opts.binary).resolve()
        if not binary.exists():
            raise FileNotFoundError(f"Binary not found: {binary}")

    launcher = _find_launcher(ghidra_dir)

    if opts.script_dir:
        script_dir = Path(opts.script_dir)
    else:
        script_dir = _find_script_dir(ghidra_dir)

    owns_project_dir = not opts.project_dir
    project_dir = Path(opts.project_dir) if opts.project_dir else Path(
        tempfile.mkdtemp(prefix="ghidra_headless_"))

    on_output = opts.on_output

    managed_program = opts.program
    if has_binary:
        try:
            # analyzeHeadless only persists imported programs after the import run exits.
            # Start the live RPC server on the saved project program, not the import-phase object.
            managed_program = _run_import_stage(
                launcher,
                project_dir,
                opts.project_name,
                binary,
                opts.overwrite,
                opts.analyze,
                max(opts.startup_timeout, opts.read_timeout),
                on_output,
            )
        except BaseException:
            if owns_project_dir:
                shutil.rmtree(project_dir, ignore_errors=True)
            raise

    # Build analyzeHeadless command
    cmd = [
        str(launcher),
        str(project_dir), opts.project_name,
    ]

    cmd += ["-process", managed_program]
    cmd.append("-noanalysis")

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
    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"Ghidra exited prematurely (code={proc.returncode})")
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            line = line.strip()
            if line and on_output:
                on_output(line)
            if READY_BANNER in line:
                for part in line.split():
                    if part.startswith("port="):
                        actual_port = int(part.split("=", 1)[1])
                break
        else:
            raise TimeoutError(
                f"Timed out after {opts.startup_timeout}s waiting for Ghidra")
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

    return HeadlessClient(client, proc, project_dir, owns_project_dir,
                          base_url, on_output)
