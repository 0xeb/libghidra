// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! Launch headless Ghidra and return a connected [`GhidraClient`].

use std::collections::VecDeque;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::client::{ClientOptions, GhidraClient};
use crate::error::{Error, ErrorCode};
use crate::models::ShutdownPolicy;

const READY_BANNER: &str = "LIBGHIDRA_HEADLESS_READY";

/// Canonicalize a path, stripping the `\\?\` prefix on Windows so that
/// Java (Ghidra) can parse it.
fn clean_canonicalize(p: &str) -> std::io::Result<PathBuf> {
    let canon = std::fs::canonicalize(p)?;
    if cfg!(windows) {
        let s = canon.to_string_lossy();
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            return Ok(PathBuf::from(stripped));
        }
    }
    Ok(canon)
}

/// Options for launching headless Ghidra.
pub struct HeadlessOptions {
    pub ghidra_dir: String,
    pub binary: String,
    /// Reopen an existing program (mutually exclusive with `binary`).
    pub program: String,
    pub port: u16,
    /// Bind address for the headless server.
    pub bind: String,
    pub project_dir: String,
    pub project_name: String,
    pub analyze: bool,
    pub overwrite: bool,
    /// Shutdown policy: "save", "discard", or "none".
    pub shutdown: String,
    /// Bearer auth token.
    pub auth_token: String,
    /// Max runtime in seconds (0 = no limit, forwarded as max_runtime_ms).
    pub max_runtime_seconds: u64,
    pub bind_attempts: u32,
    pub startup_timeout: Duration,
    pub read_timeout: Duration,
    pub script_dir: String,
    pub extra_script_args: Vec<String>,
    pub on_output: Option<Box<dyn Fn(&str) + Send>>,
}

impl Default for HeadlessOptions {
    fn default() -> Self {
        Self {
            ghidra_dir: String::new(),
            binary: String::new(),
            program: String::new(),
            port: 18080,
            bind: "127.0.0.1".to_string(),
            project_dir: String::new(),
            project_name: "HeadlessProject".to_string(),
            analyze: true,
            overwrite: true,
            shutdown: "save".to_string(),
            auth_token: String::new(),
            max_runtime_seconds: 0,
            bind_attempts: 1,
            startup_timeout: Duration::from_secs(300),
            read_timeout: Duration::from_secs(300),
            script_dir: String::new(),
            extra_script_args: Vec::new(),
            on_output: None,
        }
    }
}

/// A connected client backed by a headless Ghidra process.
pub struct HeadlessClient {
    client: GhidraClient,
    child: Option<Child>,
    base_url: String,
    project_dir: PathBuf,
    owns_project_dir: bool,
    on_output: Option<Box<dyn Fn(&str) + Send>>,
}

impl HeadlessClient {
    /// The connected RPC client.
    pub fn client(&self) -> &GhidraClient {
        &self.client
    }

    /// The base URL the client is connected to.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The project directory used by this headless session.
    pub fn project_dir(&self) -> &Path {
        &self.project_dir
    }

    /// Release the process handle without killing it.
    /// After detach(), Drop and close() become no-ops for the process.
    pub fn detach(&mut self) {
        let _ = self.child.take();
        self.owns_project_dir = false;
    }

    /// Shut down the host, wait for exit, clean up. Returns the exit code.
    pub fn close(&mut self, save: bool) -> i32 {
        let policy = if save {
            ShutdownPolicy::Save
        } else {
            ShutdownPolicy::Discard
        };
        let _ = self.client.shutdown(policy);

        // Drain remaining output
        self.drain_output();

        let code = match self.child.take() {
            Some(mut c) => match c.wait() {
                Ok(s) => s.code().unwrap_or(-1),
                Err(_) => -1,
            },
            None => 0,
        };

        if self.owns_project_dir {
            let _ = std::fs::remove_dir_all(&self.project_dir);
        }
        code
    }

    fn drain_output(&mut self) {
        if let Some(ref mut child) = self.child {
            if let Some(stdout) = child.stdout.take() {
                let reader = std::io::BufReader::new(stdout);
                for line in reader.lines().map_while(|l| l.ok()) {
                    let trimmed = line.trim().to_string();
                    if !trimmed.is_empty() {
                        if let Some(ref cb) = self.on_output {
                            cb(&trimmed);
                        }
                    }
                }
            }
        }
    }
}

impl std::ops::Deref for HeadlessClient {
    type Target = GhidraClient;
    fn deref(&self) -> &GhidraClient {
        &self.client
    }
}

impl std::ops::DerefMut for HeadlessClient {
    fn deref_mut(&mut self) -> &mut GhidraClient {
        &mut self.client
    }
}

impl Drop for HeadlessClient {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        if self.owns_project_dir {
            let _ = std::fs::remove_dir_all(&self.project_dir);
        }
    }
}

fn find_launcher(ghidra_dir: &Path) -> Result<PathBuf, Error> {
    let candidates = if cfg!(windows) {
        vec![ghidra_dir.join("support").join("analyzeHeadless.bat")]
    } else {
        vec![ghidra_dir.join("support").join("analyzeHeadless")]
    };
    for c in &candidates {
        if c.exists() {
            return Ok(c.clone());
        }
    }
    Err(Error::new(
        ErrorCode::NotFound,
        format!(
            "analyzeHeadless not found in {}/support/",
            ghidra_dir.display()
        ),
    ))
}

fn find_script_dir(ghidra_dir: &Path) -> Result<PathBuf, Error> {
    let d = ghidra_dir
        .join("Ghidra")
        .join("Extensions")
        .join("LibGhidraHost")
        .join("ghidra_scripts");
    if d.exists() {
        Ok(d)
    } else {
        Err(Error::new(
            ErrorCode::NotFound,
            format!(
                "LibGhidraHost extension not installed at {}",
                d.parent().unwrap_or(&d).display()
            ),
        ))
    }
}

fn infer_imported_program_name(binary: &Path) -> Result<String, Error> {
    binary
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::ConfigError,
                format!(
                    "Unable to infer imported program name from {}",
                    binary.display()
                ),
            )
        })
}

fn run_import_stage(
    launcher: &Path,
    project_dir: &Path,
    project_name: &str,
    binary: &Path,
    overwrite: bool,
    analyze: bool,
    timeout: Duration,
    on_output: Option<&Box<dyn Fn(&str) + Send>>,
) -> Result<String, Error> {
    let mut cmd = Command::new(launcher);
    let _ = cmd
        .arg(project_dir)
        .arg(project_name)
        .arg("-import")
        .arg(binary);
    if overwrite {
        let _ = cmd.arg("-overwrite");
    }
    if !analyze {
        let _ = cmd.arg("-noanalysis");
    }
    let _ = cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());

    let mut child = cmd.spawn().map_err(|e| {
        Error::new(
            ErrorCode::TransportError,
            format!("Failed to launch import stage: {e}"),
        )
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::new(ErrorCode::TransportError, "Failed to capture import stdout"))?;
    let mut reader = std::io::BufReader::new(stdout);
    let deadline = Instant::now() + timeout;
    let mut tail: VecDeque<String> = VecDeque::with_capacity(200);
    let mut line_buf = String::new();

    while Instant::now() < deadline {
        line_buf.clear();
        match reader.read_line(&mut line_buf) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line_buf.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }
                if tail.len() == 200 {
                    let _ = tail.pop_front();
                }
                tail.push_back(trimmed.clone());
                if let Some(cb) = on_output {
                    cb(&trimmed);
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    let status = child.wait().map_err(|e| {
        Error::new(
            ErrorCode::TransportError,
            format!("Failed waiting for import stage: {e}"),
        )
    })?;
    if !status.success() {
        let tail_text = tail
            .iter()
            .rev()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Err(Error::new(
            ErrorCode::TransportError,
            format!(
                "Import stage failed with exit code {}\n{}",
                status.code().unwrap_or(-1),
                tail_text
            ),
        ));
    }

    infer_imported_program_name(binary)
}

/// Launch headless Ghidra, wait for readiness, return a connected client.
///
/// ```no_run
/// use libghidra as ghidra;
/// let mut h = ghidra::launch_headless(ghidra::HeadlessOptions {
///     ghidra_dir: "/path/to/ghidra_dist".into(),
///     binary: "/path/to/target.exe".into(),
///     ..Default::default()
/// }).unwrap();
/// let funcs = h.list_functions(0, u64::MAX, 0, 0).unwrap();
/// h.close(true);
/// ```
pub fn launch_headless(opts: HeadlessOptions) -> Result<HeadlessClient, Error> {
    let ghidra_dir = clean_canonicalize(&opts.ghidra_dir).map_err(|e| {
        Error::new(
            ErrorCode::NotFound,
            format!("Ghidra dir not found: {}: {e}", opts.ghidra_dir),
        )
    })?;

    // Validate: need either binary or program
    let has_binary = !opts.binary.is_empty();
    let has_program = !opts.program.is_empty();
    if !has_binary && !has_program {
        return Err(Error::new(
            ErrorCode::ConfigError,
            "HeadlessOptions: either binary or program must be set".to_string(),
        ));
    }
    if has_binary && has_program {
        return Err(Error::new(
            ErrorCode::ConfigError,
            "HeadlessOptions: binary and program are mutually exclusive".to_string(),
        ));
    }

    let binary = if has_binary {
        Some(clean_canonicalize(&opts.binary).map_err(|e| {
            Error::new(
                ErrorCode::NotFound,
                format!("Binary not found: {}: {e}", opts.binary),
            )
        })?)
    } else {
        None
    };

    let launcher = find_launcher(&ghidra_dir)?;
    let script_dir = if opts.script_dir.is_empty() {
        find_script_dir(&ghidra_dir)?
    } else {
        PathBuf::from(&opts.script_dir)
    };

    let owns_project_dir = opts.project_dir.is_empty();
    let project_dir = if owns_project_dir {
        std::env::temp_dir().join("ghidra_headless_rust")
    } else {
        PathBuf::from(&opts.project_dir)
    };
    std::fs::create_dir_all(&project_dir).map_err(|e| {
        Error::new(
            ErrorCode::TransportError,
            format!(
                "Failed to create headless project dir {}: {e}",
                project_dir.display()
            ),
        )
    })?;

    let mut managed_program = opts.program.clone();
    if let Some(ref bin) = binary {
        match run_import_stage(
            &launcher,
            &project_dir,
            &opts.project_name,
            bin,
            opts.overwrite,
            opts.analyze,
            opts.startup_timeout.max(opts.read_timeout),
            opts.on_output.as_ref(),
        ) {
            Ok(program_name) => managed_program = program_name,
            Err(e) => {
                if owns_project_dir {
                    let _ = std::fs::remove_dir_all(&project_dir);
                }
                return Err(e);
            }
        }
    }

    // Build command
    let mut cmd = Command::new(&launcher);
    let _ = cmd.arg(&project_dir).arg(&opts.project_name);
    let _ = cmd.arg("-process").arg(&managed_program).arg("-noanalysis");

    let _ = cmd
        .arg("-scriptPath")
        .arg(&script_dir)
        .arg("-postScript")
        .arg("LibGhidraHeadlessServer.java")
        .arg(format!("bind={}", opts.bind))
        .arg(format!("port={}", opts.port))
        .arg(format!("shutdown={}", opts.shutdown));
    if !opts.auth_token.is_empty() {
        let _ = cmd.arg(format!("auth={}", opts.auth_token));
    }
    if opts.max_runtime_seconds > 0 {
        let _ = cmd.arg(format!(
            "max_runtime_ms={}",
            opts.max_runtime_seconds as u128 * 1000
        ));
    }
    if opts.bind_attempts > 1 {
        let _ = cmd.arg(format!("bind_attempts={}", opts.bind_attempts));
    }
    for arg in &opts.extra_script_args {
        let _ = cmd.arg(arg);
    }
    let _ = cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());

    let mut child = cmd.spawn().map_err(|e| {
        Error::new(
            ErrorCode::TransportError,
            format!("Failed to launch analyzeHeadless: {e}"),
        )
    })?;

    // Merge stderr into stdout reader by taking stdout
    // (stderr is separate but we'll read stdout which has the banner)
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::new(ErrorCode::TransportError, "Failed to capture stdout"))?;

    // Wait for LIBGHIDRA_HEADLESS_READY banner using read_line so we
    // keep ownership of the BufReader and can return stdout to the child.
    let deadline = Instant::now() + opts.startup_timeout;
    let mut reader = std::io::BufReader::new(stdout);
    let mut actual_port = opts.port;
    let mut found = false;
    let on_output = &opts.on_output;
    let mut line_buf = String::new();

    while Instant::now() < deadline {
        line_buf.clear();
        match reader.read_line(&mut line_buf) {
            Ok(0) => {
                // EOF — process exited
                let code = child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
                return Err(Error::new(
                    ErrorCode::TransportError,
                    format!("Ghidra exited prematurely (code={code})"),
                ));
            }
            Ok(_) => {
                let trimmed = line_buf.trim().to_string();
                if !trimmed.is_empty() {
                    if let Some(ref cb) = on_output {
                        cb(&trimmed);
                    }
                }
                if trimmed.contains(READY_BANNER) {
                    for part in trimmed.split_whitespace() {
                        if let Some(val) = part.strip_prefix("port=") {
                            if let Ok(p) = val.parse::<u16>() {
                                actual_port = p;
                            }
                        }
                    }
                    found = true;
                    break;
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    if !found {
        let _ = child.kill();
        let _ = child.wait();
        if owns_project_dir {
            let _ = std::fs::remove_dir_all(&project_dir);
        }
        return Err(Error::new(
            ErrorCode::Timeout,
            format!(
                "Timed out after {}s waiting for Ghidra to start",
                opts.startup_timeout.as_secs()
            ),
        ));
    }

    // Return stdout to the child for drain_output later
    child.stdout = Some(reader.into_inner());

    // Connect
    let base_url = format!("http://{}:{actual_port}", opts.bind);
    let client = GhidraClient::new(ClientOptions {
        base_url: base_url.clone(),
        auth_token: opts.auth_token.clone(),
        read_timeout: opts.read_timeout,
        ..Default::default()
    });

    Ok(HeadlessClient {
        client,
        child: Some(child),
        base_url,
        project_dir,
        owns_project_dir,
        on_output: opts.on_output,
    })
}
