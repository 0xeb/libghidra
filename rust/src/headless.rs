// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//! Launch headless Ghidra and return a connected [`GhidraClient`].

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// A sink for a headless host's stdout lines (progress/log streaming).
pub type OutputCallback = Box<dyn Fn(&str) + Send>;

/// Options for launching a project-scoped headless Ghidra RPC host.
pub struct HeadlessProjectOptions {
    pub ghidra_dir: String,
    pub port: u16,
    /// Bind address for the headless server.
    pub bind: String,
    pub project_dir: String,
    pub project_name: String,
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
    pub extra_headless_args: Vec<String>,
    pub on_output: Option<OutputCallback>,
}

impl Default for HeadlessProjectOptions {
    fn default() -> Self {
        Self {
            ghidra_dir: String::new(),
            port: 18080,
            bind: "127.0.0.1".to_string(),
            project_dir: String::new(),
            project_name: "HeadlessProject".to_string(),
            shutdown: "save".to_string(),
            auth_token: String::new(),
            max_runtime_seconds: 0,
            bind_attempts: 1,
            startup_timeout: Duration::from_secs(300),
            read_timeout: Duration::from_secs(300),
            script_dir: String::new(),
            extra_script_args: Vec::new(),
            extra_headless_args: Vec::new(),
            on_output: None,
        }
    }
}

/// A connected client backed by a headless Ghidra process.
pub struct HeadlessClient {
    client: GhidraClient,
    child: Option<Child>,
    output_thread: Option<JoinHandle<()>>,
    base_url: String,
    project_dir: PathBuf,
    owns_project_dir: bool,
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
        let _ = self.output_thread.take();
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

        let code = match self.child.take() {
            Some(mut c) => match c.wait() {
                Ok(s) => s.code().unwrap_or(-1),
                Err(_) => -1,
            },
            None => 0,
        };

        if let Some(output_thread) = self.output_thread.take() {
            let _ = output_thread.join();
        }

        if self.owns_project_dir {
            let _ = std::fs::remove_dir_all(&self.project_dir);
        }
        code
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
        if let Some(output_thread) = self.output_thread.take() {
            let _ = output_thread.join();
        }
        if self.owns_project_dir {
            let _ = std::fs::remove_dir_all(&self.project_dir);
        }
    }
}

fn emit_output_line(line: &str, on_output: Option<&(dyn Fn(&str) + Send)>) {
    let trimmed = line.trim();
    if !trimmed.is_empty() {
        if let Some(cb) = on_output {
            cb(trimmed);
        }
    }
}

fn start_output_drainer(
    stdout: ChildStdout,
    on_output: Option<OutputCallback>,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("libghidra-headless-output".to_string())
        .spawn(move || {
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines().map_while(|l| l.ok()) {
                emit_output_line(&line, on_output.as_deref());
            }
        })
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

/// Launch a project-scoped headless Ghidra host and return a connected client.
///
/// ```no_run
/// use libghidra as ghidra;
/// let mut h = ghidra::launch_headless_project(ghidra::HeadlessProjectOptions {
///     ghidra_dir: "/path/to/ghidra_dist".into(),
///     ..Default::default()
/// }).unwrap();
/// h.close(true);
/// ```
pub fn launch_headless_project(opts: HeadlessProjectOptions) -> Result<HeadlessClient, Error> {
    let ghidra_dir = clean_canonicalize(&opts.ghidra_dir).map_err(|e| {
        Error::new(
            ErrorCode::NotFound,
            format!("Ghidra dir not found: {}: {e}", opts.ghidra_dir),
        )
    })?;

    let launcher = find_launcher(&ghidra_dir)?;
    let script_dir = if opts.script_dir.is_empty() {
        find_script_dir(&ghidra_dir)?
    } else {
        PathBuf::from(&opts.script_dir)
    };

    let owns_project_dir = opts.project_dir.is_empty();
    let project_dir = if owns_project_dir {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("ghidra_headless_rust_{suffix}"))
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

    // Build command. No -import and no -process: Ghidra creates/opens
    // the project, runs the server script without an active program, and
    // callers drive ImportProgram/OpenProgram explicitly over RPC.
    let mut cmd = Command::new(&launcher);
    let _ = cmd.arg(&project_dir).arg(&opts.project_name);
    for arg in &opts.extra_headless_args {
        let _ = cmd.arg(arg);
    }
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
                emit_output_line(&trimmed, opts.on_output.as_deref());
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

    let output_thread = match start_output_drainer(reader.into_inner(), opts.on_output) {
        Ok(thread) => thread,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            if owns_project_dir {
                let _ = std::fs::remove_dir_all(&project_dir);
            }
            return Err(Error::new(
                ErrorCode::TransportError,
                format!("Failed to start headless output drainer: {e}"),
            ));
        }
    };

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
        output_thread: Some(output_thread),
        base_url,
        project_dir,
        owns_project_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn generic_headless_options_default_to_no_action() {
        assert_eq!(HeadlessProjectOptions::default().shutdown, "save");
    }

    #[test]
    fn output_drainer_consumes_child_stdout_until_eof() {
        const LINE_COUNT: usize = 10_000;

        let mut cmd = output_flood_command(LINE_COUNT);
        let _ = cmd.stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = cmd.spawn().expect("spawn stdout writer");
        let stdout = child.stdout.take().expect("capture child stdout");

        let seen = Arc::new(AtomicUsize::new(0));
        let seen_by_callback = Arc::clone(&seen);
        let output_thread = start_output_drainer(
            stdout,
            Some(Box::new(move |_| {
                let _ = seen_by_callback.fetch_add(1, Ordering::Relaxed);
            })),
        )
        .expect("start output drainer");

        let status = child.wait().expect("wait for stdout writer");
        assert!(status.success(), "stdout writer failed: {status:?}");
        output_thread.join().expect("join output drainer");
        assert_eq!(seen.load(Ordering::Relaxed), LINE_COUNT);
    }

    #[cfg(windows)]
    fn output_flood_command(line_count: usize) -> Command {
        let mut cmd = Command::new("cmd");
        let _ = cmd
            .arg("/C")
            .arg(format!("for /L %i in (1,1,{line_count}) do @echo line%i"));
        cmd
    }

    #[cfg(not(windows))]
    fn output_flood_command(line_count: usize) -> Command {
        let mut cmd = Command::new("sh");
        let _ = cmd.arg("-c").arg(format!(
            "i=1; while [ $i -le {line_count} ]; do echo line$i; i=$((i+1)); done"
        ));
        cmd
    }
}
