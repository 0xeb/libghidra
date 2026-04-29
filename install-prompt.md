# libghidra Install Prompt (for AI Agents)

Self-contained runbook to stand up `libghidra` from zero. Each step
ends with an explicit verification gate. **If a gate fails, follow the
remediation note before continuing.** Do not skip gates — every later
step assumes the earlier ones succeeded.

The runbook walks the **recommended happy path**: install the prebuilt
Python wheel from the GitHub Releases page, install the `LibGhidraHost`
Ghidra extension, launch a headless host, and confirm typed RPC reads
work end-to-end. C++ and Rust SDKs are listed under "Where to go next".

For human users: see `README.md` instead.

---

## Step 0 — Preflight (verify dependencies)

| Check | Command | Expected | Remediation |
|-------|---------|----------|-------------|
| JDK 21 | `java -version` | `21` in output | Install Eclipse Adoptium 21: <https://adoptium.net/temurin/releases/?version=21> |
| Python ≥ 3.12 | `python --version` | major.minor ≥ 3.12 | <https://www.python.org/downloads/> (the abi3 wheels target cp312) |
| pip (recent) | `python -m pip --version` | any modern | `python -m ensurepip --upgrade` |
| Gradle ≥ 8 | `gradle --version` | major ≥ 8 | <https://gradle.org/install/>, or use `ghidra/gradlew*` from the Ghidra source tree if you have one |
| Git | `git --version` | any modern | <https://git-scm.com/downloads> |
| curl | `curl --version` | any modern | OS package manager |

If you only need the **HTTP client** (no offline decompiler engine),
the pure-Python fallback wheel works on Python ≥ 3.10. The native
abi3 wheel — which carries the offline `LocalClient` engine — is the
default the runbook uses.

---

## Step 1 — Acquire Ghidra distribution

Download Ghidra 12.0.4+ from the official release page:
<https://github.com/NationalSecurityAgency/ghidra/releases>

Verify the SHA-256 against the release-page hash:

```bash
sha256sum ghidra_*_PUBLIC.zip   # compare to release-page hash
```

Extract to a stable location and set `GHIDRA_INSTALL_DIR` to the
directory that contains `support/`, `Ghidra/`, `ghidraRun*` (i.e. the
Ghidra root, **not** its parent):

```bash
# Windows (PowerShell)
$env:GHIDRA_INSTALL_DIR = "C:/ghidra_dist/ghidra_12.1_PUBLIC"

# POSIX
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1_PUBLIC
```

**Gate**:
```bash
test -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
test -f "$GHIDRA_INSTALL_DIR/support/buildExtension.gradle"
ls "$GHIDRA_INSTALL_DIR/Ghidra/Framework"   # non-empty
```

If the gate fails: re-extract and confirm `GHIDRA_INSTALL_DIR` points
at the Ghidra root, not its parent and not its `Ghidra/` subdirectory.

---

## Step 2 — Clone the libghidra repo

```bash
git clone https://github.com/0xeb/libghidra.git
cd libghidra
```

**Gate**:
```bash
test -d .git
test -f README.md
test -d ghidra-extension
test -d python
```

---

## Step 3 — Build and install the LibGhidraHost extension

This installs the Ghidra extension that serves the typed RPC API.

```bash
cd ghidra-extension
gradle installExtension -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"
cd ..
```

**Gate**:
```bash
ls "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/LibGhidraHost"
test -f "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/LibGhidraHost/ghidra_scripts/LibGhidraHeadlessServer.java"
```

If the gate fails: try `gradle clean buildExtension` and copy the
produced `.zip` from `dist/` into
`$GHIDRA_INSTALL_DIR/Extensions/Ghidra/`. Ghidra unpacks it on next
launch. Pre-generated Java protobuf stubs are checked in, so `protoc`
is **not** required for the extension build.

---

## Step 4 — Install the Python wheel

The wheel includes both the HTTP/RPC client and the offline
`LocalClient` engine (Sleigh decompiler + embedded processor specs).

Pick the URL that matches your platform from
<https://github.com/0xeb/libghidra/releases> (the version below is
illustrative — use whatever the latest release tag is):

```bash
# Linux x86_64
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.2/libghidra-0.0.2-cp312-abi3-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl

# Linux aarch64
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.2/libghidra-0.0.2-cp312-abi3-manylinux_2_26_aarch64.manylinux_2_28_aarch64.whl

# macOS Apple Silicon
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.2/libghidra-0.0.2-cp312-abi3-macosx_15_0_arm64.whl

# Windows x64
pip install https://github.com/0xeb/libghidra/releases/download/v0.0.2/libghidra-0.0.2-cp312-abi3-win_amd64.whl
```

If your platform has no native wheel (Intel Mac, Windows-on-ARM, etc.),
use the pure-Python fallback inside the `libghidra-python-*.zip` on
the same release page:

```bash
pip install libghidra-0.0.2-py3-none-any.whl   # HTTP client only
```

**Gate**:
```bash
python -c "import libghidra; print(libghidra.__version__)"
libghidra --help | head -3
```

The first command prints the version (e.g. `0.0.2`). The second
shows the bundled CLI (`status`, `functions`, `decompile`, …).

If `import libghidra` fails: confirm Python ≥ 3.12 (`python --version`),
then re-download the wheel matching your interpreter's tag triple
(`python -c "import sysconfig; print(sysconfig.get_platform())"`).

---

## Step 5 — Pick a test binary

Use a small, universally available binary so the agent can finish the
end-to-end check without extra setup:

| Platform | Suggested test binary |
|----------|------------------------|
| Windows  | `C:/Windows/System32/notepad.exe` |
| Linux    | `/bin/ls` |
| macOS    | `/bin/ls` |

Or compile a trivial one:

```bash
echo 'int main(void){return 42;}' > /tmp/tinybin.c
cc -o /tmp/tinybin /tmp/tinybin.c
```

**Gate**: the chosen test binary path exists and is readable.

---

## Step 6 — Launch the headless RPC host

This imports the test binary, runs auto-analysis, and exposes the typed
libghidra RPC at `http://127.0.0.1:18080`.

```bash
# Windows
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless.bat" \
  C:/tmp/libghidra-bootstrap boot \
  -import <test-binary> \
  -postScript LibGhidraHeadlessServer.java port=18080 &

# POSIX
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
  /tmp/libghidra-bootstrap boot \
  -import <test-binary> \
  -postScript LibGhidraHeadlessServer.java port=18080 &
```

The host prints `LIBGHIDRA_HEADLESS_READY` to stdout once the RPC
listener is up; analysis finishes shortly after on small binaries.
Use the HTTP `/status` endpoint as the authoritative readiness signal.

**Gate**:
```bash
# Wait until the host responds with HTTP 200 (~3 min ceiling)
until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/status)" = "200" ]; do
  sleep 2
done
curl -s http://127.0.0.1:18080/status
```

The `/status` JSON should contain a non-empty `service_name` and the
program's `language_id` (e.g. `x86:LE:64:default`).

**Alternative — start from the GUI:** launch
`$GHIDRA_INSTALL_DIR/ghidraRun*`, open or import the program, then
`Tools > libghidra Host > Start Server...`. The default URL
`http://127.0.0.1:18080` matches what the rest of this runbook
assumes.

---

## Step 7 — Smoke-test typed RPC reads

Run from any Python interpreter that has the wheel installed:

```python
import libghidra as ghidra

client = ghidra.connect("http://127.0.0.1:18080")

status = client.get_status()
print(f"Connected: {status.service_name}")

funcs = client.list_functions()
print(f"Function count: {len(funcs.functions)}")
for f in funcs.functions[:5]:
    print(f"  0x{f.entry_address:x}  {f.name}")

if funcs.functions:
    first = funcs.functions[0]
    decomp = client.get_decompilation(first.entry_address)
    print(f"--- decompilation of {first.name} ---")
    print(decomp.pseudocode_c[:400])
```

Or use the bundled CLI:

```bash
libghidra status    --url http://127.0.0.1:18080
libghidra functions --url http://127.0.0.1:18080 --limit 5
libghidra decompile --url http://127.0.0.1:18080 0x<entry-of-first-function>
```

**Gate**:
- `client.get_status().service_name` is non-empty.
- `client.list_functions()` returns ≥ 1 function for a real binary.
- `client.get_decompilation(addr)` returns a non-empty
  `pseudocode_c` string for the first function's entry address.

If `list_functions()` returns zero entries:
- The post-script may have been launched before analysis completed —
  re-run Step 6 and wait longer at the gate.
- Confirm the imported binary actually has functions
  (`file <path>` should report an executable, not data).
- Try a different test binary (e.g. a freshly built `tinybin`).

---

## Step 8 — Clean shutdown

```bash
curl -X POST http://127.0.0.1:18080/shutdown
```

`/shutdown` returns `{"success":true}` once the HTTP listener is
stopping. The Java host then applies the launch-time save policy and
exits. **For large pending state this can take tens of seconds.** Wait
for both `java` and any related processes to leave the process list
before reusing the project directory.

```bash
# Windows
tasklist | findstr /I "java.exe"        # expect: empty
ls C:/tmp/libghidra-bootstrap            # expect: only boot.gpr and boot.rep/

# POSIX
pgrep -f java                            # expect: empty
ls /tmp/libghidra-bootstrap              # expect: only boot.gpr and boot.rep/
```

**Gate**: the process list contains no `java`, and the project
directory contains only `<name>.gpr` and `<name>.rep/` — no
`*.lock` / `*.lock~` files.

If `*.lock` files remain after the host exited (force-kill from a
previous run), remove them before launching again.

---

## Where to go next

- **C++ SDK** — both backends (HTTP + offline local): see
  [`cpp/README.md`](cpp/README.md).
- **Rust crate** — including `cargo binstall libghidra` for the
  prebuilt local archive: see [`rust/README.md`](rust/README.md).
- **Full Python API** — async client, format detection, CLI helpers:
  see [`python/README.md`](python/README.md).
- **SQL on top of libghidra** — `ghidrasql` turns this RPC layer into
  60+ SQL virtual tables for analysis and write-through annotations:
  <https://github.com/0xeb/ghidrasql>.

---

## Lessons baked in (rationale, do not skip)

These are non-obvious gotchas that have cost real time. The runbook
already routes around them; this section explains why so the agent
recognizes the symptoms.

- **`GHIDRA_INSTALL_DIR` must point at the Ghidra root** — the
  directory containing `support/buildExtension.gradle`, **not** its
  parent and **not** its `Ghidra/` subdirectory. The extension build
  fails with confusing path errors otherwise.
- **The native wheel is `cp312-abi3`** — Python ≥ 3.12 is required.
  The pure-Python fallback (`libghidra-*-py3-none-any.whl` from the
  release zip) accepts Python ≥ 3.10 but ships only the HTTP/RPC
  client; the offline `LocalClient` engine is unavailable.
- **`POST /shutdown` returns success ~150 ms in.** After the listener
  stops, the Java host flushes the project per its launch-time save
  policy. Trust the response and just wait for the Java process to
  exit before reusing the project directory.
- **Force-killing leaves orphaned `*.lock` / `*.lock~` files** in the
  project directory. If you find them after a previous crash and no
  `java` is running, delete both before launching again.
- **`LocalClient` auto-detects ELF / PE / Mach-O / raw inputs** via
  `libghidra.format_detect` and feeds the right Sleigh `language_id`
  to the offline engine. Pass an explicit `language_id` on
  `OpenProgramRequest` only when detection is wrong (rare; mostly for
  raw-binary inputs).
- **The HTTP host's port defaults to 18080.** If you override it
  (`-Dlibghidra.host.port=...` for the GUI, `port=...` for the
  headless post-script), update every URL in the smoke checks
  accordingly.
