# Project Bubble — Seccomp Sandbox with Web UI

A lightweight sandboxing system built on Linux **seccomp-bpf** with a **Flask** web interface for running programs, observing behavior, and capturing fine-grained policy events in real time.

- **Default behavior:** *Deny with `EPERM` and continue* (no TRAP). Disallowed operations are intercepted via **SECCOMP User Notification**, logged with rich context, and the target process continues execution whenever possible.
- **UI-first workflow:** Run commands or uploaded binaries, toggle permissions (FS write, network), and review stdout, violations, and a full event stream.
![ui](https://raw.githubusercontent.com/cas1m1r/Bubbles/refs/heads/main/file_drop_ex.png)
---

## ✨ Highlights

### 1) Clear violation display
- Dedicated **Security Violations** section at the top.
- Each card shows:
  - syscall (e.g., `openat`, `socket`, `connect`)
  - reason (`errno`), timestamp
  - rich context (path, flags, domain, port, etc.)
- Color-coded for fast triage.

### 2) Modern, readable layout
- Two columns for **Stdout** and **All Events**.
- **Execution Summary** at the bottom (exit code, duration, memory).
- Dark theme, compact spacing.

### 3) Configurable permissions (UI toggles)
- 📖 **Filesystem Read** — always allowed (checked & disabled)
- 📝 **Filesystem Write** — allow/deny (default: deny)
- 🌐 **Network Access** — allow/deny (default: deny)
- ⚙️ **Log Process Spawns** — opt-in NOTIFY on `exec*`
- 🔒 **PID Namespace**
- 🔍 **Diagnostic logging** — ask kernel to log seccomp decisions (best effort)

Additional behavior (always on):
- **Deny with `EPERM` and continue** for disallowed FS/NET ops (via USER_NOTIF).
- **Watchdog timeout** in the Flask orchestrator to prevent runaway jobs.

---

## 📁 Project Structure

```
Bubbles/
├── sandbox/
│   ├── seccomp_launcher.c      # C launcher: libseccomp + USER_NOTIF supervisor thread
│   ├── test_violations.c       # Simple test program to exercise FS/NET
│   ├── Makefile
│   └── test.sh                 # Local sanity tests (optional)
│
└── orchestrator/
    ├── app.py                  # Flask server (runner, eventing, artifacts)
    ├── templates/
    │   └── index.html          # Web UI (single page)
    ├── uploads/                # Uploaded executables (created at runtime)
    ├── artifacts/              # Collected stdout (one file per run)
    └── offline/                # NDJSON event sink when no backend is configured
```

> If you placed `orchestrator/` at the repo root already, adjust the paths accordingly. The launcher path is read from `SANDBOX_LAUNCHER` or defaults to `../sandbox/seccomp_launcher` from `orchestrator/app.py`.

---

## 🚀 Quick Start

### 1) Build the sandbox launcher

```bash
sudo apt-get install -y build-essential libseccomp-dev   # Debian/Ubuntu
# dnf/yum users: sudo dnf install libseccomp-devel

cd sandbox
make            # builds ./seccomp_launcher
```

### 2) (Optional) Run quick tests

```bash
cd sandbox
./test.sh       # basic checks for FS/NET deny logging (optional)
```

### 3) Start the Web UI

```bash
cd orchestrator
python3 -m pip install --upgrade pip
python3 -m pip install flask requests
# (optional) point to your launcher if the default path differs:
# export SANDBOX_LAUNCHER=/absolute/path/to/seccomp_launcher
python3 app.py
```

Open http://localhost:8090

---

## 🧭 Web UI Workflow

1. **Set permissions**
   - Check “Allow Filesystem Write” to permit writes.
   - Check “Allow Network” to permit sockets/connect.
   - “Log Process Spawns” enables optional visibility on `exec*` (we *continue* those syscalls; no blocking).
   - “PID Namespace” isolates PIDs (optional).
   - “Diagnostic logging” requests kernel-level seccomp logs (best-effort hint).

2. **Run**
   - Enter a command such as `/usr/bin/echo hello` or `./test_violations`.
   - Or **upload** a binary and click “Upload & Run” (optionally provide an interpreter and args).

3. **Analyze**
   - **Security Violations**: see any denied FS/NET activity with context.
   - **Standard Output**: target program’s stdout (also saved as an artifact).
   - **All Events**: raw JSON stream (spawn/exit, alerts, stderr fallbacks).
   - **Execution Summary**: exit code, duration, max RSS, artifact IDs.

4. **Iterate**
   - Toggle permissions and re-run to learn the minimal privilege set.

---

## 🖥️ Command-Line Usage (launcher)

The current launcher supports explicit allow/deny switches for FS/NET, optional exec logging, PID namespaces, and diagnostic mode.

```
./seccomp_launcher [--pidns] [--deny-fs=1|0] [--deny-net=1|0] [--notify-exec] [--diagnose] -- <program> [args...]
```

**Examples**

```bash
# Default (deny writes, deny network), allow reads
./seccomp_launcher -- /bin/echo "hello world"

# Allow file modifications
./seccomp_launcher --deny-fs=0 -- /bin/sh -lc 'echo ok > /tmp/allowed.txt'

# Allow networking (sockets/connect/etc.)
./seccomp_launcher --deny-net=0 -- curl -s https://example.com

# Log process spawns (execve/execveat) for visibility (continues, does not block)
./seccomp_launcher --notify-exec -- /bin/echo hello

# Combine: allow network, log spawns, keep FS writes denied
./seccomp_launcher --deny-net=0 --notify-exec -- /bin/sh -lc 'curl -s https://example.com >/dev/null'
```

> The launcher *never* kills your process for policy reasons; it denies with `EPERM` and logs, letting the process continue where possible. The orchestrator may still terminate long-running jobs via a watchdog timeout (configurable in `app.py`).

---

## 📊 Event Model

The orchestrator captures events from the launcher’s stderr (prefer JSON). Typical events:

### Process spawn

```json
{
  "type": "process.spawn",
  "exe": "/usr/bin/echo",
  "ts": "2025-10-12T23:44:10Z"
}
```

With `--notify-exec`, you’ll also see an explicit `execve/execveat` record:
```json
{
  "type": "process.spawn",
  "syscall": "execve",
  "pid": 4478,
  "exe": "/usr/bin/echo",
  "ts": "2025-10-13T03:37:39Z"
}
```

### Filesystem deny (via USER_NOTIF → EPERM)

```json
{
  "type": "policy.alert",
  "reason": "errno",
  "category": "fs",
  "syscall": "openat",
  "syscall_no": 257,
  "ts": "2025-10-12T06:39:02Z",
  "path": "/tmp/should_not_exist.txt",
  "flags": "O_WRONLY|O_CREAT",
  "mode": 420,
  "denied": "EPERM"
}
```

### Network deny (optional block set active)

```json
{
  "type": "policy.alert",
  "reason": "errno",
  "category": "net",
  "syscall": "connect",
  "syscall_no": 42,
  "ts": "2025-10-12T06:40:02Z",
  "peer": "93.184.216.34",
  "port": 443,
  "family": 2,
  "denied": "EPERM"
}
```

### Process exit

```json
{
  "type": "process.exit",
  "action": "launcher.end",
  "duration_ms": 104,
  "notes": "exit=0 max_rss_kb=1676"
}
```

> When no external backend is configured, events are also appended to `orchestrator/offline/*.ndjson`.

---

## ⚙️ Orchestrator (Flask) details

- **Path to launcher:**  
  Read from env `SANDBOX_LAUNCHER` or defaults to `../sandbox/seccomp_launcher` relative to `orchestrator/app.py`.
- **Timeout:**  
  A watchdog in `spawn_and_observe` caps wall time (default in code: `timeout_s=8`). Adjust if you need longer runs.
- **Artifacts:**  
  Stdout is saved as `orchestrator/artifacts/<run_id>.stdout.txt` and registered as an artifact in the JSON result.
- **Optional backend ingestion:**  
  If you set `BUBBLE_API`, events/runs/samples/artifacts are POSTed to that endpoint; otherwise they are stored under `offline/`.

---

## 🔧 Building blocks & design

- **libseccomp** filter with **SCMP_ACT_ALLOW** baseline.
- Targeted syscalls are marked **SCMP_ACT_NOTIFY** to route to a supervisor thread:
  - FS mutations (open with write/create/trunc, `unlink*`, `rename*`, `chmod*`, etc.)
  - (Optionally) NET operations (`socket`, `connect`, `sendto`, etc.) — if you want deny-with-telemetry mode
  - Optional `exec*` visibility (`--notify-exec`) — allowed with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
- The supervisor logs rich context and responds with **`error = -EPERM`** (deny) or **continue** (for `exec*` when enabled).
- **No TRAP mode** — the launcher never kills by policy; it denies with `EPERM` and logs, letting the process continue where possible.

---

## 🧪 Handy test recipes

```bash
# File write (denied by default)
./seccomp_launcher -- /bin/sh -lc 'echo hi > /tmp/blocked.txt'

# File write (allowed)
./seccomp_launcher --deny-fs=0 -- /bin/sh -lc 'echo ok > /tmp/allowed.txt'

# Network connect (denied by default)
./seccomp_launcher -- /bin/sh -lc 'curl -s https://example.com || true'

# Network connect (allowed)
./seccomp_launcher --deny-net=0 -- /bin/sh -lc 'curl -s https://example.com >/dev/null'

# Exec visibility
./seccomp_launcher --notify-exec -- /bin/sh -lc '/usr/bin/echo hello'
```

---

## 🩺 Troubleshooting

- **“No output” or “timeout”**  
  Increase the orchestrator timeout in `app.py` (`timeout_s` in `spawn_and_observe`). Long-running shells or downloads can exceed the default.
- **`execvp`/`Bad address`**  
  This occurs if an older build blocked `execve` via NOTIFY without continuing. Rebuild the latest launcher (the fix sets `SECCOMP_USER_NOTIF_FLAG_CONTINUE` for `exec*` when `--notify-exec` is on).
- **UI shows events but stdout empty**  
  Some programs buffer stdout when not attached to a TTY. Use `stdbuf -oL` or `-u` for Python, or write to stderr for immediate visibility.
- **Network allowed but still failing**  
  The sandbox only governs syscalls; DNS/proxy/firewall issues are out of scope. Test with `curl -v` and confirm connectivity outside the sandbox.

---

## 🔐 Security notes

- This is a **user-space sandbox** demo intended for analysis and experimentation. It is not a drop-in container or a full VM boundary.
- Filters are x86_64-specific in this implementation.
- Always review and tailor syscall policies for your threat model before production usage.

---

## 📄 License

MIT (or your preferred license). Add your LICENSE file at the repo root.

---

## 🙌 Credits

- Linux **seccomp**, **libseccomp**, and **SECCOMP_USER_NOTIF**.
- Flask for the UI and orchestration.

---

### Version compatibility

- Kernel: Linux 5.x recommended (USER_NOTIF support required)
- Compiler: GCC with pthread
- Userspace: Python 3.8+, Flask ≥ 3.0
