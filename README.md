# Project Bubble - Seccomp Sandbox with Web UI

A lightweight sandboxing system using Linux seccomp-bpf with a Flask-based web interface for runtime analysis.

## ✨ Key Improvements

### 1. **Enhanced Violation Display**
- Violations are now prominently displayed in a dedicated section at the top
- Each violation shows:
  - Syscall name (e.g., `openat`, `socket`)
  - Reason (trap/errno)
  - Detailed context (path, flags, domain, port, etc.)
  - Timestamp
- Color-coded violation cards for easy scanning

### 2. **Reorganized Layout**
- Execution summary moved to the bottom
- Violations displayed first (most important)
- Two-column layout: Stdout | All Events
- Clean, dark-themed modern UI

### 3. **Configurable Permissions**
New permission checkboxes in the UI:
- 📖 **Filesystem Read** - Allow reading files (default: ✓)
- 📝 **Filesystem Write** - Allow creating/modifying files (default: ✗)
- 🌐 **Network Access** - Allow socket operations (default: ✗)
- ⚙️ **Process Execution** - Allow spawning processes (default: ✓)
- 🔒 **PID Namespace** - Isolate process IDs
- 🔍 **Diagnostic Mode** - Relaxed limits for debugging

Additional options:
- **Mode**: TRAP (kill on violation) vs ERRNO (return error, continue)
- **Log filesystem operations** - Detailed FS event logging
- **Log process spawns** - Track exec calls
- **Continue on trap** - Don't kill, just log

## 📁 Project Structure

```
Bubble/
├── sandbox/
    ├── seccomp_launcher.c    # Enhanced C launcher with permission flags
    ├── test_violations.c     # Test binary
    ├── Makefile
    └── test.sh               # Comprehensive test suite
    ├── orchestrator/
    └── app.py                # Flask backend with permission support
    ├── templates/
    │   └── index.html        # Modern web UI
    ├── uploads/              # Uploaded binaries
    ├── artifacts/            # Execution artifacts (stdout)
    └── offline/              # Offline event storage
```

## 🚀 Quick Start

### 1. Build the Sandbox

```bash
cd sandbox
make
```

**Requirements:**
- `libseccomp-dev` (Ubuntu/Debian) or `libseccomp-devel` (RHEL/Fedora)
- GCC with pthread support

### 2. Run Tests

```bash
cd sandbox
./test.sh
```

This will run comprehensive tests showing:
- Basic execution
- Blocked file writes
- Allowed file writes (with permission)
- Network blocking/allowing
- Process spawn notifications
- Detailed violation logging

### 3. Start the Web UI

```bash
cd orchestrator
python3 app.py
```

Visit http://localhost:8090 in your browser.

**Requirements:**
- Python 3.8+
- Flask: `pip3 install flask requests`

## 🎯 Usage Examples

### Command Line

```bash
# Block file writes (default)
./seccomp_launcher -- /bin/sh -c 'echo test > /tmp/blocked.txt'

# Allow file writes
./seccomp_launcher --allow-fs-write -- /bin/sh -c 'echo test > /tmp/allowed.txt'

# Allow network operations
./seccomp_launcher --allow-network -- curl example.com

# Log mode (continue on violation)
./seccomp_launcher --mode=errno --log-continue --log-errno -- ./test_violations

# Full monitoring
./seccomp_launcher --mode=errno --log-errno --notify-exec --log-continue -- your_program
```

### Web UI Workflow

1. **Configure Permissions**
   - Check boxes for allowed operations
   - Select mode (TRAP kills on violation, ERRNO logs and continues)
   - Enable logging options as needed

2. **Run Command**
   - Type command directly (e.g., `/bin/echo hello` or `./test_violations`)
   - Or upload a binary and run it

3. **Analyze Results**
   - **Violations** section shows all blocked operations clearly
   - **Stdout** shows program output + violation summary
   - **All Events** shows complete JSON event stream
   - **Execution Summary** at bottom shows exit status, duration, memory usage

4. **Iterate**
   - Grant specific permissions (e.g., enable "Filesystem Write")
   - Re-run to see how behavior changes
   - Useful for understanding minimum required privileges

## 🔧 Command-Line Options

| Option | Description |
|--------|-------------|
| `--mode=trap` | Kill process on policy violation (default) |
| `--mode=errno` | Return EPERM, continue execution |
| `--allow-fs-write` | **NEW:** Allow filesystem modifications |
| `--allow-network` | **NEW:** Allow socket/network operations |
| `--log-errno` | Log filesystem operations via NOTIFY |
| `--notify-exec` | Log process spawns (exec calls) |
| `--log-continue` | Don't kill on TRAP, just log |
| `--pidns` | Use PID namespace isolation |
| `--diagnose` | Diagnostic mode (relaxed resource limits) |

## 📊 Violation Types

The system detects and logs:

### Filesystem Operations
- **openat/open** - File opening with write/create flags
- **unlinkat/unlink** - File deletion
- **renameat2/rename** - File renaming
- **mkdir/mkdirat** - Directory creation
- **chmod/chown** - Permission/ownership changes
- **trunc
