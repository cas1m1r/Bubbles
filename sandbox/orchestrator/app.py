#!/usr/bin/env python3
import os, json, shlex, time, threading, uuid, hashlib
from datetime import datetime, timezone
from subprocess import Popen, PIPE
from pathlib import Path
from flask import Flask, request, jsonify, render_template
import requests

# ---------- paths & config ----------
BASE_DIR    = Path(__file__).resolve().parent
TEMPLATES   = BASE_DIR / "templates"
UPLOAD_DIR  = BASE_DIR / "uploads"
ART_DIR     = BASE_DIR / "artifacts"
OFFLINE_DIR = BASE_DIR / "offline"
for d in (UPLOAD_DIR, ART_DIR, OFFLINE_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Path to compiled launcher
LAUNCHER = os.environ.get(
    "SANDBOX_LAUNCHER",
    str((BASE_DIR / ".." / "sandbox" / "seccomp_launcher").resolve())
)

# Optional: push events to a backend timeline (leave unset to run fully offline)
BUBBLE_API = os.environ.get("BUBBLE_API")
HOST_ID    = os.uname().nodename or "bubble-orchestrator"

app = Flask(__name__, template_folder=str(TEMPLATES))

# ---------- helpers ----------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def uu() -> str:
    return str(uuid.uuid4())

def sha256_hex(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def read_status_rss_kb(pid: int):
    try:
        with open(f"/proc/{pid}/status","r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except Exception:
        return None

# ---------- offline event sink (if no API) ----------
def _offline_append(kind: str, doc: dict):
    path = OFFLINE_DIR / f"{kind}.ndjson"
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(doc) + "\n")

def bubble_post(path: str, payload: dict):
    """Return dict; if API unavailable, persist locally."""
    base = (BUBBLE_API or "").strip()
    if not base:
        _offline_append(path.strip("/").replace("/","_"), payload)
        return {"offline": True}
    try:
        r = requests.post(f"{base}{path}", json=payload, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        _offline_append(path.strip("/").replace("/","_"),
                        {"payload": payload, "error": str(e), "ts": now_iso()})
        return {"offline": True, "error": str(e)}

def emit_event(sample_id: str, run_id: str, ev: dict):
    payload = {
        "event_id": uu(),
        "sample_id": sample_id,
        "run_id": run_id,
        "host_id": HOST_ID,
        "timestamp": ev.get("timestamp") or ev.get("ts") or now_iso(),
        "event": ev,
        "context": {"labels":["orchestrator","seccomp"], "tags":[ev.get("type","")], "operator":"orchestrator@local"},
        "meta": {"ingested_by":"orchestrator.flask","raw_source":"stderr/json"}
    }
    bubble_post("/v1/events", payload)

def create_sample_and_run(filename: str | None):
    sample_id = uu()
    bubble_post("/v1/samples", {
        "sample_id": sample_id,
        "filename": filename or "adhoc",
        "sha256": None,
        "submitter": "orchestrator@local",
        "tags": ["orchestrator","manual"],
        "notes": "Created by Flask orchestrator"
    })
    run_id = uu()
    bubble_post("/v1/runs", {
        "run_id": run_id,
        "sample_id": sample_id,
        "host_id": HOST_ID,
        "start_ts": now_iso(),
        "status": "running"
    })
    (BASE_DIR / ".last_run.json").write_text(
        json.dumps({"sample_id": sample_id, "run_id": run_id}, indent=2),
        encoding="utf-8"
    )
    return sample_id, run_id

def finalize_run(run_id: str, sample_id: str, verdict: str | None, start_ts: str):
    bubble_post("/v1/runs", {
        "run_id": run_id,
        "sample_id": sample_id,
        "host_id": HOST_ID,
        "start_ts": start_ts,
        "end_ts": now_iso(),
        "status": "completed",
        "verdict": verdict or "unknown"
    })

def register_artifact(sample_id: str, run_id: str, p: Path, kind: str):
    artifact_id = uu()
    checksum = f"sha256:{sha256_hex(p)}"
    rel = str(p.relative_to(BASE_DIR))
    bubble_post("/v1/artifacts", {
        "artifact_id": artifact_id,
        "sample_id": sample_id,
        "run_id": run_id,
        "type": kind,
        "storage_path": rel,
        "checksum": checksum,
        "size_bytes": p.stat().st_size
    })
    return artifact_id

# ---------- core runner ----------
def spawn_and_observe(
    cmd_argv,
    diagnose: bool = False,
    pidns: bool = False,
    notify_exec: bool = True,
    permissions: dict | None = None,
    cwd: Path | None = None,
    timeout_s: int = 10,
):
    # Resolve CWD / metadata
    run_cwd = str(cwd) if cwd else None
    
    filename = cmd_argv[0] if cmd_argv else None

    # Create sample/run up front so we can emit events immediately
    sample_id, run_id = create_sample_and_run(os.path.basename(filename) if filename else None)
    start_ts = now_iso()

    emit_event(sample_id, run_id, {
        "type": "process.spawn",
        "action": "launcher.start",
        "cmdline": " ".join(cmd_argv),
        "cwd": run_cwd or os.getcwd(),
        "exe": filename
    })

    # ---------- build launcher argv ----------
    perms = permissions or {}
    fs_write = bool(perms.get("fs_write", False))   # checked => allow write
    net_ok   = bool(perms.get("network", False))    # checked => allow net

    args = [LAUNCHER]
    args += [f"--deny-fs={'0' if fs_write else '1'}"]
    args += [f"--deny-net={'0' if net_ok   else '1'}"]
    if notify_exec:
        args.append("--notify-exec")
    if pidns:
        args.append("--pidns")
    if diagnose:
        args.append("--diagnose")
    args += ["--"] + cmd_argv

    # ---------- spawn & observers ----------
    t0 = time.time()
    proc = Popen(args, stdout=PIPE, stderr=PIPE, text=True, bufsize=1, cwd=run_cwd)
    alerts: list[dict] = []
    max_rss_kb = 0
    stdout_buf: list[str] = []
    stop = False
    timed_out = False

    # NEW: snapshot cwd (robust even if cwd=None)
    cwd_path = Path(run_cwd or os.getcwd())
    try:
        initial_file_set = set(os.listdir(cwd_path))
    except Exception:
        initial_file_set = set()

    def read_status_rss_kb_local(pid):
        try:
            return read_status_rss_kb(pid)
        except Exception:
            return None

    # sample RSS
    def sampler():
        nonlocal max_rss_kb
        while not stop and proc.poll() is None:
            rss = read_status_rss_kb_local(proc.pid)
            if rss and rss > max_rss_kb:
                max_rss_kb = rss
            time.sleep(0.05)

    # stream stdout
    def read_stdout():
        if not proc.stdout: return
        for line in iter(proc.stdout.readline, ""):
            stdout_buf.append(line)

    # stream stderr and parse events here (so main never blocks on it)
    def read_stderr():
        if not proc.stderr: return
        for line in iter(proc.stderr.readline, ""):
            s = line.strip()
            if not s:
                continue
            ts = now_iso()
            if s.startswith("{") and s.endswith("}"):
                try:
                    j = json.loads(s)
                    emit_event(sample_id, run_id, j)
                    alerts.append(j)
                    continue
                except json.JSONDecodeError:
                    pass
            ev = {"type": "sandbox.msg", "action": "stderr", "message": s, "ts": ts}
            emit_event(sample_id, run_id, ev)
            alerts.append(ev)

    # watchdog timeout
    def watchdog():
        nonlocal timed_out
        while not stop and proc.poll() is None:
            if time.time() - t0 > timeout_s:
                timed_out = True
                try:
                    proc.terminate()
                    for _ in range(20):
                        if proc.poll() is not None:
                            break
                        time.sleep(0.05)
                    if proc.poll() is None:
                        proc.kill()
                finally:
                    break
            time.sleep(0.1)

    threads = [
        threading.Thread(target=sampler, daemon=True),
        threading.Thread(target=read_stdout, daemon=True),
        threading.Thread(target=read_stderr, daemon=True),
        threading.Thread(target=watchdog, daemon=True),
    ]
    [t.start() for t in threads]

    rc = proc.wait()
    stop = True
    for t in threads:
        t.join(timeout=0.3)
    duration_s = time.time() - t0

    # ---------- NEW: detect dropped files with metadata ----------
    dropped_files = []
    try:
        final_set = set(os.listdir(cwd_path))
        new_files = sorted(final_set - initial_file_set)
        for name in new_files:
            p = cwd_path / name
            try:
                if p.is_file():
                    dropped_files.append({
                        "name": name,
                        "size": p.stat().st_size,
                        "sha256": sha256_hex(p),
                    })
            except Exception:
                # best-effort; skip unreadable files
                pass
    except Exception:
        pass

    if dropped_files:
        ev = {
            "type": "fs.drop",
            "cwd": str(cwd_path),
            "count": len(dropped_files),
            "files": dropped_files,
            "ts": now_iso(),
        }
        emit_event(sample_id, run_id, ev)
        alerts.append(ev)

    if timed_out:
        ev = {
            "type": "sandbox.msg",
            "action": "timeout",
            "message": f"terminated after {timeout_s}s",
            "ts": now_iso(),
            "dropped_files": dropped_files,
        }
        emit_event(sample_id, run_id, ev)
        alerts.append(ev)

    # ---------- artifacts & finalize ----------
    stdout_text = "".join(stdout_buf)
    out_path = ART_DIR / f"{run_id}.stdout.txt"
    out_path.write_text(stdout_text, encoding="utf-8")
    art_id = register_artifact(sample_id, run_id, out_path, "stdout")

    emit_event(sample_id, run_id, {
        "type": "process.exit",
        "action": "launcher.end",
        "duration_ms": int(duration_s * 1000),
        "notes": f"exit={rc} max_rss_kb={max_rss_kb}"
    })

    verdict = ("ok" if rc == 0 else "violation" if alerts else "unknown")
    finalize_run(run_id, sample_id, verdict, start_ts)

    return {
        "sample_id": sample_id,
        "run_id": run_id,
        "command": cmd_argv,
        "launcher": LAUNCHER,
        "start_ts": start_ts,
        "end_ts": now_iso(),
        "duration_s": round(duration_s, 6),
        "exit_code": rc,
        "max_rss_kb": max_rss_kb,
        "alerts": alerts,
        "stdout": stdout_text,
        "diagnose": diagnose,
        "pidns": pidns,
        "stdout_artifact_id": art_id,
        "offline": (not BUBBLE_API),
        "mode": "deny-with-EPERM-continue",
        # NEW: bubble up to the UI
        "dropped_files": dropped_files,
    }


# ---------- routes ----------
@app.get("/")
def index():
    return render_template("index.html")

@app.post("/upload")
def upload():
    f = request.files.get("file")
    if not f:
        return jsonify({"error":"no file"}), 400
    dest = (UPLOAD_DIR / os.path.basename(f.filename))
    f.save(dest)
    os.chmod(dest, 0o755)

    # shebang sniff (optional interpreter hint)
    interpreter = ""
    try:
        with dest.open("rb") as fh:
            if fh.read(2) == b"#!":
                fh.seek(0)
                interpreter = fh.readline().decode("utf-8","ignore").strip()[2:].split()[0]
    except Exception:
        pass
    return jsonify({"path": str(dest), "interpreter": interpreter})

@app.post("/run")
def run():
    data = request.get_json(force=True)

    # Common knobs from UI
    notify_exec = bool(data.get("notify_exec", True))
    diagnose    = bool(data.get("diagnose", False))
    pidns       = bool(data.get("pidns", False))
    permissions = data.get("permissions") or {}

    # Uploaded file path?
    if data.get("uploaded_path"):
        upath = Path(data["uploaded_path"]).resolve()
        interp = (data.get("interpreter") or "").strip()
        extra  = shlex.split(data.get("args","")) if data.get("args") else []
        cmd_argv = ([interp, str(upath)] if interp else [str(upath)]) + extra
        result = spawn_and_observe(
            cmd_argv,
            diagnose=diagnose,
            pidns=pidns,
            notify_exec=notify_exec,
            permissions=permissions,
            cwd=upath.parent
        )
        return jsonify(result)

    # Raw command
    cmd = data.get("cmd")
    if   isinstance(cmd, str):  cmd_argv = shlex.split(cmd)
    elif isinstance(cmd, list): cmd_argv = cmd
    else:
        return jsonify({"error":"cmd must be string or list"}), 400

    result = spawn_and_observe(
        cmd_argv,
        diagnose=diagnose,
        pidns=pidns,
        notify_exec=notify_exec,
        permissions=permissions,
        cwd=None
    )
    return jsonify(result)

if __name__ == "__main__":
    print(f"[orchestrator] LAUNCHER = {LAUNCHER}")
    app.run(host="0.0.0.0", port=8090, debug=True)
