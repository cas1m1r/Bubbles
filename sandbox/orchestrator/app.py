#!/usr/bin/env python3
import os, json, shlex, time, threading, uuid, hashlib
from datetime import datetime, timezone
from subprocess import Popen, PIPE
from pathlib import Path
from flask import Flask, request, jsonify, render_template
import requests

BASE_DIR   = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
ART_DIR    = BASE_DIR / "artifacts"
OFFLINE_DIR= BASE_DIR / "offline"
for d in (UPLOAD_DIR, ART_DIR, OFFLINE_DIR): d.mkdir(parents=True, exist_ok=True)

LAUNCHER   = os.environ.get("SANDBOX_LAUNCHER", str((BASE_DIR / ".." / "sandbox" / "seccomp_launcher").resolve()))
BUBBLE_API = os.environ.get("BUBBLE_API")  # if None/empty => offline mode
HOST_ID    = os.uname().nodename or "bubble-orchestrator"

app = Flask(__name__)

def now_iso(): return datetime.now(timezone.utc).isoformat()
def uu(): return str(uuid.uuid4())

def sha256_hex(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()

def read_status_rss_kb(pid: int):
    try:
        with open(f"/proc/{pid}/status","r") as f:
            for line in f:
                if line.startswith("VmRSS:"): return int(line.split()[1])
    except Exception:
        return None

# ---------- ingestion: best-effort ----------
def _offline_append(kind: str, doc: dict):
    path = OFFLINE_DIR / f"{kind}.ndjson"
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(doc) + "\n")

def bubble_post(path: str, payload: dict):
    """Return dict; if API unavailable, persist locally and return {'offline':True}."""
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
        "timestamp": ev.get("timestamp") or now_iso(),
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
    (BASE_DIR.parent / ".last_run.json").write_text(json.dumps({"sample_id": sample_id, "run_id": run_id}, indent=2))
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
    rel = str(p.relative_to(BASE_DIR.parent))
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

def spawn_and_observe(cmd_argv, mode="trap", diagnose=False, pidns=False, 
                      log_errno=False, notify_exec=False, log_continue=False,
                      permissions=None, cwd: Path | None=None):
    """
    Enhanced spawning with permission controls.
    permissions: dict with keys: fs_read, fs_write, network, exec (all bool)
    """
    run_cwd = str(cwd) if cwd else None
    perms = permissions or {}

    filename = cmd_argv[0] if cmd_argv else None
    sample_id, run_id = create_sample_and_run(os.path.basename(filename) if filename else None)
    start_ts = now_iso()

    emit_event(sample_id, run_id, {
        "type":"process.spawn","action":"launcher.start",
        "cmdline":" ".join(cmd_argv),"cwd": run_cwd or os.getcwd(),"exe": filename,
        "permissions": perms
    })

    args = [LAUNCHER]
    if pidns: args.append("--pidns")
    if diagnose: args.append("--diagnose")
    if mode in ("trap","errno"): args.append(f"--mode={mode}")
    if log_errno: args.append("--log-errno")
    if notify_exec: args.append("--notify-exec")
    if log_continue: args.append("--log-continue")
    
    # Permission flags
    if perms.get("fs_write"): args.append("--allow-fs-write")
    if perms.get("network"): args.append("--allow-network")
    
    args += ["--"] + cmd_argv

    t0 = time.time()
    proc = Popen(args, stdout=PIPE, stderr=PIPE, text=True, bufsize=1, cwd=run_cwd)
    alerts, max_rss_kb = [], 0
    viol_lines = []

    stop=False
    def sampler():
        nonlocal max_rss_kb
        while not stop and proc.poll() is None:
            rss = read_status_rss_kb(proc.pid)
            if rss and rss > max_rss_kb: max_rss_kb = rss
            time.sleep(0.05)
    threading.Thread(target=sampler, daemon=True).start()

    for line in proc.stderr:
        line=line.strip()
        if not line: continue
        ts=now_iso()
        if line.startswith("{") and line.endswith("}"):
            try: j=json.loads(line)
            except json.JSONDecodeError: j={"type":"policy.alert.raw","line":line,"ts":ts}
            
            # Build structured event
            ev={"type": j.get("type", "policy.alert"),
                "action": j.get("reason") or j.get("type") or "violation",
                "notes": line}
            if "syscall" in j: ev["syscall"] = j["syscall"]
            if "path" in j:    ev["path"] = j["path"]
            if "flags" in j:   ev["flags"] = j["flags"]
            
            emit_event(sample_id, run_id, ev)
            alerts.append(j)

            # Human-readable violation line
            reason = j.get("reason","violation")
            sc = j.get("syscall")
            p  = j.get("path")
            extras=[]
            if "flags" in j: extras.append(f"flags={j['flags']}")
            if "mode"  in j: extras.append(f"mode={j['mode']}")
            if "domain" in j: extras.append(f"domain={j['domain']}")
            if "type" in j and j.get("category") == "net":
                extras.append(f"type={j.get('type')}")
            
            line_hr = f"[BLOCKED] {reason}"
            if sc: line_hr += f" syscall={sc}"
            if p: line_hr += f" path={p}"
            if extras: line_hr += " " + " ".join(extras)
            viol_lines.append(line_hr)

        else:
            # Non-JSON lines (sandbox messages)
            emit_event(sample_id, run_id, {"type":"operator.action","action":"sandbox.msg","notes": line})
            alerts.append({"type":"sandbox.msg","message":line,"ts":ts})
            if "child killed by signal" in line or "sandbox]" in line:
                viol_lines.append(line)

    # Read stdout
    stdout_text = proc.stdout.read() if proc.stdout else ""
    rc = proc.wait(); stop=True
    duration_s = time.time()-t0

    # Detect termination signal
    term_signal=None
    for a in reversed(alerts):
        if a.get("type")=="sandbox.msg" and "child killed by signal" in a.get("message",""):
            try: term_signal=int(a["message"].split()[-1])
            except: pass
            break

    # Save stdout artifact
    out_path = ART_DIR / f"{run_id}.stdout.txt"
    out_path.write_text(stdout_text, encoding="utf-8")
    art_id = register_artifact(sample_id, run_id, out_path, "stdout")
    stdout_from_art = out_path.read_text(encoding="utf-8", errors="replace")

    # Append violation summary to stdout view
    stdout_view = stdout_from_art
    if viol_lines:
        stdout_view += ("\n\n=== Security Policy Violations ===\n" + "\n".join(viol_lines))

    emit_event(sample_id, run_id, {"type":"process.exit","action":"launcher.end",
        "duration_ms": int(duration_s*1000),
        "exit_code": rc,
        "term_signal": term_signal,
        "max_rss_kb": max_rss_kb})
    
    verdict = "blocked" if term_signal else ("clean" if rc==0 else "error")
    finalize_run(run_id, sample_id, verdict, start_ts)

    return {
        "sample_id": sample_id, "run_id": run_id,
        "command": cmd_argv, "launcher": LAUNCHER,
        "start_ts": start_ts, "end_ts": now_iso(),
        "duration_s": round(duration_s,6), "exit_code": rc, "term_signal": term_signal,
        "max_rss_kb": max_rss_kb, "alerts": alerts,
        "stdout": stdout_view,
        "mode": mode, "diagnose": diagnose, "pidns": pidns,
        "log_errno": log_errno, "notify_exec": notify_exec, "log_continue": log_continue,
        "permissions": perms,
        "stdout_artifact_id": art_id,
        "offline": (not BUBBLE_API)
    }


@app.get("/")
def index(): return render_template("index.html")

@app.post("/upload")
def upload():
    f = request.files.get("file")
    if not f: return jsonify({"error":"no file"}), 400
    dest = (UPLOAD_DIR / os.path.basename(f.filename))
    f.save(dest); os.chmod(dest, 0o755)

    # Shebang sniff
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

    # Extract permissions
    perms = data.get("permissions", {})
    
    # Common parameters
    common_params = {
        "mode": data.get("mode", "trap"),
        "diagnose": bool(data.get("diagnose", False)),
        "pidns": bool(data.get("pidns", False)),
        "log_errno": bool(data.get("log_errno", False)),
        "notify_exec": bool(data.get("notify_exec", False)),
        "log_continue": bool(data.get("log_continue", False)),
        "permissions": perms
    }

    if data.get("uploaded_path"):
        upath = Path(data["uploaded_path"]).resolve()
        interp = (data.get("interpreter") or "").strip()
        extra  = shlex.split(data.get("args","")) if data.get("args") else []
        cmd_argv = ([interp, str(upath)] if interp else [str(upath)]) + extra
        result = spawn_and_observe(cmd_argv, cwd=upath.parent, **common_params)
        return jsonify(result)

    cmd = data.get("cmd")
    if   isinstance(cmd, str):  cmd_argv = shlex.split(cmd)
    elif isinstance(cmd, list): cmd_argv = cmd
    else: return jsonify({"error":"cmd must be string or list"}), 400

    result = spawn_and_observe(cmd_argv, cwd=None, **common_params)
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, debug=True)