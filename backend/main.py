"""
SentinelAPI — hosted product backend (production-ready).

Exposes:
  GET  /                              -> static scan UI
  POST /api/scan                      -> {target, consent, checks?, webhook_url?}
                                         validates, SSRF-guards, enqueues a scan
  GET  /api/scan/{job_id}             -> status + findings
  POST /api/scan/{job_id}/cancel      -> cancel an in-flight scan
  DELETE /api/scan/{job_id}           -> delete a scan from history
  GET  /api/scan/{job_id}/report      -> downloadable HTML report
  GET  /api/scan/{job_id}/report.json -> downloadable JSON report
  GET  /api/scan/{job_id}/report.pdf  -> downloadable PDF report
  GET  /api/scans                     -> recent scans + severity counts
  GET  /api/health                    -> liveness + version

Security / hardening:
  * SSRF guard        — blocks private/loopback/link-local/reserved addresses
  * API key auth      — SENTINEL_API_KEY (enforced when set)
  * Rate limiting     — per-client-IP sliding window (RATE_LIMIT_PER_MINUTE)
  * Bounded job pool  — MAX_WORKERS concurrent scans (no unbounded threads)
  * Cancel support    — in-flight engine subprocesses can be killed
  * Webhook notify    — optional POST on completion (webhook_url in request)
  * CORS              — CORS_ORIGINS for a separate frontend origin

Runs the Go engine (engine/sentinel-engine) as a subprocess and persists scan
history in SQLite. Set ALLOW_PRIVATE_SCAN=1 only for local development.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"
DIST = ROOT / "frontend" / "dist"
ENGINE_BIN = ROOT / "engine" / "sentinel-engine"
DB_PATH = Path(os.environ.get("DB_PATH", str(ROOT / "scans.db")))

# ---- environment-driven configuration --------------------------------------
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_SCAN", "0") == "1"
API_KEY = os.environ.get("SENTINEL_API_KEY", "").strip()
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "1") == "1"
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "10"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "4"))
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "120"))
CORS_ORIGINS = [o.strip() for o in os.environ.get(
    "CORS_ORIGINS", "*").split(",") if o.strip()]
DASH_USER = os.environ.get("SENTINEL_USER", "admin")
DASH_PASSWORD = os.environ.get("SENTINEL_PASSWORD", "").strip()
SESSION_SECRET = os.environ.get("SENTINEL_SESSION_SECRET", "athera-session-secret")

VALID_CHECKS = {"bola", "mass-assignment", "bfla", "exposure", "missing-auth",
                "security-misconfig", "rate-limit", "debug-endpoints",
                "jwt", "sqli", "cors", "ssrf", "graphql", "spec-audit"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("sentinelapi")

app = FastAPI(title="SentinelAPI", version="1.0.0")

if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# ---- SQLite job store ------------------------------------------------------
_conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
_conn.execute(
    "CREATE TABLE IF NOT EXISTS scans ("
    " id TEXT PRIMARY KEY, target TEXT, status TEXT,"
    " findings TEXT, error TEXT, created_at REAL)")
_conn.commit()
_lock = threading.Lock()

# ---- bounded worker pool + in-flight job registry ---------------------------
_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
_jobs: dict[str, subprocess.Popen] = {}          # job_id -> running engine proc
_job_lock = threading.Lock()

# Live scan logs, streamed to the dashboard's attack terminal.
_job_logs: dict[str, list[str]] = {}


def append_log(job_id: str, line: str) -> None:
    with _lock:
        lines = _job_logs.setdefault(job_id, [])
        lines.append(line)
        if len(lines) > 500:
            del lines[:-500]


def _db_update(sql: str, params: tuple) -> None:
    with _lock:
        _conn.execute(sql, params)
        _conn.commit()


def set_status(job_id: str, status: str, *, findings: list | None = None,
               error: str | None = None) -> None:
    if findings is not None:
        _db_update("UPDATE scans SET status=?, findings=?, error=? WHERE id=?",
                   (status, json.dumps(findings), error or "", job_id))
    elif error is not None:
        _db_update("UPDATE scans SET status=?, error=? WHERE id=?",
                   (status, error, job_id))
    else:
        _db_update("UPDATE scans SET status=? WHERE id=?", (status, job_id))


class ScanRequest(BaseModel):
    target: str
    consent: bool = False
    checks: list[str] | None = None
    webhook_url: str | None = None


# ---- SSRF guard ------------------------------------------------------------
def validate_target(url: str) -> str:
    """Allow only public http(s) targets. Block private/reserved addresses."""
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        raise ValueError("only http/https targets are allowed")
    if not u.hostname:
        raise ValueError("invalid target URL")
    if ALLOW_PRIVATE:
        return url
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(u.hostname, port)
    except socket.gaierror:
        raise ValueError("could not resolve target host")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ValueError("target resolves to a private/internal address")
    return url


def validate_checks(checks: list[str] | None) -> list[str] | None:
    """Normalise user-selected checks, or None to run everything."""
    if checks is None:
        return None
    clean = [c.strip().lower() for c in checks if c.strip()]
    bad = [c for c in clean if c not in VALID_CHECKS]
    if bad:
        raise ValueError(
            f"unknown check(s): {', '.join(bad)} — "
            f"valid: {', '.join(sorted(VALID_CHECKS))}")
    return clean or None


# ---- auth / rate-limit -----------------------------------------------------
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign_session(payload: dict) -> str:
    header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64u(json.dumps(payload).encode())
    sig = hmac.new(SESSION_SECRET.encode(), f"{header}.{body}".encode(),
                   hashlib.sha256).digest()
    return f"{header}.{body}.{_b64u(sig)}"


def _verify_session(token: str) -> dict | None:
    try:
        h, b, s = token.split(".")
    except ValueError:
        return None
    expected = hmac.new(SESSION_SECRET.encode(), f"{h}.{b}".encode(),
                        hashlib.sha256).digest()
    try:
        if not hmac.compare_digest(expected, _b64d(s)):
            return None
        payload = json.loads(_b64d(b))
    except Exception:
        return None
    if payload.get("exp", 0) < time.time():
        return None
    return payload


def require_auth(request: Request) -> None:
    """Auth: dashboard session JWT (when SENTINEL_PASSWORD set) or API key."""
    if not API_KEY and not DASH_PASSWORD:
        return  # open mode
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if DASH_PASSWORD and _verify_session(token):
            return
        if API_KEY and secrets.compare_digest(token, API_KEY):
            return
    provided = request.headers.get("x-api-key", "").strip()
    if API_KEY and provided and secrets.compare_digest(provided, API_KEY):
        return
    if DASH_PASSWORD:
        raise HTTPException(401, "login required — POST /api/auth/login")
    raise HTTPException(401, "missing or invalid API key")


_rate_hits: dict[str, list[float]] = {}
_rate_lock = threading.Lock()


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def enforce_rate_limit(request: Request) -> None:
    if not RATE_LIMIT_ENABLED or RATE_LIMIT_PER_MINUTE <= 0:
        return
    ip = _client_ip(request)
    now = time.time()
    with _rate_lock:
        hits = _rate_hits.setdefault(ip, [])
        hits[:] = [t for t in hits if now - t < 60.0]
        if len(hits) >= RATE_LIMIT_PER_MINUTE:
            retry_after = max(1, int(60 - (now - hits[0])))
            raise HTTPException(
                429,
                f"rate limit exceeded — try again in {retry_after}s",
                headers={"Retry-After": str(retry_after)})
        hits.append(now)


# ---- engine execution ------------------------------------------------------
class ScanCancelled(Exception):
    pass


def _ensure_engine_binary() -> None:
    if ENGINE_BIN.exists():
        return
    subprocess.run(["go", "build", "-o", "sentinel-engine", "."],
                   cwd=ROOT / "engine", check=True,
                   capture_output=True, timeout=300)


def execute_engine(target: str, checks: list[str] | None,
                   job_id: str) -> list:
    _ensure_engine_binary()
    cmd = [str(ENGINE_BIN), "--base", target,
           "--checks", ",".join(checks) if checks else "all"]
    with tempfile.TemporaryDirectory() as td:
        out_json = os.path.join(td, "findings.json")
        out_html = os.path.join(td, "report.html")
        cmd += ["--out-json", out_json, "--out-html", out_html]

        proc = subprocess.Popen(cmd, cwd=ROOT,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        with _job_lock:
            _jobs[job_id] = proc

        def _pump_logs():
            # Stream each engine line into the job's live log buffer.
            for line in proc.stdout:
                line = line.rstrip("\n").rstrip("\r")
                if line.strip():
                    append_log(job_id, line)

        reader = threading.Thread(target=_pump_logs, daemon=True)
        reader.start()
        try:
            proc.wait(timeout=SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise RuntimeError(f"scan exceeded {SCAN_TIMEOUT}s timeout")
        finally:
            with _job_lock:
                _jobs.pop(job_id, None)
        reader.join(timeout=2)

        if proc.returncode != 0:
            detail = "\n".join(_job_logs.get(job_id, [])[-5:])
            raise RuntimeError(detail or f"engine exited {proc.returncode}")

        with open(out_json) as fh:
            return json.load(fh)


# ---- webhook notification --------------------------------------------------
def notify_webhook(webhook_url: str, payload: dict) -> None:
    try:
        import urllib.request
        req = urllib.request.Request(
            webhook_url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception as exc:  # noqa: BLE001 — best-effort only
        log.warning("webhook delivery failed: %s", exc)


def run_scan(job_id: str, target: str, checks: list[str] | None,
             webhook_url: str | None) -> None:
    set_status(job_id, "running")
    append_log(job_id, "[*] sentinel engine armed")
    append_log(job_id, f"[*] target acquired: {target}")
    append_log(job_id, "[*] active checks: " + (",".join(checks) if checks else "all"))
    try:
        findings = execute_engine(target, checks, job_id)
        append_log(job_id, f"[+] mission complete: {len(findings)} finding(s)")
        set_status(job_id, "done", findings=findings)
        log.info("scan %s done: %d finding(s)", job_id[:8], len(findings))
        if webhook_url:
            notify_webhook(webhook_url, {
                "job_id": job_id, "target": target, "status": "done",
                "findings": findings,
            })
    except Exception as exc:  # noqa: BLE001 — surface to the client
        append_log(job_id, f"[!] scan fault: {exc}")
        set_status(job_id, "error", error=str(exc))
        log.warning("scan %s failed: %s", job_id[:8], exc)
        if webhook_url:
            notify_webhook(webhook_url, {
                "job_id": job_id, "target": target, "status": "error",
                "error": str(exc),
            })


# ---- routes ----------------------------------------------------------------
@app.get("/api/auth/status")
def auth_status():
    return {"login_required": bool(DASH_PASSWORD), "api_key_required": bool(API_KEY)}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def auth_login(req: LoginRequest):
    if not DASH_PASSWORD:
        raise HTTPException(400, "dashboard login is not configured")
    if req.username != DASH_USER or not secrets.compare_digest(req.password, DASH_PASSWORD):
        raise HTTPException(401, "invalid credentials")
    token = _sign_session({"sub": req.username, "exp": int(time.time()) + 86400})
    return {"token": token, "username": req.username, "expires_in": 86400}


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": app.version,
        "engine": ENGINE_BIN.exists(),
        "auth_enforced": bool(API_KEY) or bool(DASH_PASSWORD),
        "login_required": bool(DASH_PASSWORD),
        "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
    }


@app.post("/api/scan")
def scan(req: ScanRequest, request: Request):
    require_auth(request)
    enforce_rate_limit(request)
    if not req.consent:
        raise HTTPException(400, "You must confirm you are authorized to scan this target")
    try:
        target = validate_target(req.target)
        checks = validate_checks(req.checks)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    job_id = uuid.uuid4().hex
    _db_update(
        "INSERT INTO scans (id, target, status, findings, error, created_at)"
        " VALUES (?,?,?,?,?,?)",
        (job_id, target, "queued", "", "", time.time()))
    _executor.submit(run_scan, job_id, target, checks, req.webhook_url)
    log.info("scan %s queued for %s", job_id[:8], target)
    return {"job_id": job_id, "status": "queued"}


@app.get("/api/scan/{job_id}")
def scan_status(job_id: str, request: Request):
    require_auth(request)
    with _lock:
        row = _conn.execute(
            "SELECT target, status, findings, error FROM scans WHERE id=?",
            (job_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "scan not found")
    target, status, findings, error = row
    fs = json.loads(findings) if findings else []
    return {
        "job_id": job_id,
        "target": target,
        "status": status,
        "findings": fs,
        "grade": grade_of(fs),
        "logs": list(_job_logs.get(job_id, [])),
        "error": error,
    }


@app.post("/api/scan/{job_id}/cancel")
def cancel_scan(job_id: str, request: Request):
    require_auth(request)
    with _job_lock:
        proc = _jobs.get(job_id)
    with _lock:
        row = _conn.execute("SELECT status FROM scans WHERE id=?",
                            (job_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "scan not found")
    if row[0] not in ("queued", "running"):
        raise HTTPException(409, f"scan is already {row[0]}")
    if proc is not None:
        proc.kill()
    set_status(job_id, "cancelled")
    return {"job_id": job_id, "status": "cancelled"}


@app.delete("/api/scan/{job_id}")
def delete_scan(job_id: str, request: Request):
    require_auth(request)
    with _job_lock:
        proc = _jobs.get(job_id)
    if proc is not None:
        proc.kill()
    with _lock:
        cur = _conn.execute("DELETE FROM scans WHERE id=?", (job_id,))
        _conn.commit()
    _job_logs.pop(job_id, None)
    if cur.rowcount == 0:
        raise HTTPException(404, "scan not found")
    return {"job_id": job_id, "deleted": True}


@app.get("/api/scans")
def list_scans(request: Request):
    """Recent scans with per-severity counts, for the dashboard history panel."""
    require_auth(request)
    with _lock:
        rows = _conn.execute(
            "SELECT id, target, status, findings, created_at FROM scans"
            " ORDER BY created_at DESC LIMIT 20").fetchall()
    scans = []
    for job_id, target, status, findings, created_at in rows:
        fs = json.loads(findings) if findings else []
        counts: dict = {}
        for f in fs:
            sev = f.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1
        sample = [{
            "severity": f.get("severity", "LOW"),
            "title": f.get("title", ""),
            "endpoint": f.get("endpoint", ""),
        } for f in fs[:3]]
        scans.append({
            "job_id": job_id,
            "target": target,
            "status": status,
            "created_at": created_at,
            "findings": len(fs),
            "counts": counts,
            "grade": grade_of(fs),
            "sample": sample,
        })
    return {"scans": scans}


def _get_done_scan(job_id: str):
    with _lock:
        row = _conn.execute(
            "SELECT target, status, findings FROM scans WHERE id=?",
            (job_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "scan not found")
    target, status, findings = row
    if status != "done":
        raise HTTPException(409, f"scan is not complete (status={status})")
    return target, json.loads(findings) if findings else []


# ---- security grade + OWASP mapping ----------------------------------------
_GRADE_WEIGHT = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}


def grade_of(findings: list) -> dict:
    """SSL-Labs-style letter grade + 0-100 score from finding severities."""
    score = 100
    for f in findings:
        score -= _GRADE_WEIGHT.get(f.get("severity", "LOW"), 2)
    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return {"grade": grade, "score": score}


def owasp_of(title: str) -> tuple[str, str]:
    """Map a finding title to its OWASP API Security Top 10 (2023) category."""
    t = title.lower()
    if "object-level" in t or "bola" in t or "idor" in t:
        return ("API1 — Broken Object Level Authorization",
                "Verify the requester owns the object on every request before returning or modifying it.")
    if "excessive data exposure" in t or "data exposure" in t:
        return ("API3 — Excessive Data Exposure",
                "Return only fields declared in the schema; never rely on the client to filter sensitive data.")
    if "authentication" in t:
        return ("API2 — Broken Authentication",
                "Enforce authentication on every protected endpoint — declaring it in the spec is not enough.")
    if "function" in t or "bfla" in t:
        return ("API5 — Broken Function Level Authorization",
                "Enforce role checks server-side on admin endpoints; never trust client-side roles.")
    if "mass assignment" in t:
        return ("API6 — Mass Assignment",
                "Whitelist allowed fields on create/update and reject or ignore unknown properties.")
    if "security misconfiguration" in t:
        return ("API8 — Security Misconfiguration",
                "Remove server-version headers and add X-Content-Type-Options, X-Frame-Options and HSTS.")
    if "rate limit" in t:
        return ("API4 — Unrestricted Resource Consumption",
                "Add rate limiting (429 + Retry-After) per client on every endpoint.")
    if "debug endpoint" in t:
        return ("API9 — Improper Inventory Management",
                "Remove or lock down debug/staging endpoints in production.")
    return ("OWASP API Top 10",
            "Review the finding against the OWASP API Security Top 10 and apply the relevant control.")


# ---- report rendering ------------------------------------------------------
_SEV_COLORS = {"CRITICAL": "#f43f5e", "HIGH": "#fb923c",
               "MEDIUM": "#facc15", "LOW": "#60a5fa"}


def _render_report_html(target: str, findings: list) -> str:
    g = grade_of(findings)
    cards = []
    for f in findings:
        sev = f.get("severity", "LOW")
        color = _SEV_COLORS.get(sev, "#8b96ad")
        owasp, fix = owasp_of(f.get("title", ""))
        cards.append(
            f'<div style="background:#161b22;border:1px solid #30363d;'
            f'border-radius:12px;padding:16px;margin:12px 0;">'
            f'<span style="background:{color};color:#fff;font-size:11px;'
            f'font-weight:800;padding:3px 10px;border-radius:999px;">{sev}</span> '
            f'<b>{f.get("title", "")}</b><br/>'
            f'<code style="color:#79c0ff;font-size:13px;">{f.get("endpoint", "")}</code>'
            f'<p style="color:#c9d1d9;font-size:13px;">{f.get("detail", "")}</p>'
            f'<p style="color:#d29922;font-size:12px;margin:6px 0;"><b>🛡 {owasp}</b><br/>'
            f'<span style="color:#8b96ad;">Fix: {fix}</span></p>'
            f'<pre style="background:#0d1117;padding:10px;border-radius:8px;'
            f'color:#7ee787;font-size:12px;overflow-x:auto;">'
            f'{f.get("reproduction", "")}</pre></div>')
    body = "".join(cards) or '<p style="color:#8b96ad;">No vulnerabilities detected ✓</p>'
    return (
        '<!doctype html><html><head><meta charset="utf-8"/>'
        '<title>SentinelAPI Report</title></head>'
        '<body style="background:#0d1117;color:#e6edf3;font-family:system-ui,'
        'sans-serif;padding:32px;max-width:820px;margin:0 auto;">'
        f'<h1 style="font-size:22px;">Security Scan Report</h1>'
        f'<p style="color:#8b96ad;">Target: {target} · {len(findings)} finding(s) · '
        f'Security Grade: <b style="color:{_grade_color(g["grade"])};font-size:20px;">{g["grade"]}</b> '
        f'({g["score"]}/100)</p>'
        f'{body}</body></html>')


def _grade_color(grade: str) -> str:
    return {"A": "#3fb950", "B": "#58a6ff", "C": "#d29922",
            "D": "#db6d28", "F": "#f85149"}.get(grade, "#8b96ad")


def _render_report_pdf(target: str, findings: list) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            rightMargin=48, leftMargin=48,
                            topMargin=48, bottomMargin=48)
    styles = getSampleStyleSheet()
    g = grade_of(findings)
    story = [
        Paragraph("Security Scan Report", styles["Title"]),
        Paragraph(f"Target: {target} — {len(findings)} finding(s) — "
                  f'Security Grade: <b><font color="{_grade_color(g["grade"])}">{g["grade"]}</font></b> '
                  f'({g["score"]}/100)',
                  styles["Normal"]),
        Spacer(1, 20),
    ]
    if not findings:
        story.append(Paragraph("No vulnerabilities detected ✓", styles["Normal"]))
    for f in findings:
        sev = f.get("severity", "LOW")
        color = getattr(colors, {
            "CRITICAL": "red", "HIGH": "orange",
            "MEDIUM": "gold", "LOW": "skyblue"}.get(sev, "grey"))
        owasp, fix = owasp_of(f.get("title", ""))
        story.append(Table(
            [[Paragraph(f'<b>[{sev}] {f.get("title", "")}</b>',
                        styles["Heading3"])],
             [Paragraph(f.get("endpoint", ""), styles["Code"])],
             [Paragraph(f.get("detail", ""), styles["Normal"])],
             [Paragraph(f"<b>{owasp}</b> — {fix}", styles["Normal"])],
             [Paragraph(f.get("reproduction", ""), styles["Code"])]],
            colWidths=[doc.width],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
                ("BOX", (0, 0), (-1, -1), 1, color),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ])))
        story.append(Spacer(1, 12))
    doc.build(story)
    return buf.getvalue()


@app.get("/api/scan/{job_id}/report")
def scan_report(job_id: str, request: Request):
    """Download a self-contained HTML report for a completed scan."""
    require_auth(request)
    target, findings = _get_done_scan(job_id)
    html = _render_report_html(target, findings)
    return Response(
        content=html, media_type="text/html",
        headers={"Content-Disposition":
                 f'attachment; filename="sentinelapi-{job_id[:8]}.html"'})


@app.get("/api/scan/{job_id}/report.json")
def scan_report_json(job_id: str, request: Request):
    """Download a machine-readable JSON report for a completed scan."""
    require_auth(request)
    target, findings = _get_done_scan(job_id)
    return Response(
        content=json.dumps({"target": target, "findings": findings}, indent=2),
        media_type="application/json",
        headers={"Content-Disposition":
                 f'attachment; filename="sentinelapi-{job_id[:8]}.json"'})


@app.get("/api/scan/{job_id}/report.pdf")
def scan_report_pdf(job_id: str, request: Request):
    """Download a PDF report for a completed scan."""
    require_auth(request)
    target, findings = _get_done_scan(job_id)
    pdf = _render_report_pdf(target, findings)
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="sentinelapi-{job_id[:8]}.pdf"'})


# ---- SARIF / CSV export ----------------------------------------------------
def _render_report_sarif(target: str, findings: list) -> dict:
    rules = []
    rule_index: dict[str, int] = {}
    for f in findings:
        title = f.get("title", "Unknown")
        if title not in rule_index:
            rule_index[title] = len(rules)
            rules.append({
                "id": "SENT" + str(len(rules) + 1).zfill(4),
                "name": title,
                "shortDescription": {"text": title},
            })
    results = []
    for f in findings:
        rid = rules[rule_index[f.get("title", "Unknown")]]["id"]
        results.append({
            "ruleId": rid,
            "level": {"CRITICAL": "error", "HIGH": "error",
                      "MEDIUM": "warning", "LOW": "note"}.get(
                          f.get("severity", "LOW"), "note"),
            "message": {"text": f.get("detail", "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("endpoint", "")}}}],
            "properties": {
                "severity": f.get("severity", "LOW"),
                "reproduction": f.get("reproduction", ""),
            },
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SentinelAPI", "version": app.version,
                "informationUri": "https://athera-secure-production.up.railway.app",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def _render_report_csv(target: str, findings: list) -> str:
    import csv as _csv
    from io import StringIO
    buf = StringIO()
    w = _csv.writer(buf)
    w.writerow(["severity", "title", "endpoint", "detail", "reproduction"])
    for f in findings:
        w.writerow([f.get("severity", ""), f.get("title", ""),
                    f.get("endpoint", ""), f.get("detail", ""),
                    f.get("reproduction", "")])
    return buf.getvalue()


@app.get("/api/scan/{job_id}/report.sarif")
def scan_report_sarif(job_id: str, request: Request):
    """Download a SARIF 2.1.0 report (GitHub Code Scanning compatible)."""
    require_auth(request)
    target, findings = _get_done_scan(job_id)
    return Response(
        content=json.dumps(_render_report_sarif(target, findings), indent=2),
        media_type="application/sarif+json",
        headers={"Content-Disposition":
                 f'attachment; filename="sentinelapi-{job_id[:8]}.sarif"'})


@app.get("/api/scan/{job_id}/report.csv")
def scan_report_csv(job_id: str, request: Request):
    """Download a CSV report."""
    require_auth(request)
    target, findings = _get_done_scan(job_id)
    return Response(
        content=_render_report_csv(target, findings), media_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="sentinelapi-{job_id[:8]}.csv"'})


# ---- scan diff / regression ------------------------------------------------
@app.get("/api/scan/{job_id}/diff")
def scan_diff(job_id: str, request: Request):
    """Compare a scan against the previous completed scan of the same target."""
    require_auth(request)
    target, findings = _get_done_scan(job_id)
    with _lock:
        row = _conn.execute(
            "SELECT id, findings FROM scans WHERE target=? AND status='done'"
            " AND id != ? ORDER BY created_at DESC LIMIT 1",
            (target, job_id)).fetchone()

    def key(f):
        return (f.get("title", ""), f.get("endpoint", ""))

    if row is None:
        return {"job_id": job_id, "baseline": None,
                "new": [], "fixed": [], "new_count": 0, "fixed_count": 0,
                "unchanged": len(findings)}

    prev = json.loads(row[1]) if row[1] else []
    prev_keys = {key(f) for f in prev}
    curr_keys = {key(f) for f in findings}
    new = [f for f in findings if key(f) not in prev_keys]
    fixed = [f for f in prev if key(f) not in curr_keys]
    return {"job_id": job_id, "baseline": row[0],
            "new": new, "fixed": fixed,
            "new_count": len(new), "fixed_count": len(fixed),
            "unchanged": len(findings) - len(new)}


# ---- WebSocket live log streaming ------------------------------------------
@app.websocket("/api/scan/{job_id}/ws")
async def scan_ws(websocket: WebSocket, job_id: str):
    await websocket.accept()
    sent = 0
    try:
        while True:
            logs = list(_job_logs.get(job_id, []))
            if len(logs) > sent:
                for line in logs[sent:]:
                    await websocket.send_text(line)
                sent = len(logs)
            with _lock:
                row = _conn.execute(
                    "SELECT status FROM scans WHERE id=?", (job_id,)).fetchone()
            if row and row[0] in ("done", "error", "cancelled"):
                await websocket.send_text("__DONE__:" + row[0])
                break
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass


@app.on_event("shutdown")
def shutdown():
    _executor.shutdown(wait=False, cancel_futures=True)


# ---- static frontend (mounted last so /api/* routes win) -------------------
if DIST.exists():
    app.mount("/", StaticFiles(directory=str(DIST), html=True), name="frontend")
else:
    app.mount("/", StaticFiles(directory=str(STATIC), html=True), name="static")
