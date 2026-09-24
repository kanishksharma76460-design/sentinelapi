"""
SentinelAPI — hosted product backend.

Exposes:
  GET  /                    -> static scan UI
  POST /api/scan            -> {target, consent}  -> validates, SSRF-guards,
                               queues a scan, returns job_id
  GET  /api/scan/{job_id}   -> status + findings
  GET  /api/health          -> liveness

Runs the Go engine (engine/sentinel-engine) as a subprocess and persists scan
history in SQLite. Set ALLOW_PRIVATE_SCAN=1 only for local development.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"
ENGINE_BIN = ROOT / "engine" / "sentinel-engine"
DB_PATH = Path(os.environ.get("DB_PATH", str(ROOT / "scans.db")))
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_SCAN", "0") == "1"

app = FastAPI(title="SentinelAPI", version="1.0.0")

# ---- job store (SQLite) ----------------------------------------------------
_conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
_conn.execute(
    "CREATE TABLE IF NOT EXISTS scans ("
    " id TEXT PRIMARY KEY, target TEXT, status TEXT,"
    " findings TEXT, error TEXT, created_at REAL)")
_conn.commit()
_lock = threading.Lock()


class ScanRequest(BaseModel):
    target: str
    consent: bool = False


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


# ---- engine execution ------------------------------------------------------
def execute_engine(target: str) -> list:
    if not ENGINE_BIN.exists():
        subprocess.run(["go", "build", "-o", "sentinel-engine", "."],
                       cwd=ROOT / "engine", check=True,
                       capture_output=True, timeout=300)
    with tempfile.TemporaryDirectory() as td:
        out_json = os.path.join(td, "findings.json")
        out_html = os.path.join(td, "report.html")
        subprocess.run(
            [str(ENGINE_BIN), "--base", target,
             "--out-json", out_json, "--out-html", out_html],
            cwd=ROOT, check=True, capture_output=True, timeout=120)
        with open(out_json) as fh:
            return json.load(fh)


def run_scan(job_id: str, target: str) -> None:
    try:
        findings = execute_engine(target)
        with _lock:
            _conn.execute(
                "UPDATE scans SET status='done', findings=? WHERE id=?",
                (json.dumps(findings), job_id))
            _conn.commit()
    except Exception as exc:  # noqa: BLE001 - surface to the client
        with _lock:
            _conn.execute(
                "UPDATE scans SET status='error', error=? WHERE id=?",
                (str(exc), job_id))
            _conn.commit()


# ---- routes ----------------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(str(STATIC / "index.html"))


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
def scan(req: ScanRequest):
    if not req.consent:
        raise HTTPException(400, "You must confirm you are authorized to scan this target")
    try:
        target = validate_target(req.target)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    job_id = uuid.uuid4().hex
    with _lock:
        _conn.execute(
            "INSERT INTO scans (id, target, status, findings, error, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (job_id, target, "queued", "", "", time.time()))
        _conn.commit()
    threading.Thread(target=run_scan, args=(job_id, target), daemon=True).start()
    return {"job_id": job_id, "status": "queued"}


@app.get("/api/scan/{job_id}")
def scan_status(job_id: str):
    with _lock:
        row = _conn.execute(
            "SELECT target, status, findings, error FROM scans WHERE id=?",
            (job_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "scan not found")
    target, status, findings, error = row
    return {
        "job_id": job_id,
        "target": target,
        "status": status,
        "findings": json.loads(findings) if findings else [],
        "error": error,
    }


@app.get("/api/scans")
def list_scans():
    """Recent scans with per-severity counts, for the dashboard history panel."""
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
            "sample": sample,
        })
    return {"scans": scans}


def _render_report(target: str, findings: list) -> str:
    cards = []
    for f in findings:
        sev = f.get("severity", "LOW")
        color = {"CRITICAL": "#f43f5e", "HIGH": "#fb923c",
                 "MEDIUM": "#facc15", "LOW": "#60a5fa"}.get(sev, "#8b96ad")
        cards.append(
            f'<div style="background:#161b22;border:1px solid #30363d;'
            f'border-radius:12px;padding:16px;margin:12px 0;">'
            f'<span style="background:{color};color:#fff;font-size:11px;'
            f'font-weight:800;padding:3px 10px;border-radius:999px;">{sev}</span> '
            f'<b>{f.get("title", "")}</b><br/>'
            f'<code style="color:#79c0ff;font-size:13px;">{f.get("endpoint", "")}</code>'
            f'<p style="color:#c9d1d9;font-size:13px;">{f.get("detail", "")}</p>'
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
        f'<p style="color:#8b96ad;">Target: {target} · {len(findings)} finding(s)</p>'
        f'{body}</body></html>')


@app.get("/api/scan/{job_id}/report")
def scan_report(job_id: str):
    """Download a self-contained HTML report for a completed scan."""
    with _lock:
        row = _conn.execute(
            "SELECT target, status, findings FROM scans WHERE id=?",
            (job_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "scan not found")
    target, status, findings = row
    if status != "done":
        raise HTTPException(409, "scan is not complete")
    html = _render_report(target, json.loads(findings) if findings else [])
    return Response(
        content=html, media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="sentinelapi-{job_id[:8]}.html"'},
    )
