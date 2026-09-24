"""
End-to-end test for the hosted product backend.

Starts the vulnerable API + the backend, then verifies:
  1. /api/health responds
  2. consent is required (no consent -> 400)
  3. SSRF guard blocks private/internal targets
  4. a consented scan of the sandbox returns the 6 ground-truth findings

Usage: python tests/e2e_backend.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API_PORT = "8014"
BK_PORT = "8015"
API_BASE = f"http://127.0.0.1:{API_PORT}"
BK_BASE = f"http://127.0.0.1:{BK_PORT}"


def wait_ready(url: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.2)
    return False


def request(method: str, url: str, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_ssrf_guard() -> bool:
    env = dict(os.environ)
    env.pop("ALLOW_PRIVATE_SCAN", None)
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "from backend.main import validate_target\n"
        "blocked = ['http://127.0.0.1:8000', 'http://169.254.169.254/latest/meta-data',\n"
        "           'http://10.0.0.5', 'http://192.168.1.1', 'http://[::1]:80', 'http://localhost']\n"
        "for t in blocked:\n"
        "    try:\n"
        "        validate_target(t)\n"
        "        print('SSRF GUARD FAIL: allowed', t); sys.exit(1)\n"
        "    except ValueError:\n"
        "        pass\n"
        "print('ssrf guard: OK')\n"
    )
    r = subprocess.run([str(ROOT / ".venv/bin/python"), "-c", code],
                       cwd=ROOT, capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip())
    return r.returncode == 0


def main() -> int:
    env = dict(os.environ)
    env["ALLOW_PRIVATE_SCAN"] = "1"  # let the backend scan our local sandbox

    api = subprocess.Popen(
        [str(ROOT / ".venv/bin/python"), "-m", "uvicorn", "vuln_api.main:app",
         "--host", "127.0.0.1", "--port", API_PORT],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    bk = subprocess.Popen(
        [str(ROOT / ".venv/bin/python"), "-m", "uvicorn", "backend.main:app",
         "--host", "127.0.0.1", "--port", BK_PORT],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_ready(BK_BASE + "/api/health"), "backend did not start"
        assert wait_ready(API_BASE + "/health"), "target API did not start"

        # 1. health
        s, _ = request("GET", BK_BASE + "/api/health")
        print("health:", s)

        # 2. consent required
        s, body = request("POST", BK_BASE + "/api/scan",
                          {"target": API_BASE, "consent": False})
        print("no-consent ->", s, body.get("detail"))
        assert s == 400

        # 3. SSRF guard
        ssrf_ok = test_ssrf_guard()
        assert ssrf_ok

        # 4. happy path: consented scan of sandbox
        s, body = request("POST", BK_BASE + "/api/scan",
                          {"target": API_BASE, "consent": True})
        assert s == 200, body
        job_id = body["job_id"]

        findings = []
        for _ in range(30):
            time.sleep(1)
            s, st = request("GET", BK_BASE + f"/api/scan/{job_id}")
            if st["status"] == "done":
                findings = st["findings"]
                break
            if st["status"] == "error":
                print("scan error:", st["error"])
                return 1
        print("findings:", len(findings))
        assert len(findings) == 32, f"expected 32 findings, got {len(findings)}"

        # 5. JSON report download
        s, body = request("GET", BK_BASE + f"/api/scan/{job_id}/report.json")
        assert s == 200, body
        assert len(body.get("findings", [])) == 32, "JSON report findings mismatch"

        # 6. PDF report download
        req = urllib.request.Request(
            BK_BASE + f"/api/scan/{job_id}/report.pdf")
        with urllib.request.urlopen(req, timeout=10) as r:
            pdf = r.read()
        assert pdf[:4] == b"%PDF", "PDF report does not start with %PDF"

        # 6b. SARIF + CSV report download
        s, body = request("GET", BK_BASE + f"/api/scan/{job_id}/report.sarif")
        assert s == 200, body
        assert body.get("version") == "2.1.0", "SARIF report missing version"
        assert len(body.get("runs", [{}])[0].get("results", [])) == 32, "SARIF results mismatch"
        req2 = urllib.request.Request(
            BK_BASE + f"/api/scan/{job_id}/report.csv")
        with urllib.request.urlopen(req2, timeout=10) as r:
            csv = r.read().decode()
        assert csv.startswith("severity,title,endpoint"), "CSV report header mismatch"

        # 6c. regression diff
        s, body = request("POST", BK_BASE + "/api/scan",
                          {"target": API_BASE, "consent": True})
        assert s == 200, body
        job2 = body["job_id"]
        for _ in range(30):
            time.sleep(1)
            _, st = request("GET", BK_BASE + f"/api/scan/{job2}")
            if st["status"] == "done":
                break
        s, diff = request("GET", BK_BASE + f"/api/scan/{job2}/diff")
        assert s == 200, diff
        assert diff["baseline"] == job_id, "diff baseline should be the first scan"
        assert diff["new_count"] == 0 and diff["unchanged"] == 32, diff

        # 7. invalid checks rejected
        s, body = request("POST", BK_BASE + "/api/scan",
                          {"target": API_BASE, "consent": True,
                           "checks": ["bogus"]})
        print("bad-checks ->", s, body.get("detail"))
        assert s == 400

        # 8. delete scan
        s, body = request("DELETE", BK_BASE + f"/api/scan/{job_id}")
        print("delete ->", s, body)
        assert s == 200
        s, _ = request("GET", BK_BASE + f"/api/scan/{job_id}")
        assert s == 404, "deleted scan still fetchable"

        print("RESULT: PASS ✅  (health, consent, SSRF, 32 findings, "
              "JSON+PDF+SARIF+CSV reports, diff, check validation, delete)")
        return 0
    finally:
        bk.terminate(); bk.wait()
        api.terminate(); api.wait()


if __name__ == "__main__":
    sys.exit(main())
