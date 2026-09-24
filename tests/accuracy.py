"""
Accuracy evaluation for SentinelAPI.

Runs the scanner engine against the vulnerable sandbox API and measures
precision / recall / F1 against a known ground truth.

Ground truth = the vulnerabilities seeded in vuln_api/main.py:
  - 2 BOLA/IDOR findings (users + orders)
  - 4 excessive-exposure findings (password_hash, ssn, token, card_last4)
  - 0 findings on the SECURE /posts/{post_id} endpoint (negative control)

Usage:
  python tests/accuracy.py            # uses the Go engine (builds if needed)
  ENGINE=python python tests/accuracy.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (severity, title, endpoint, undeclared_field_or_None)
GROUND_TRUTH = {
    # BOLA / IDOR (all methods)
    ("CRITICAL", "Broken Object-Level Authorization (BOLA / IDOR)", "GET /users/{user_id}", None),
    ("CRITICAL", "Broken Object-Level Authorization (BOLA / IDOR)", "GET /orders/{order_id}", None),
    ("CRITICAL", "Broken Object-Level Authorization (BOLA / IDOR)", "PUT /users/{user_id}", None),
    # excessive data exposure (flat + nested)
    ("HIGH", "Excessive Data Exposure", "GET /users/{user_id}", "password_hash"),
    ("HIGH", "Excessive Data Exposure", "GET /users/{user_id}", "ssn"),
    ("HIGH", "Excessive Data Exposure", "GET /users/{user_id}", "token"),
    ("HIGH", "Excessive Data Exposure", "GET /orders/{order_id}", "card_last4"),
    ("HIGH", "Excessive Data Exposure", "PUT /users/{user_id}", "password_hash"),
    ("HIGH", "Excessive Data Exposure", "PUT /users/{user_id}", "ssn"),
    ("HIGH", "Excessive Data Exposure", "PUT /users/{user_id}", "token"),
    ("HIGH", "Excessive Data Exposure", "GET /users/{user_id}/profile", "profile.ssn"),
    ("HIGH", "Excessive Data Exposure", "GET /users/{user_id}/profile", "payment.card"),
    ("HIGH", "Excessive Data Exposure", "GET /users/{user_id}/profile", "payment.cvv"),
    # broken authentication (declared security, no enforcement)
    ("HIGH", "Broken Authentication", "GET /users/{user_id}", None),
    ("HIGH", "Broken Authentication", "GET /orders/{order_id}", None),
    ("HIGH", "Broken Authentication", "PUT /users/{user_id}", None),
    ("HIGH", "Broken Authentication", "GET /admin/users", None),
    # broken function-level authorization (regular user reaches admin endpoint)
    ("HIGH", "Broken Function Level Authorization", "GET /admin/users", None),
    # mass assignment (write endpoint accepts privileged fields)
    ("HIGH", "Mass Assignment", "POST /users", None),
}

PORT = int(os.environ.get("ACC_PORT", "8011"))
BASE = f"http://127.0.0.1:{PORT}"


def wait_ready(url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"target API did not become ready at {url}")


def field_of(f: dict):
    ev = f.get("evidence") or [{}]
    return ev[0].get("undeclared_field")  # None for BOLA findings


def detected_set(findings: list) -> set:
    return {
        (f["severity"], f["title"], f["endpoint"], field_of(f))
        for f in findings
    }


def main() -> int:
    engine = os.environ.get("ENGINE", "go")

    # 1. start the vulnerable API
    api = subprocess.Popen(
        [str(ROOT / ".venv/bin/python"), "-m", "uvicorn", "vuln_api.main:app",
         "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        wait_ready(BASE + "/health")

        # 2. run the engine
        out_json = f"/tmp/sentinel_acc_{engine}.json"
        out_html = f"/tmp/sentinel_acc_{engine}.html"
        if engine == "go":
            subprocess.run(["go", "build", "-o", "sentinel-engine", "."],
                           cwd=ROOT / "engine", check=True)
            subprocess.run(
                [str(ROOT / "engine/sentinel-engine"), "--base", BASE,
                 "--out-json", out_json, "--out-html", out_html],
                cwd=ROOT, check=True)
        else:
            subprocess.run(
                [str(ROOT / ".venv/bin/python"), "scanner/scanner.py",
                 "--base", BASE, "--out-json", out_json, "--out-html", out_html],
                cwd=ROOT, check=True)

        findings = json.loads(Path(out_json).read_text())
    finally:
        api.terminate()
        api.wait()

    detected = detected_set(findings)
    tp = detected & GROUND_TRUTH
    fp = detected - GROUND_TRUTH
    fn = GROUND_TRUTH - detected

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 0.0
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    posts_findings = [f for f in findings if "/posts/" in f["endpoint"]]

    print(f"engine        : {engine}")
    print(f"findings      : {len(findings)}")
    print(f"true positives: {len(tp)}")
    print(f"false positives: {len(fp)}")
    print(f"false negatives: {len(fn)}")
    if fp:
        print("FALSE POSITIVES:", *fp, sep="\n  - ")
    if fn:
        print("FALSE NEGATIVES (missed):", *fn, sep="\n  - ")
    print(f"secure /posts findings (must be 0): {len(posts_findings)}")
    print(f"precision = {precision:.3f}")
    print(f"recall    = {recall:.3f}")
    print(f"F1        = {f1:.3f}")

    ok = precision == 1.0 and recall == 1.0 and len(posts_findings) == 0
    print("RESULT:", "PASS ✅" if ok else "FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
