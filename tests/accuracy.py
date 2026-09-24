"""
SentinelAPI benchmark — runs the scanner against a corpus of vulnerable sandbox
APIs and reports per-target + aggregate precision / recall / F1.

Ground truth = the vulnerabilities seeded in each sandbox. Each target also has
secure control endpoints that must produce ZERO findings.

Usage:
  python tests/accuracy.py              # Go engine, whole corpus
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
BANK_TRUTH = {
    ("CRITICAL", "Broken Object-Level Authorization (BOLA / IDOR)", "GET /users/{user_id}", None),
    ("CRITICAL", "Broken Object-Level Authorization (BOLA / IDOR)", "GET /orders/{order_id}", None),
    ("CRITICAL", "Broken Object-Level Authorization (BOLA / IDOR)", "PUT /users/{user_id}", None),
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
    ("HIGH", "Broken Authentication", "GET /users/{user_id}", None),
    ("HIGH", "Broken Authentication", "GET /orders/{order_id}", None),
    ("HIGH", "Broken Authentication", "PUT /users/{user_id}", None),
    ("HIGH", "Broken Authentication", "GET /admin/users", None),
    ("HIGH", "Broken Function Level Authorization", "GET /admin/users", None),
    ("HIGH", "Mass Assignment", "POST /users", None),
}

LIBRARY_TRUTH = {
    ("CRITICAL", "Broken Object-Level Authorization (BOLA / IDOR)", "GET /books/{book_id}", None),
    ("MEDIUM", "Excessive Data Exposure", "GET /books/{book_id}", "isbn"),
    ("HIGH", "Broken Authentication", "GET /books/{book_id}", None),
    ("HIGH", "Broken Authentication", "GET /members", None),
    ("HIGH", "Excessive Data Exposure", "GET /members/{member_id}/profile", "member.library_card"),
}

TARGETS = [
    {"name": "bank", "module": "vuln_api.main:app", "port": "8011", "truth": BANK_TRUTH},
    {"name": "library", "module": "vuln_api2.main:app", "port": "8012", "truth": LIBRARY_TRUTH},
]

ENGINE = os.environ.get("ENGINE", "go")


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
    return ev[0].get("undeclared_field")  # None for non-exposure findings


def detected_set(findings: list) -> set:
    return {(f["severity"], f["title"], f["endpoint"], field_of(f)) for f in findings}


def run_engine(target: dict) -> list:
    base = f"http://127.0.0.1:{target['port']}"
    out_json = f"/tmp/sentinel_{target['name']}_{ENGINE}.json"
    out_html = f"/tmp/sentinel_{target['name']}_{ENGINE}.html"
    if ENGINE == "go":
        subprocess.run(["go", "build", "-o", "sentinel-engine", "."],
                       cwd=ROOT / "engine", check=True, capture_output=True)
        subprocess.run([str(ROOT / "engine/sentinel-engine"), "--base", base,
                        "--out-json", out_json, "--out-html", out_html],
                       cwd=ROOT, check=True, capture_output=True)
    else:
        subprocess.run([str(ROOT / ".venv/bin/python"), "scanner/scanner.py",
                        "--base", base, "--out-json", out_json, "--out-html", out_html],
                       cwd=ROOT, check=True, capture_output=True)
    return json.loads(Path(out_json).read_text())


def evaluate(target: dict) -> dict:
    api = subprocess.Popen(
        [str(ROOT / ".venv/bin/python"), "-m", "uvicorn", target["module"],
         "--host", "127.0.0.1", "--port", target["port"]],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_ready(f"http://127.0.0.1:{target['port']}/health")
        findings = run_engine(target)
    finally:
        api.terminate()
        api.wait()

    detected = detected_set(findings)
    truth = target["truth"]
    tp = detected & truth
    fp = detected - truth
    fn = truth - detected
    return {
        "name": target["name"], "n": len(findings),
        "tp": len(tp), "fp": len(fp), "fn": len(fn),
        "fp_list": sorted(fp), "fn_list": sorted(fn),
    }


def main() -> int:
    print(f"engine: {ENGINE}")
    results = [evaluate(t) for t in TARGETS]

    tot_tp = sum(r["tp"] for r in results)
    tot_fp = sum(r["fp"] for r in results)
    tot_fn = sum(r["fn"] for r in results)
    precision = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) else 0.0
    recall = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    for r in results:
        print(f"\n[{r['name']}] findings={r['n']} TP={r['tp']} FP={r['fp']} FN={r['fn']}")
        if r["fp_list"]:
            print("  FALSE POSITIVES:", *r["fp_list"], sep="\n    - ")
        if r["fn_list"]:
            print("  FALSE NEGATIVES:", *r["fn_list"], sep="\n    - ")

    print(f"\n=== AGGREGATE ({len(TARGETS)} targets) ===")
    print(f"true positives: {tot_tp}")
    print(f"false positives: {tot_fp}")
    print(f"false negatives: {tot_fn}")
    print(f"precision = {precision:.3f}")
    print(f"recall    = {recall:.3f}")
    print(f"F1        = {f1:.3f}")

    ok = tot_fp == 0 and tot_fn == 0
    print("RESULT:", "PASS ✅" if ok else "FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
