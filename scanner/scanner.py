"""
SentinelAPI — the scanner engine.

Takes a target API's OpenAPI spec + base URL, registers two principals, and runs
two vulnerability classes:

  1. BOLA / IDOR            — cross-account differential test: call each
                              resource endpoint with account A's token but
                              account B's resource identifier; if B-owned data
                              comes back, the endpoint is flagged CRITICAL.
  2. Excessive data exposure — diff the *actual* response keys against the
                              keys declared in the OpenAPI response schema;
                              any undeclared, sensitive-looking key is flagged.

Outputs:
  findings.json   — machine-readable results
  report.html     — self-contained, severity-ranked dashboard (no server needed)

Usage:
  python scanner/scanner.py --base http://127.0.0.1:8000 \
        --out-json scanner/findings.json --out-html scanner/report.html
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass, field

import httpx

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
# keys whose presence in a response is plausibly a leak
SENSITIVE_HINTS = (
    "password", "passwd", "secret", "token", "ssn", "card", "cvv",
    "pan", "key", "otp", "aadhaar", "pan_number",
)

# marker fields returned by /register that identify a principal (used as the
# oracle for "is this B's data?")
IDENTIFIER_FIELDS = ("id", "username", "email", "order_id", "post_id")


@dataclass
class Finding:
    severity: str
    title: str
    endpoint: str
    detail: str
    reproduction: str
    evidence: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "title": self.title,
            "endpoint": self.endpoint,
            "detail": self.detail,
            "reproduction": self.reproduction,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def fetch_spec(client: httpx.Client, base: str) -> dict:
    r = client.get(f"{base}/openapi.json")
    r.raise_for_status()
    return r.json()


def register(client: httpx.Client, base: str, username: str) -> dict:
    r = client.post(f"{base}/register", json={"username": username})
    r.raise_for_status()
    return r.json()


def get_param_endpoints(spec: dict) -> list[tuple[str, str, dict]]:
    """Return [(method, path, operation)] for GET endpoints with path params."""
    out = []
    for path, methods in spec.get("paths", {}).items():
        if "{" not in path:
            continue
        for method, op in methods.items():
            if method.lower() == "get":
                out.append((method.upper(), path, op))
    return out


def path_params(path: str) -> list[str]:
    return re.findall(r"\{([^}]+)\}", path)


def contains_value(obj, target) -> bool:
    """Recursive search: is `target` present anywhere in the JSON object?"""
    if isinstance(obj, dict):
        for v in obj.values():
            if v == target or contains_value(v, target):
                return True
    elif isinstance(obj, list):
        for v in obj:
            if v == target or contains_value(v, target):
                return True
    return False


def schema_keys(op: dict) -> set | None:
    """Extract declared response property names, or None if undeclared."""
    try:
        props = op["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
        return set(props.keys())
    except (KeyError, TypeError):
        return None


def sensitive(key: str) -> bool:
    k = key.lower()
    return any(h in k for h in SENSITIVE_HINTS)


def curl_repro(method: str, base: str, path: str, token: str) -> str:
    return f"curl -s -H 'Authorization: Bearer {token}' '{base}{path}'"


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------
def check_bola(client, base, endpoint, user_a, user_b, seen) -> list[Finding]:
    """Cross-account differential test for broken object-level authorization."""
    findings = []
    method, path, _op = endpoint
    params = path_params(path)
    if len(params) != 1:
        return findings

    # values owned by B — if any comes back under A's session, that's a leak.
    b_markers = {k: user_b[k] for k in IDENTIFIER_FIELDS if k in user_b}

    for marker_key, marker_val in b_markers.items():
        filled = path.replace("{" + params[0] + "}", str(marker_val))
        try:
            r = client.request(
                method, base + filled,
                headers={"Authorization": f"Bearer {user_a['token']}"},
            )
        except httpx.HTTPError as exc:
            print(f"  [!] request error on {filled}: {exc}", file=sys.stderr)
            continue
        if r.status_code != 200:
            continue
        try:
            body = r.json()
        except json.JSONDecodeError:
            body = None

        for mk, mv in b_markers.items():
            if mv is not None and contains_value(body, mv):
                key = ("BOLA", path)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    severity="CRITICAL",
                    title="Broken Object-Level Authorization (BOLA / IDOR)",
                    endpoint=f"{method} {path}",
                    detail=(
                        f"Account '{user_a['username']}' (token A) fetched "
                        f"{filled} and received data owned by "
                        f"'{user_b['username']}' (field {mk}={mv!r}). No "
                        "ownership check is enforced."
                    ),
                    reproduction=curl_repro(method, base, filled, user_a["token"]),
                    evidence=[{mk: mv}],
                ))
                break
    return findings


def check_exposure(client, base, endpoint, user_a) -> list[Finding]:
    """Diff actual response keys vs declared schema keys."""
    method, path, op = endpoint
    params = path_params(path)
    if len(params) != 1:
        return []
    declared = schema_keys(op)
    if declared is None:
        return []  # no declared schema -> nothing to diff against

    # fetch A's own resource to get a 200 baseline; the path param may map to
    # any of A's identifier fields (id, order_id, ...), so try each in turn.
    a_markers = {k: user_a[k] for k in IDENTIFIER_FIELDS if k in user_a}
    body = None
    filled = None
    for _mk, mv in a_markers.items():
        candidate = path.replace("{" + params[0] + "}", str(mv))
        try:
            r = client.request(
                method, base + candidate,
                headers={"Authorization": f"Bearer {user_a['token']}"},
            )
        except httpx.HTTPError as exc:
            print(f"  [!] request error on {candidate}: {exc}", file=sys.stderr)
            continue
        if r.status_code == 200:
            try:
                body = r.json()
            except json.JSONDecodeError:
                body = None
            filled = candidate
            break
    if body is None or filled is None:
        return []

    actual = set(body.keys()) if isinstance(body, dict) else set()
    extras = actual - declared
    findings = []
    for key in sorted(extras):
        sev = "HIGH" if sensitive(key) else "MEDIUM"
        findings.append(Finding(
            severity=sev,
            title="Excessive Data Exposure",
            endpoint=f"{method} {path}",
            detail=(
                f"Field '{key}' is returned in the response but is NOT declared "
                "in the OpenAPI response schema. The client receives more data "
                "than the contract specifies."
            ),
            reproduction=curl_repro(method, base, filled, user_a["token"]),
            evidence=[{"undeclared_field": key, "declared_fields": sorted(declared)}],
        ))
    return findings


# ---------------------------------------------------------------------------
# report rendering (self-contained HTML — no server required)
# ---------------------------------------------------------------------------
def render_html(spec: dict, findings: list[Finding], base: str) -> str:
    title = spec.get("info", {}).get("title", "Target API")
    cards = []
    for f in findings:
        badge = {
            "CRITICAL": "#e5484d",
            "HIGH": "#f76b15",
            "MEDIUM": "#ffb224",
            "LOW": "#3e63dd",
        }.get(f.severity, "#8d8d8d")
        ev = html.escape(json.dumps(f.evidence, indent=2))
        cards.append(f"""
        <div class="card">
          <div class="card-head">
            <span class="badge" style="background:{badge}">{html.escape(f.severity)}</span>
            <span class="title">{html.escape(f.title)}</span>
          </div>
          <div class="endpoint">{html.escape(f.endpoint)}</div>
          <p class="detail">{html.escape(f.detail)}</p>
          <pre class="curl">{html.escape(f.reproduction)}</pre>
          <details><summary>evidence</summary><pre>{ev}</pre></details>
        </div>""")

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = " · ".join(f"{k}: {v}" for k, v in
                         sorted(counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SentinelAPI — Scan Report</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         background:#0d1117; color:#e6edf3; }}
  header {{ padding:28px 36px; border-bottom:1px solid #21262d;
           background:linear-gradient(180deg,#161b22,#0d1117); }}
  h1 {{ margin:0 0 6px; font-size:22px; }}
  .sub {{ color:#8b949e; font-size:13px; }}
  .stats {{ margin-top:12px; font-size:14px; color:#79c0ff; }}
  main {{ padding:24px 36px; display:grid; gap:16px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:10px; padding:16px; }}
  .card-head {{ display:flex; align-items:center; gap:10px; }}
  .badge {{ font-size:11px; font-weight:700; letter-spacing:.04em; color:#fff;
           padding:3px 9px; border-radius:999px; }}
  .title {{ font-weight:600; font-size:15px; }}
  .endpoint {{ color:#79c0ff; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
              font-size:13px; margin:8px 0; }}
  .detail {{ color:#c9d1d9; font-size:13px; line-height:1.5; margin:8px 0; }}
  .curl {{ background:#0d1117; border:1px solid #30363d; border-radius:6px;
          padding:10px; font-size:12px; color:#7ee787; overflow-x:auto; }}
  details {{ color:#8b949e; font-size:12px; margin-top:8px; }}
  details pre {{ background:#0d1117; padding:8px; border-radius:6px; overflow-x:auto; }}
  .empty {{ color:#8b949e; padding:40px; text-align:center; }}
</style>
</head>
<body>
<header>
  <h1>🛡️ SentinelAPI — Scan Report</h1>
  <div class="sub">Target: {html.escape(title)} · {html.escape(base)}</div>
  <div class="stats">{html.escape(summary) or 'no findings'}</div>
</header>
<main>
  {''.join(cards) or '<div class="empty">No vulnerabilities detected ✓</div>'}
</main>
</body>
</html>"""


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="SentinelAPI scanner")
    ap.add_argument("--base", required=True, help="target API base URL")
    ap.add_argument("--out-json", default="findings.json")
    ap.add_argument("--out-html", default="report.html")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    client = httpx.Client(timeout=10, follow_redirects=False)

    spec = fetch_spec(client, base)
    user_a = register(client, base, "alice")
    user_b = register(client, base, "bob")
    print(f"[*] registered alice (id={user_a['id']}) and bob (id={user_b['id']})")

    endpoints = get_param_endpoints(spec)
    print(f"[*] found {len(endpoints)} GET endpoint(s) with path parameters")

    findings: list[Finding] = []
    seen: set = set()
    for ep in endpoints:
        findings += check_bola(client, base, ep, user_a, user_b, seen)
        findings += check_exposure(client, base, ep, user_a)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    with open(args.out_json, "w") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=2)
    with open(args.out_html, "w") as fh:
        fh.write(render_html(spec, findings, base))

    print(f"[*] {len(findings)} finding(s):")
    for f in findings:
        print(f"    {f.severity:<9} {f.title}  ->  {f.endpoint}")
    print(f"[*] wrote {args.out_json}")
    print(f"[*] wrote {args.out_html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
