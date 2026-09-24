"""
SentinelAPI — the scanner engine.

Takes a target API's OpenAPI spec + base URL, registers two principals, and runs
three vulnerability classes:

  1. BOLA / IDOR            — cross-account differential test across ALL HTTP
                              methods; if B-owned data comes back under A's
                              token, the endpoint is flagged CRITICAL.
  2. Excessive data exposure — recursively diff actual response paths against
                              the schema (including nested objects).
  3. Broken authentication  — endpoints that declare a security requirement
                              but return data with no token are flagged HIGH.

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


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def all_endpoints(spec: dict) -> list[tuple[str, str, dict]]:
    """Return [(method, path, operation)] for every operation in the spec."""
    out = []
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if isinstance(op, dict) and method.lower() in HTTP_METHODS:
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


def op_has_security(op: dict) -> bool:
    return bool(op and op.get("security"))


def schema_paths(op: dict) -> set | None:
    """Return dotted paths declared in the 200 response schema, or None."""
    try:
        props = op["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
    except (KeyError, TypeError):
        return None

    out: set[str] = set()

    def walk(p, prefix=""):
        for name, raw in p.items():
            path = f"{prefix}.{name}" if prefix else name
            if isinstance(raw, dict):
                if "properties" in raw:
                    walk(raw["properties"], path)
                elif isinstance(raw.get("items"), dict) and "properties" in raw["items"]:
                    walk(raw["items"]["properties"], path)
                else:
                    out.add(path)
            else:
                out.add(path)

    walk(props)
    return out


def collect_response_paths(obj, prefix="", out=None):
    """Return dotted paths to every leaf in a JSON response."""
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                collect_response_paths(v, p, out)
            else:
                out.append(p)
    elif isinstance(obj, list):
        for v in obj:
            collect_response_paths(v, prefix, out)
    return out


def last_segment(p: str) -> str:
    return p.rsplit(".", 1)[-1]


def has_key(obj, key: str) -> bool:
    if isinstance(obj, dict):
        if key in obj:
            return True
        return any(has_key(v, key) for v in obj.values())
    if isinstance(obj, list):
        return any(has_key(v, key) for v in obj)
    return False


def sensitive(key: str) -> bool:
    k = key.lower()
    return any(h in k for h in SENSITIVE_HINTS)


def curl_repro(method: str, base: str, path: str, token: str) -> str:
    return f"curl -s -H 'Authorization: Bearer {token}' '{base}{path}'"


def curl_no_auth(method: str, base: str, path: str) -> str:
    return f"curl -s -X {method} '{base}{path}'"


def curl_body(method: str, base: str, path: str, token: str, body: str) -> str:
    return (f"curl -s -X {method} -H 'Authorization: Bearer {token}' "
            f"-H 'Content-Type: application/json' -d '{body}' '{base}{path}'")


def do_request(client, method, url, token):
    """Request of any method. Write methods get a minimal JSON body; an empty
    token means no Authorization header is sent."""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    kwargs = {"headers": headers}
    if method in ("POST", "PUT", "PATCH"):
        kwargs["json"] = {}
    r = client.request(method, url, **kwargs)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, None
def check_bola(client, base, endpoint, user_a, user_b, seen) -> list[Finding]:
    """Cross-account differential test for broken object-level authorization (any method)."""
    findings = []
    method, path, _op = endpoint
    params = path_params(path)
    if len(params) != 1:
        return findings

    b_markers = {k: user_b[k] for k in IDENTIFIER_FIELDS if k in user_b}
    for marker_key, marker_val in b_markers.items():
        filled = path.replace("{" + params[0] + "}", str(marker_val))
        try:
            status, body = do_request(client, method, base + filled, user_a["token"])
        except httpx.HTTPError as exc:
            print(f"  [!] request error on {filled}: {exc}", file=sys.stderr)
            continue
        if status != 200:
            continue

        for mk, mv in b_markers.items():
            if mv is not None and contains_value(body, mv):
                key = ("BOLA", method, path)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    severity="CRITICAL",
                    title="Broken Object-Level Authorization (BOLA / IDOR)",
                    endpoint=f"{method} {path}",
                    detail=(
                        f"Account '{user_a['username']}' (token A) called {filled} "
                        f"and received data owned by '{user_b['username']}' "
                        f"(field {mk}={mv!r}). No ownership check is enforced."
                    ),
                    reproduction=curl_repro(method, base, filled, user_a["token"]),
                    evidence=[{mk: mv}],
                ))
                break
    return findings


def check_exposure(endpoint, body, base, filled, user_a) -> list[Finding]:
    """Recursively diff actual response paths vs declared schema paths."""
    method, path, op = endpoint
    declared = schema_paths(op)
    if declared is None:
        return []

    actual = set(collect_response_paths(body))
    extras = actual - declared
    findings = []
    for key in sorted(extras):
        sev = "HIGH" if sensitive(last_segment(key)) else "MEDIUM"
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


def check_missing_auth(client, endpoint, base, filled) -> list[Finding]:
    """Flag endpoints that declare security but return data with no token."""
    method, path, _op = endpoint
    try:
        status, body = do_request(client, method, base + filled, "")
    except httpx.HTTPError:
        return []
    if status != 200 or body is None:
        return []
    return [Finding(
        severity="HIGH",
        title="Broken Authentication",
        endpoint=f"{method} {path}",
        detail=(
            f"The spec declares an API-key security requirement for {method} {path}, "
            "but it returns data with no Authorization header (HTTP 200)."
        ),
        reproduction=curl_no_auth(method, base, filled),
        evidence=[{"http_status": 200}],
    )]


def check_mass_assignment(client, base, endpoint, a_token) -> list[Finding]:
    """Inject privileged fields into write endpoints; flag if accepted & echoed."""
    method, path, _op = endpoint
    if method not in ("POST", "PUT", "PATCH"):
        return []
    injected = '{"username":"mallory","role":"admin","is_admin":true,"balance":999999}'
    try:
        r = client.request(method, base + path, content=injected, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {a_token}",
        })
    except httpx.HTTPError:
        return []
    if r.status_code not in (200, 201):
        return []
    try:
        body = r.json()
    except ValueError:
        return []
    echoed = [f for f in ("role", "is_admin") if has_key(body, f)]
    if not echoed:
        return []
    return [Finding(
        severity="HIGH",
        title="Mass Assignment",
        endpoint=f"{method} {path}",
        detail=(
            "The write endpoint accepts and persists privileged fields not part "
            f"of its contract ({', '.join(echoed)}). A client can escalate its "
            "own privileges."
        ),
        reproduction=curl_body(method, base, path, a_token, injected),
        evidence=[{"injected_fields": echoed}],
    )]


def check_bfa(client, base, endpoint, a_token) -> list[Finding]:
    """Flag admin-prefixed endpoints a regular (non-admin) token can access."""
    method, path, _op = endpoint
    if not path.startswith("/admin/"):
        return []
    try:
        status, _ = do_request(client, method, base + path, a_token)
    except httpx.HTTPError:
        return []
    if status != 200:
        return []
    return [Finding(
        severity="HIGH",
        title="Broken Function Level Authorization",
        endpoint=f"{method} {path}",
        detail=(
            f"A regular (non-admin) token can access {method} {path} (HTTP 200); "
            "the endpoint should be restricted to admin roles."
        ),
        reproduction=curl_repro(method, base, path, a_token),
        evidence=[{"role": "user", "http_status": 200}],
    )]


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

    endpoints = all_endpoints(spec)
    print(f"[*] found {len(endpoints)} operation(s)")

    a_token = user_a["token"]

    def resolve_baseline(ep):
        method, path, _op = ep
        params = path_params(path)
        if len(params) == 1:
            for k in IDENTIFIER_FIELDS:
                if k not in user_a:
                    continue
                cand = path.replace("{" + params[0] + "}", str(user_a[k]))
                try:
                    status, body = do_request(client, method, base + cand, a_token)
                except httpx.HTTPError:
                    continue
                if status == 200:
                    return cand, body
            return "", None
        if method not in ("GET", "HEAD"):
            return "", None  # avoid mutating writes
        try:
            status, body = do_request(client, method, base + path, a_token)
        except httpx.HTTPError:
            return "", None
        return (path, body) if status == 200 else ("", None)

    findings: list[Finding] = []
    seen: set = set()
    for ep in endpoints:
        findings += check_bola(client, base, ep, user_a, user_b, seen)
        findings += check_mass_assignment(client, base, ep, a_token)
        findings += check_bfa(client, base, ep, a_token)

        declared = schema_paths(ep[2])
        if declared is not None or op_has_security(ep[2]):
            filled, body = resolve_baseline(ep)
            if declared is not None and filled and body is not None:
                findings += check_exposure(ep, body, base, filled, user_a)
            if op_has_security(ep[2]) and filled:
                findings += check_missing_auth(client, ep, base, filled)

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
