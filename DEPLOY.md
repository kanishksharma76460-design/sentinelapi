# Deploying SentinelAPI to Railway

Two services:

| Service | What it runs | Dockerfile |
|---|---|---|
| **product** | scan UI + API + Go engine | `Dockerfile` (root) |
| **sandbox** | the deliberately vulnerable target (demo) | `Dockerfile.sandbox` |

> The product scans **public http(s) targets** (SSRF-guarded). The sandbox's public
> Railway URL is a valid target, so the demo is self-contained.

---

## 1. Deploy the product

1. Push this repo to GitHub (already done — private repo works; Railway reads via OAuth).
2. In Railway: **New Project → Deploy from GitHub repo** → select the repo.
3. Railway auto-detects `Dockerfile` + `railway.toml` and deploys the product.
4. Set env vars (see the configuration table below — most are optional but
   `SENTINEL_API_KEY` is strongly recommended for production).
5. Add a **domain** (Railway → Networking) → e.g. `https://sentinelapi.up.railway.app`.
6. Verify: open `https://<domain>/api/health` → `{"status":"ok", ...}`.

## 2. Deploy the sandbox (for the live demo)

1. Railway → **New Service → Deploy from Dockerfile** (same repo).
2. Set **Dockerfile path** to `Dockerfile.sandbox`.
3. Deploy → it serves `vuln_api.main:app` on port 8000.
4. Add a domain → `https://sandbox.up.railway.app`.

## 3. Wire them together

- Open the product UI, paste the **sandbox's public URL**, tick the consent box, Scan.
- You'll see the 19 findings on the live dashboard.

## 4. Build checks (local, if Docker daemon is running)

```bash
docker build -t sentinelapi .
docker build -f Dockerfile.sandbox -t sentinelapi-sandbox .
```

---

### What runs in the product container

- `backend/main.py` — FastAPI (consent gate + SSRF guard + SQLite job queue)
- `backend/static/index.html` — the Three.js UI
- `engine/sentinel-engine` — the Go scanner (built in-image, no `go` needed at runtime)

### Security notes for production

- `ALLOW_PRIVATE_SCAN` must stay `0` (blocks SSRF to internal networks).
- The scan consent checkbox is the authorization record — keep it required.
- `scans.db` is ephemeral by default; mount a volume at `DB_PATH` for history.
- Set `SENTINEL_API_KEY` and enter the same key in the UI's **API Key** field
  (sidebar) — the backend then requires it on every `/api/*` route.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_API_KEY` | *(empty)* | Enforce API-key auth on all `/api/*` routes when set |
| `ALLOW_PRIVATE_SCAN` | `0` | Allow scanning private/localhost targets (dev only) |
| `RATE_LIMIT_ENABLED` | `1` | Enable per-IP rate limiting |
| `RATE_LIMIT_PER_MINUTE` | `10` | Max scans per client IP per minute |
| `MAX_WORKERS` | `4` | Max concurrent scan engine processes |
| `SCAN_TIMEOUT_SECONDS` | `120` | Per-scan engine timeout |
| `DB_PATH` | `scans.db` | SQLite path (mount a volume for persistence) |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins for a separate frontend |

### API surface

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scan` | Start a scan — body `{target, consent, checks?, webhook_url?}` |
| `GET` | `/api/scan/{id}` | Poll status + findings |
| `POST` | `/api/scan/{id}/cancel` | Cancel an in-flight scan |
| `DELETE` | `/api/scan/{id}` | Delete a scan from history |
| `GET` | `/api/scan/{id}/report` | HTML report (download) |
| `GET` | `/api/scan/{id}/report.json` | JSON report (download) |
| `GET` | `/api/scan/{id}/report.pdf` | PDF report (download) |
| `GET` | `/api/scans` | Recent scans + severity counts |
| `GET` | `/api/health` | Liveness + version |

`checks` accepts any subset of `bola`, `mass-assignment`, `bfla`, `exposure`,
`missing-auth` (omit for all). `webhook_url` receives a POST with the findings
on completion.
