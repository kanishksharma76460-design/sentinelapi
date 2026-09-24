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
4. Set env vars if needed (all optional):
   - `ALLOW_PRIVATE_SCAN=0` (default — keep it off in production)
   - `DB_PATH=/data/scans.db` (mount a volume at `/data` for scan-history persistence)
5. Add a **domain** (Railway → Networking) → e.g. `https://sentinelapi.up.railway.app`.
6. Verify: open `https://<domain>/api/health` → `{"status":"ok"}`.

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
