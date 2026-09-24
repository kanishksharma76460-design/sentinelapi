# AMIHACKS 2026 — Problem Statements & Technical Analysis

> **24-hour hackathon · 3 tracks · mixed-skill ceiling**
> This README frames each track as its underlying *computational problem* and gives a concrete, tiered tech stack — MVP (what wins the demo) vs. Advanced (what wins the ceiling).

| Track | Problem | Core CS problem class | Difficulty |
|---|---|---|---|
| **A** | Surplus-to-Shelter — Food Rescue Routing | Online assignment + routing with deadlines | Easy–Medium |
| **B** | CityPulse — Live Civic Health Dashboard | Stream fusion + anomaly detection | Medium |
| **C** | SentinelAPI — Zero-Trust API Vulnerability Scanner | Differential program testing / security analysis | Medium–Hard |

---

## Track A — Surplus-to-Shelter: Real-Time Food Rescue Routing

**Framing.** Not a CRUD app — it's an **online bipartite assignment problem** over a spatio-temporal stream:

- Donations arrive dynamically: `(location, food_type, quantity, expiry, cold_chain)`.
- Shelters are resources with capacity and compatibility constraints: `(location, capacity, diet_restrictions, refrigeration)`.
- Each donation has a **hard deadline** (expiry) → it's a deadline-constrained assignment with travel cost.

**Key challenges**

1. **Match quality** — minimize waste (unmatched food past expiry) while respecting food-type / capacity / cold-chain compatibility.
2. **Routing realism** — Euclidean distance is wrong; road network distance matters in a city.
3. **State machine** — `Available → Claimed → In-transit → Delivered` with real-time visibility to donors, shelters, and drivers.
4. **Scale realism** — even a toy dataset must be architecturally consistent with the real-time constraint.

**Tech stack**

| Layer | MVP | Advanced |
|---|---|---|
| Matching | Greedy + deadline-first heap, or `scipy.optimize.linear_sum_assignment` (min-cost bipartite) | Google **OR-Tools** CP-SAT for vehicle routing + assignment |
| Distance | Haversine | **OSRM** / GraphHopper (self-hosted, free road routing) |
| Backend | FastAPI (async) | FastAPI + background worker (Celery/ARQ) for routing jobs |
| Realtime | WebSocket / SSE | Same, or NATS for pub/sub |
| Storage | SQLite | **PostgreSQL + PostGIS** (geo queries, `ST_DWithin`) |
| Frontend | Next.js + MapLibre GL | Next.js + Deck.gl overlay for live routes |
| Donor→shelter flow | Manual claim | Auto-assignment + SMS/WhatsApp dispatch |

**Winning demo:** a live map where a donation posted in one corner of the city is matched to the nearest compatible shelter in <1s, with a visible ETA and expiry countdown.

---

## Track B — CityPulse: Live Civic Health Dashboard

**Framing.** This is **stream processing + online anomaly detection over heterogeneous feeds** — a data-fusion problem, not a dashboard problem. The hard part is schema normalization and *honest* correlation.

**Key challenges**

1. **Schema fusion** — feeds differ in rate (weather ≈ hourly, transit ≈ minutes, 311 ≈ bursty), format (JSON/CSV/XML), and identity (no common `place_id`). Normalize to a canonical event model: `(event_type, timestamp, geohash, severity, source)`.
2. **Rate mismatch** — windowed aggregation (tumbling/sliding windows) is mandatory; never join raw ticks.
3. **Anomaly detection** — streaming z-score/EMA is the floor; the ceiling is model-based.
4. **Correlation honesty** — co-occurrence ≠ causation. Must present links as *"possibly related,"* not confirmed, to avoid civic misinformation. Use cross-correlation on lagged windows, not naive co-incidence.
5. **Degradation** — system must stay correct if a feed stalls (watermarking / staleness markers).

**Tech stack**

| Layer | MVP | Advanced |
|---|---|---|
| Ingestion | Python `asyncio` pollers → Postgres | **Redpanda/Kafka** + **Bytewax** or Flink |
| Time-series store | Postgres | **TimescaleDB** or ClickHouse |
| Anomaly detection | Rolling z-score / EMA + threshold | **Isolation Forest**, STL decomposition (`statsmodels`), or LSTM/Transformer autoencoder |
| Correlation | Lagged Pearson on rolling windows | Granger causality (with stationarity caveats) / cross-correlation matrices |
| Summary | Template NLG grounded in data | **LLM** (RAG over ingested events, strict "cite the feed" grounding) |
| Frontend | Next.js + MapLibre + WebSocket | + Deck.gl heatmaps, a literal "pulse/heartbeat" metaphor |
| Replay | Seed a multi-day synthetic dataset | Kafka topic replay / time-travel querying |

**Winning demo:** three simulated feeds (weather, transit, 311) fused into one map; a storm event triggers a visible, correctly-labelled correlation spike ("complaints ↑ near X *coinciding with* weather alert") with a one-line plain-language summary.

---

## Track C — SentinelAPI: Zero-Trust API Vulnerability Scanner

**Framing.** This is **differential program testing** against a partially-specified system. You're not fuzzing blindly — you're *comparing behaviour across security contexts* and flagging divergences from the spec's stated contract.

**The core trick that makes it tractable:** build the scanner *and* a deliberately-vulnerable sandbox API. The scanner's job is to catch the flaws you planted — so precision is verifiable, and the demo is airtight.

**Vulnerability classes to implement (pick 2):**

1. **BOLA / IDOR** (`/users/{id}`) — cross-account differential test:
   - Create users A and B with distinct tokens.
   - Request `GET /users/{B.id}` using A's token.
   - If the response contains B's resource → **CRITICAL (broken object-level authorization)**.
2. **Excessive data exposure** — diff the response keys against the OpenAPI response schema; flag PII-like fields (`password_hash`, `ssn`, `email`, `token`) returned outside the declared schema.
3. *(stretch)* **Broken authentication / missing rate-limit** — probe unauthenticated access to protected endpoints; check for `RateLimit-*` / `Retry-After` headers.

**Key challenges**

- **Spec ingestion** — robust OpenAPI 3.x parsing (path params, security schemes, response schemas).
- **Test-case generation** — enumerate `(endpoint, auth_context, param_substitution)` triples.
- **Oracle design** — the hard part is deciding "what should NOT have been returned" (the differential diff is the oracle).
- **False-positive control** — every finding must ship a reproducible `curl` + evidence diff, or it gets ignored.
- **Ethics/scope** — sandbox targets only; the scanner must never touch unauthorized systems.

**Tech stack**

| Layer | MVP | Advanced |
|---|---|---|
| Engine | Python `httpx` + `asyncio` (concurrent), `prance`/`openapi-spec-validator` | **Rust** (`tokio` + `reqwest` + `openapiv3` + `serde`) → CLI emitting `findings.json` |
| Wrapper | — | Python (FastAPI) subprocess orchestrator over the Rust binary |
| Spec parsing | `openapi.json` (FastAPI auto-generates) | Same + Swagger 2.0 fallback |
| Oracle | Response key/schema diff + cross-account diff | + LLM-assisted test-case generation (reason about auth logic from spec descriptions) |
| Reporting | `findings.json` → static HTML dashboard | React dashboard, CVSS-style severity, trend analytics |
| Advanced | — | Agentic multi-step auth chains, API dependency graph (cascading exposure) |

**Winning demo:** start the sandbox API → run the scanner → dashboard shows `CRITICAL — BOLA on GET /users/{id}` with a copy-paste `curl` proving user A read user B's record, plus the exact leaked fields.

---

## Comparative Summary

| Criterion | A (Food Rescue) | B (CityPulse) | C (SentinelAPI) |
|---|---|---|---|
| Time-to-working-demo | **Fastest** | Medium | Medium |
| Risk of not finishing | Low | Medium (feeds + fusion) | Medium (oracle design) |
| Technical wow-factor | Medium | High (live fusion) | **Highest** (deep-tech) |
| Dependency on external data | None (synthetic) | Needs 3+ feeds (can simulate) | None (self-built sandbox) |
| Demo reliability on stage | Very high | Medium (live data) | **Highest** (deterministic) |
| "No one did this" novelty | Medium | Medium-High | **Highest** |

## Recommendation

- **Safest finish:** Track A.
- **Best wow + still finishable:** Track C — deterministic demo, zero external dependencies, and the "we built the sandbox *and* the scanner" framing is a strong deep-tech story.
- **Highest risk/reward:** Track B — impressive only if the fusion and correlation look genuinely live and honest.

---

**Stack language of choice:** Python (FastAPI + asyncio) is the fastest path for all three; add Rust only on Track C's engine where high-concurrency scanning and the deep-tech label both justify it.

---

## ✅ Built — SentinelAPI (Track C) implementation

A fully working, deterministic, zero-external-dependency build of Track C.

```
kanishhacka/
├── vuln_api/main.py      # deliberately vulnerable sandbox API (FastAPI)
├── engine/               # Go scanner engine (stdlib-only, single static binary)
│   ├── main.go           #   CLI entry (--base, --out-json, --out-html)
│   ├── spec.go           #   OpenAPI parsing (path params, endpoints)
│   ├── oracle.go         #   differential + schema oracles (pure, testable)
│   ├── scanner.go        #   driver: register A/B, run checks, rank findings
│   └── report.go         #   findings.json + self-contained report.html
├── scanner/scanner.py    # Python scanner — reference/fallback (ENGINE=python)
├── scanner/report.html   # generated severity-ranked dashboard (self-contained)
├── run.sh                # one-command demo: start API → scan → report
└── .venv/                # Python 3.13 + fastapi + uvicorn + httpx
```

**Detected (verified live) — 5 vulnerability classes, 19 findings:**

| Class | Findings | Example proof |
|---|---|---|
| **BOLA / IDOR** (all methods) | 3 CRITICAL | `curl -H 'Authorization: Bearer tok_A' …/users/4` returns bob's record; `PUT` also leaks |
| **Excessive data exposure** (flat + nested) | 10 HIGH | `password_hash`, `ssn`, `token`, `card_last4`, and nested `payment.card`/`payment.cvv`/`profile.ssn` |
| **Broken authentication** (declared security, not enforced) | 4 HIGH | `curl -s …/admin/users` returns everyone's PII with no token |
| **Broken function-level authorization** | 1 HIGH | a regular (non-admin) token reaches `GET /admin/users` |
| **Mass assignment** | 1 HIGH | `POST /users` accepts and stores `{"role":"admin"}` |

**Run it:**
```bash
./run.sh                      # default: builds + runs the Go engine
ENGINE=python ./run.sh        # run the Python scanner instead
```
or manually:
```bash
.venv/bin/python -m uvicorn vuln_api.main:app --port 8000     # terminal 1
cd engine && go build -o sentinel-engine . && ./sentinel-engine --base http://127.0.0.1:8000   # terminal 2
open scanner/report.html
```

**Two engines, one contract.** The Go engine (`engine/`) and the Python scanner
(`scanner/scanner.py`) emit the **same `findings.json` schema** and produce identical
results — verified by a parity check (both report the same 19 findings). The Go engine
is stdlib-only, compiles to a single static binary, and is the demo default; Python
is kept as the readable reference implementation.

**How the oracles work:**
1. Register two principals A and B.
2. *BOLA* — for every HTTP method, call each `{id}` endpoint with **A's token but B's
   identifier**; if B-owned data comes back, it's a cross-account leak.
3. *Exposure* — recursively diff the **actual response paths** vs the paths **declared
   in the OpenAPI schema**; any undeclared sensitive key (incl. nested ones) is flagged.
4. *Broken auth* — if the spec **declares a security requirement** but the endpoint
   returns data with **no token**, flag it.
5. Every finding ships a copy-paste `curl` reproduction + evidence diff → zero false-positive noise.

---

## 🌐 Hosted product (deployable to Railway)

The full usable product: a web app where anyone pastes an API URL and gets a
severity-ranked report.

```
backend/
├── main.py               # FastAPI: SSRF guard + consent + sqlite job queue
│                         #   runs engine/sentinel-engine as a subprocess
├── requirements.txt      # fastapi + uvicorn
└── static/index.html     # single-page scan UI (vanilla JS, dark theme)
Dockerfile                # multi-stage: build Go engine → Python runtime
railway.toml              # Railway deploy config (Dockerfile builder)
.dockerignore
```

**Routes:** `GET /` (UI) · `POST /api/scan` (`{target, consent}`) · `GET /api/scan/{id}` · `GET /api/health`

**Product-safety features (why it's not just a demo):**
- **Consent gate** — a scan requires an explicit "I'm authorized" confirmation.
- **SSRF guard** — rejects private / loopback / link-local / reserved targets so the
  server can't be used to attack internal networks.
- **Async jobs** — scans run in background threads with SQLite-backed history.

Run locally:
```bash
.venv/bin/python -m uvicorn vuln_api.main:app --port 8000          # sandbox target
ALLOW_PRIVATE_SCAN=1 .venv/bin/python -m uvicorn backend.main:app --port 8080  # product
# open http://127.0.0.1:8080 and scan http://127.0.0.1:8000
```

---

## 🎯 Accuracy (verified)

`tests/accuracy.py` runs the engine against the sandbox and compares against ground
truth — including a **secure control endpoint** (`/posts/{id}`) that must produce
**zero** findings.

| Metric | Go engine | Python engine |
|---|---|---|
| True positives | 19/19 | 19/19 |
| False positives | 0 | 0 |
| False negatives | 0 | 0 |
| Secure-endpoint findings | 0 | 0 |
| **Precision / Recall / F1** | **1.0 / 1.0 / 1.0** | **1.0 / 1.0 / 1.0** |

Run it: `python tests/accuracy.py` (and `ENGINE=python python tests/accuracy.py`).

`tests/e2e_backend.py` additionally verifies the hosted backend: health, consent
enforcement, SSRF blocking, and a full scan returning the 19 findings.
