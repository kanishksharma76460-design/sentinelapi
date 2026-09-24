#!/usr/bin/env bash
# SentinelAPI — one-command demo.
#   ENGINE=go      (default) build + run the Go engine
#   ENGINE=python  run the Python scanner (fallback/reference)
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8000}"
BASE="http://127.0.0.1:${PORT}"
ENGINE="${ENGINE:-go}"

echo "[*] starting vulnerable API on ${BASE}"
.venv/bin/python -m uvicorn vuln_api.main:app --host 127.0.0.1 --port "${PORT}" &
API_PID=$!
trap 'kill "$API_PID" 2>/dev/null || true' EXIT

# wait for the API to come up
for _ in $(seq 1 40); do
  curl -sf "${BASE}/health" >/dev/null 2>&1 && break
  sleep 0.25
done

if [ "$ENGINE" = "go" ]; then
  echo "[*] building + running Go engine"
  (cd engine && go build -o sentinel-engine .)
  engine/sentinel-engine --base "${BASE}" \
    --out-json scanner/findings.json --out-html scanner/report.html
else
  echo "[*] running Python scanner (fallback)"
  .venv/bin/python scanner/scanner.py --base "${BASE}" \
    --out-json scanner/findings.json --out-html scanner/report.html
fi

echo ""
echo "✅ Done. Open the report in your browser:  scanner/report.html"
echo "   API is still running on ${BASE} (Ctrl+C to stop)."
wait "$API_PID"
