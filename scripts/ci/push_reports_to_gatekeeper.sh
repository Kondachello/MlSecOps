#!/usr/bin/env bash
# POST verify/ci summary to Gatekeeper for findings + events (optional).
set -euo pipefail

SUMMARY_FILE="${1:-verify-summary.json}"
WORKFLOW="${2:-verify}"

if [ ! -f "$SUMMARY_FILE" ]; then
  echo "summary file missing: $SUMMARY_FILE"
  exit 0
fi

URL="${GATEKEEPER_URL:-}"
if [ -z "$URL" ]; then
  echo "GATEKEEPER_URL not set — skip ingest"
  exit 0
fi

RUN_ID="${GITHUB_RUN_ID:-}"
BODY=$(python - <<PY
import json, os
from pathlib import Path
summary = json.loads(Path("$SUMMARY_FILE").read_text(encoding="utf-8"))
print(json.dumps({
    "workflow": "$WORKFLOW",
    "github_run_id": os.environ.get("GITHUB_RUN_ID", "") or summary.get("run_metadata", {}).get("github_run_id", ""),
    "summary": summary,
}, ensure_ascii=False))
PY
)

HDR=(-H "Content-Type: application/json")
if [ -n "${CI_INGEST_TOKEN:-}" ]; then
  HDR+=(-H "X-CI-Ingest-Token: ${CI_INGEST_TOKEN}")
fi

curl -fsS -X POST "${URL%/}/api/v1/ci/ingest-reports" "${HDR[@]}" -d "$BODY" \
  && echo "ingested $WORKFLOW → Gatekeeper" \
  || echo "ingest failed (non-fatal for CI)"
