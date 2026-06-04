#!/usr/bin/env bash
# Preflight: dataset must be available for train/verify (mock or Gatekeeper API).
set -euo pipefail

USE_GATEKEEPER="${USE_GATEKEEPER:-true}"
GATEKEEPER_URL="${GATEKEEPER_URL:-http://localhost:8000}"
DATASET_NAME="${DATASET_NAME:-}"
DATASET_VERSION="${DATASET_VERSION:-}"
SKIP_G1="${SKIP_G1:-false}"

if [[ "${SKIP_G1}" == "true" ]]; then
  echo "preflight: dataset fast-path (already verified) — OK"
  exit 0
fi

if [[ "${USE_GATEKEEPER}" != "true" ]]; then
  echo "preflight: mock mode — dataset assumed available (set USE_GATEKEEPER=true for API)"
  exit 0
fi

if [[ -z "${DATASET_NAME}" || -z "${DATASET_VERSION}" ]]; then
  echo "preflight: DATASET_NAME and DATASET_VERSION required with USE_GATEKEEPER=true" >&2
  exit 1
fi

url="${GATEKEEPER_URL}/api/v1/registry"
echo "preflight: GET ${url}"
if ! body="$(curl -fsS --connect-timeout 10 "${url}" 2>/dev/null)"; then
  echo "preflight: Gatekeeper unreachable at ${url} — fail (check GATEKEEPER_URL / tunnel)" >&2
  exit 1
fi
export REGISTRY_JSON="${body}"
python - <<'PY'
import json, os, sys
data = json.loads(os.environ["REGISTRY_JSON"])
name, ver = os.environ["DATASET_NAME"], os.environ["DATASET_VERSION"]
for ds in data.get("datasets", []):
    if ds.get("name") == name and ds.get("version") == ver:
        if ds.get("status") == "available":
            print(f"preflight: {name}@{ver} available")
            sys.exit(0)
        print(f"preflight: {name}@{ver} status={ds.get('status')}", file=sys.stderr)
        sys.exit(1)
print(f"preflight: dataset {name}@{ver} not in registry", file=sys.stderr)
sys.exit(1)
PY
