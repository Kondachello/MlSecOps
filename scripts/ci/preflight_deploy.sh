#!/usr/bin/env bash

# Preflight deploy: model approved; Tier HIGH / external — dual HITL approve.

set -euo pipefail



USE_GATEKEEPER="${USE_GATEKEEPER:-false}"

GATEKEEPER_URL="${GATEKEEPER_URL:-http://localhost:8000}"

MODEL_NAME="${MODEL_NAME:?MODEL_NAME required}"

VERSION="${VERSION:?VERSION required}"



if [[ "${USE_GATEKEEPER}" != "true" ]]; then

  echo "preflight_deploy: mock — model ${MODEL_NAME}@${VERSION} assumed approved"

  exit 0

fi



url="${GATEKEEPER_URL}/api/v1/registry"

body="$(curl -fsS "${url}")"

export REGISTRY_JSON="${body}" MODEL_NAME VERSION

python - <<'PY'

import json, os, sys

data = json.loads(os.environ["REGISTRY_JSON"])

name, ver = os.environ["MODEL_NAME"], os.environ["VERSION"]

for m in data.get("models", []):

    if m.get("name") != name or str(m.get("version")) != ver:

        continue

    st = m.get("status")

    need = int(m.get("approvals_required", 1))

    have = int(m.get("approvals_count", 0))

    if st == "pending_hitl":

        print(f"preflight_deploy: blocked — pending_hitl ({have}/{need} approvals)", file=sys.stderr)

        sys.exit(1)

    if st in ("approved", "verified", "prod"):

        if have < need and m.get("tier") == "HIGH":

            print(f"preflight_deploy: blocked — need {need} approvals, have {have}", file=sys.stderr)

            sys.exit(1)

        print(f"preflight_deploy: OK status={st} approvals={have}/{need} sha={m.get('sha256','')[:12]}")

        sys.exit(0)

    print(f"preflight_deploy: status={st}", file=sys.stderr)

    sys.exit(1)

print("preflight_deploy: model not in registry", file=sys.stderr)

sys.exit(1)

PY

