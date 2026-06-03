#!/usr/bin/env bash
# Сохранить JSON гейта в findings (когда Postgres доступен). Пример:
#   python src/gates/data_gate/data_gate.py --path data/train_m1_poisoned.csv --json \
#     | python -c "import sys,json; from core.db import ingest_gate_report; ..."
set -euo pipefail
GATE="${1:?gate id G1-G5}"
ASSET_TYPE="${2:?dataset|code|model|dependency}"
REPORT="${3:-/dev/stdin}"
python - "$GATE" "$ASSET_TYPE" "$REPORT" <<'PY'
import json, sys
from core.db import ingest_gate_report, log_event, ping
gate, asset_type, path = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read() if path != "/dev/stdin" else sys.stdin.read()
report = json.loads(text)
if not ping():
    print("ingest_gate_to_db: SKIP — no Postgres")
    sys.exit(0)
ids = ingest_gate_report(report, asset_type)
log_event("ci", "MLSecOps", "gate_ingest", asset=report.get("asset"), result="blocked" if ids else "ok",
          details={"gate": gate, "finding_ids": ids})
print(f"ingest_gate_to_db: findings={ids}")
PY
