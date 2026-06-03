"""Smoke-тест БД: hash-chain events + ingest_gate_report."""
from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def main() -> None:
    if os.getenv("CI_SKIP_DB_SMOKE", "").lower() in {"1", "true", "yes"}:
        print("smoke_db: SKIP (CI_SKIP_DB_SMOKE)")
        return

    from core.db import ingest_gate_report, log_event, ping, verify_chain

    if not ping():
        print(
            "smoke_db: SKIP — Postgres недоступен "
            f"({_pg_hint()}). Подними: docker compose -f infra/docker-compose.yml up -d postgres"
        )
        sys.exit(0)

    log_event("smoke", "MLSecOps", "smoke_start", result="ok")
    log_event("smoke", "MLSecOps", "smoke_step", asset="test@1", result="ok")
    log_event("smoke", "MLSecOps", "smoke_end", result="ok")

    chain = verify_chain()
    if not chain["ok"]:
        print(f"smoke_db: FAIL verify_chain {chain}", file=sys.stderr)
        sys.exit(1)

    report = {
        "gate": "G1",
        "asset": "data/test.csv",
        "passed": False,
        "checks": [
            {
                "check": "pii",
                "status": "FAIL",
                "severity": "high",
                "detail": "demo",
                "evidence": {"types": ["email"]},
            }
        ],
        "failed_checks": ["pii"],
    }
    ids = ingest_gate_report(report, asset_type="dataset")
    if not ids:
        print("smoke_db: FAIL ingest_gate_report", file=sys.stderr)
        sys.exit(1)

    print(f"smoke_db: OK chain={chain} findings={ids}")


def _pg_hint() -> str:
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    return f"{host}:{port}"


if __name__ == "__main__":
    main()
