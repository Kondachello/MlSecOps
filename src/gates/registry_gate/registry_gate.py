"""G5 Compliance/Registry Gate — полнота паспорта, lineage, уникальность версии.

Закрывает #20 (Shadow AI), #23 (версионирование/lineage). См. docs/07_SECURITY_GATES.md (G5).
Запускается перед регистрацией модели и в /verify; блок при FAIL.

Запуск: docker run --rm mlsec-gate-registry --card card.json --json
"""
from __future__ import annotations

import argparse
import json
import sys

GATE = "G5"

# Обязательные поля паспорта (см. core/model_card.py)
REQUIRED_CARD = ["name", "version", "owner", "tier", "source", "purpose", "data_source"]
# Обязательные поля lineage
REQUIRED_LINEAGE = ["dataset_version", "git_sha", "sha256"]  # run_id желателен


def gate_check(card: dict) -> list[dict]:
    results: list[dict] = []

    # 1. Полнота паспорта
    missing = [f for f in REQUIRED_CARD if not card.get(f)]
    results.append({"check": "card_completeness",
                    "status": "FAIL" if missing else "PASS",
                    "detail": f"не хватает полей: {missing}" if missing else "паспорт полон",
                    "evidence": {"missing": missing}})

    # 2. Lineage (данные↔код↔модель)
    miss_lin = [f for f in REQUIRED_LINEAGE if not card.get(f)]
    results.append({"check": "lineage",
                    "status": "FAIL" if miss_lin else "PASS",
                    "detail": f"разрыв lineage: {miss_lin}" if miss_lin else "lineage связно",
                    "evidence": {"missing": miss_lin}})

    # 3. Уникальность версии — TODO: проверять в БД (делает оркестратор перед регистрацией).
    results.append({"check": "version_unique", "status": "SKIP",
                    "detail": "TODO: проверка UNIQUE(name,version) в реестре", "evidence": {}})
    return results


def build_report(target: str, results: list[dict]) -> dict:
    failed = [r["check"] for r in results if r["status"] == "FAIL"]
    return {"gate": GATE, "asset": target, "passed": not failed,
            "checks": results, "failed_checks": failed}


def main() -> None:
    ap = argparse.ArgumentParser(description="G5 Compliance/Registry Gate")
    ap.add_argument("--card", required=True, help="путь к JSON паспорта модели")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    with open(args.card, encoding="utf-8") as f:
        card = json.load(f)
    results = gate_check(card)
    report = build_report(card.get("name", "?"), results)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
