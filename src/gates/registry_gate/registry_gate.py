"""G5 Compliance/Registry Gate — полнота паспорта, lineage, уникальность версии.

Закрывает #20 (Shadow AI), #23 (версионирование/lineage). См. docs/07_SECURITY_GATES.md (G5).
Запускается перед регистрацией модели и в /verify; блок при FAIL.
Гейт сам в БД не пишет (уникальность — проверяет оркестратор перед регистрацией).

Запуск: docker run --rm mlsec-gate-registry --card card.json --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

GATE = "G5"

# Обязательные поля паспорта (см. core/model_card.py и docs/09_DATA_MODEL.md)
REQUIRED_CARD: list[str] = [
    "name", "version", "owner", "tier", "source", "purpose", "data_source",
]
# Обязательные поля lineage: данные↔код↔модель
REQUIRED_LINEAGE: list[str] = [
    "dataset_version",   # версия датасета, на котором обучена модель
    "git_sha",           # SHA коммита кода
    "sha256",            # SHA-256 артефакта модели
]
# Желательные поля lineage (WARN, не FAIL)
RECOMMENDED_LINEAGE: list[str] = [
    "run_id",            # MLflow run_id
    "dataset_sha256",    # SHA-256 датасета
]

# Допустимые значения Tier
VALID_TIERS: set[str] = {"LOW", "MED", "HIGH"}  # канон: совпадает с init.sql CHECK и core/model_card

# Правила авто-Tier (fail-safe HIGH): если эти признаки присутствуют → Tier должен быть HIGH
HIGH_TIER_RULES: dict[str, str] = {
    "source": "external",         # внешние данные → HIGH
    "data_source": "internet",    # данные из интернета → HIGH
    "trained_in_ci": False,       # не обучена в CI → HIGH
}


def _check_auto_tier(card: dict) -> list[str]:
    """Вернуть список нарушений: Tier занижен относительно авто-правил."""
    tier = (card.get("tier") or "").upper()
    violations = []
    if card.get("source", "").lower() == "external" and tier != "HIGH":
        violations.append("источник=external → Tier должен быть HIGH")
    if card.get("data_source", "").lower() == "internet" and tier != "HIGH":
        violations.append("data_source=internet → Tier должен быть HIGH")
    if card.get("trained_in_ci") is False and tier != "HIGH":
        violations.append("trained_in_ci=false → Tier должен быть HIGH (fail-safe)")
    return violations


def gate_check(card: dict) -> list[dict]:
    results: list[dict] = []

    # 1. Полнота паспорта
    missing_fields = [f for f in REQUIRED_CARD if not card.get(f)]
    results.append({"check": "card_completeness",
                    "status": "FAIL" if missing_fields else "PASS",
                    "severity": "high",
                    "detail": (f"не хватает обязательных полей: {missing_fields}"
                               if missing_fields else "паспорт полон"),
                    "evidence": {"missing": missing_fields,
                                 "required": REQUIRED_CARD}})

    # 2. Tier валидность и авто-правила
    tier_raw = card.get("tier")
    tier = (tier_raw or "").upper()
    tier_issues: list[str] = []
    if not tier:
        tier_issues.append("поле 'tier' отсутствует или пустое — применён fail-safe HIGH")
    elif tier not in VALID_TIERS:
        tier_issues.append(f"недопустимое значение tier='{tier_raw}' (допустимо: {sorted(VALID_TIERS)})")
    tier_issues.extend(_check_auto_tier(card))
    results.append({"check": "tier_validity",
                    "status": "FAIL" if tier_issues else "PASS",
                    "severity": "high",
                    "detail": "; ".join(tier_issues) if tier_issues else f"Tier={tier} — ok",
                    "evidence": {"tier": tier_raw, "violations": tier_issues}})

    # 3. Lineage (данные↔код↔модель)
    miss_lin = [f for f in REQUIRED_LINEAGE if not card.get(f)]
    recommend_missing = [f for f in RECOMMENDED_LINEAGE if not card.get(f)]
    results.append({"check": "lineage",
                    "status": "FAIL" if miss_lin else "PASS",
                    "severity": "high",
                    "detail": (f"разрыв lineage — не хватает: {miss_lin}"
                               if miss_lin else "lineage связно"),
                    "evidence": {"missing_required": miss_lin,
                                 "missing_recommended": recommend_missing,
                                 "required": REQUIRED_LINEAGE}})

    # 4. SHA-256 артефакта — должен быть непустой строкой 64 символа
    sha = card.get("sha256", "")
    sha_ok = isinstance(sha, str) and len(sha) == 64 and all(c in "0123456789abcdef" for c in sha.lower())
    if sha:  # поле присутствует — валидируем формат
        results.append({"check": "sha256_format",
                        "status": "PASS" if sha_ok else "FAIL",
                        "severity": "medium",
                        "detail": ("SHA-256 валиден" if sha_ok
                                   else f"SHA-256 невалиден: длина={len(sha)}, ожидалось 64 hex-символа"),
                        "evidence": {"sha256": sha[:8] + "..." if sha else ""}})

    # 5. Уникальность версии — проверяет ОРКЕСТРАТОР (не гейт, без БД)
    results.append({"check": "version_unique", "status": "SKIP", "severity": "medium",
                    "detail": "проверку UNIQUE(name,version) выполняет оркестратор перед регистрацией",
                    "evidence": {"name": card.get("name"), "version": card.get("version")}})

    return results


def build_report(target: str, results: list[dict]) -> dict:
    failed = [r["check"] for r in results if r["status"] == "FAIL"]
    sev_summary: dict[str, list[str]] = {}
    for r in results:
        if r["status"] == "FAIL":
            sev = r.get("severity", "medium")
            sev_summary.setdefault(sev, []).append(r["check"])
    return {"gate": GATE, "asset": target, "passed": not failed,
            "checks": results, "failed_checks": failed, "severity_summary": sev_summary}


def main() -> None:
    ap = argparse.ArgumentParser(description="G5 Compliance/Registry Gate")
    ap.add_argument("--card", required=True, help="путь к JSON-паспорту модели")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="SKIP трактовать как FAIL для критичных активов")
    args = ap.parse_args()

    card_path = Path(args.card)
    if not card_path.exists():
        print(json.dumps({"gate": GATE, "error": f"файл не найден: {args.card}",
                          "passed": False}, ensure_ascii=False))
        sys.exit(1)

    with card_path.open(encoding="utf-8") as f:
        card = json.load(f)

    results = gate_check(card)
    if args.fail_closed:
        for r in results:
            if r.get("status") == "SKIP":
                r["status"] = "FAIL"
                r["detail"] = "fail-closed: " + r.get("detail", "")
    report = build_report(card.get("name", args.card), results)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
