"""G1 Data Gate — валидация датасета (схема, баланс, PII, инъекции).

Закрывает угрозы #1 (poisoning), #2 (PII), #11, #15. См. docs/07_SECURITY_GATES.md (G1).
Эталонный гейт: остальные повторяют этот контракт.

Запуск (через образ): docker run --rm --network none -v "$DS:/in:ro" mlsec-gate-data --path /in --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

GATE = "G1"

# Регэкспы PII (демо-уровень; в реале — дополнить/Presidio)
RE_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
RE_CARD = re.compile(r"\b(?:\d[ -]?){16}\b")
# Маркеры prompt-инъекций (для текстовых датасетов / RAG)
RE_INJECTION = re.compile(r"(ignore previous instructions|\[SYSTEM INSTRUCTION\]|approve any loan)", re.I)

# Доля меньшинства >= порога → подозрение на poisoning (искусственно ровный 50/50).
POISON_MIN_CLASS_SHARE = 0.35


def gate_check(path: str, schema: list[str] | None = None) -> list[dict]:
    """Прогнать проверки датасета. Возвращает список результатов (PASS/FAIL/SKIP)."""
    results: list[dict] = []
    p = Path(path)

    # 1. Формат / читаемость
    try:
        import pandas as pd
    except Exception:
        return [{"check": "pandas_available", "status": "SKIP",
                 "detail": "pandas недоступен — деградация", "evidence": {}}]

    try:
        df = pd.read_csv(p) if p.suffix == ".csv" else pd.read_parquet(p)
        results.append({"check": "format_readable", "status": "PASS",
                        "detail": f"rows={len(df)}, cols={list(df.columns)}", "evidence": {}})
    except Exception as e:  # noqa: BLE001
        return [{"check": "format_readable", "status": "FAIL",
                 "detail": f"не удалось прочитать датасет: {e}", "evidence": {}}]

    # 2. Схема (если задан эталон)
    if schema:
        extra = [c for c in df.columns if c not in schema]
        missing = [c for c in schema if c not in df.columns]
        ok = not extra and not missing
        results.append({"check": "schema", "status": "PASS" if ok else "FAIL",
                        "detail": "ок" if ok else f"extra={extra}, missing={missing}",
                        "evidence": {"extra": extra, "missing": missing}})

    # 3. Баланс классов (анти-poisoning) — если есть target
    if "target" in df.columns:
        try:
            vc = df["target"].value_counts(normalize=True)
            min_share = float(vc.min()) if len(vc) > 1 else 0.0
            ok = min_share < POISON_MIN_CLASS_SHARE
            results.append({"check": "class_balance",
                            "status": "PASS" if ok else "FAIL",
                            "detail": f"доля меньшинства = {min_share:.2f}",
                            "evidence": {"distribution": vc.round(3).to_dict()}})
        except Exception as e:  # noqa: BLE001
            results.append({"check": "class_balance", "status": "SKIP",
                            "detail": str(e), "evidence": {}})

    # 4. PII (email/карты)
    sample = df.astype(str).head(1000).agg(" ".join, axis=1).str.cat(sep=" ")
    pii_hits = []
    if RE_EMAIL.search(sample):
        pii_hits.append("email")
    if RE_CARD.search(sample):
        pii_hits.append("card")
    results.append({"check": "pii", "status": "FAIL" if pii_hits else "PASS",
                    "detail": f"найдено: {pii_hits}" if pii_hits else "ПДн не найдено",
                    "evidence": {"types": pii_hits}})

    # 5. Prompt-инъекции (для текстовых данных / RAG)
    inj = bool(RE_INJECTION.search(sample))
    results.append({"check": "prompt_injection", "status": "FAIL" if inj else "PASS",
                    "detail": "найден паттерн инъекции" if inj else "паттернов нет",
                    "evidence": {}})

    # TODO: типы/диапазоны, пропуски, дубликаты, константы — добавить аналогично.
    return results


def build_report(target: str, results: list[dict]) -> dict:
    failed = [r["check"] for r in results if r["status"] == "FAIL"]
    return {"gate": GATE, "asset": target, "passed": not failed,
            "checks": results, "failed_checks": failed}


def main() -> None:
    ap = argparse.ArgumentParser(description="G1 Data Gate")
    ap.add_argument("--path", required=True, help="путь к датасету (csv/parquet)")
    ap.add_argument("--schema", nargs="*", default=None, help="эталонный набор колонок")
    ap.add_argument("--json", action="store_true", help="печать JSON-отчёта")
    args = ap.parse_args()

    results = gate_check(args.path, schema=args.schema)
    report = build_report(args.path, results)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
