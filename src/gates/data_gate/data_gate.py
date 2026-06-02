"""
data_gate.py — Data Gate (G1): проверка датасета ДО обучения.

Закрывает угрозы:
  #1 Data Poisoning  — резкий дисбаланс классов (вчера фрод 2%, стал 50%);
  #2 PII / ПДн       — email / номера карт в данных (152-ФЗ);
  + контроль схемы   — лишние/недостающие колонки (внедрение левых фичей).

Запуск:
    python src/gates/data_gate.py data/datasets/train_clean.csv
    python src/gates/data_gate.py data/datasets/train_poisoned.csv   # → FAIL

Опции:
    --target COL              имя колонки таргета (default: target)
    --expected-cols a,b,c     эталонная схема (через запятую)
    --max-class-share 0.9     порог доли мажорного класса (анти-poison)
    --json                    напечатать JSON-отчёт (для пайплайна/UI)

Выходной код: 0 = PASS, 1 = FAIL.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import pandas as pd

# ── Паттерны PII (#2) ────────────────────────────────────────────────────────
PII_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "card16": re.compile(r"\b(?:\d[ -]?){16}\b"),
    "ru_passport": re.compile(r"\b\d{4}\s?\d{6}\b"),
}


def _record(results: list[dict], check: str, passed: bool, detail: str = "") -> None:
    results.append({"check": check, "status": "PASS" if passed else "FAIL", "detail": detail})


def gate_check(
    path: Path,
    *,
    target: str = "target",
    expected_cols: list[str] | None = None,
    max_class_share: float = 0.9,
) -> list[dict]:
    """Прогнать все проверки G1. Возвращает список результатов."""
    results: list[dict] = []

    # 0. Файл читается как CSV
    try:
        df = pd.read_csv(path)
    except Exception as e:  # noqa: BLE001
        _record(results, "readable_csv", False, f"Не удалось прочитать CSV: {e}")
        return results
    _record(results, "readable_csv", True, f"{len(df)} строк, {len(df.columns)} колонок")

    # 1. Контроль схемы (защита от внедрения левых фичей)
    if expected_cols:
        actual = set(df.columns)
        expected = set(expected_cols)
        extra = sorted(actual - expected)
        missing = sorted(expected - actual)
        ok = not extra and not missing
        detail = "Схема совпадает с эталоном"
        if not ok:
            detail = f"Лишние: {extra or '—'}; отсутствуют: {missing or '—'}"
        _record(results, "schema_match", ok, detail)

    # 2. Баланс классов (#1 Data Poisoning)
    if target in df.columns:
        shares = df[target].value_counts(normalize=True)
        top_share = float(shares.iloc[0])
        ok = top_share <= max_class_share
        dist = ", ".join(f"{k}={v:.2%}" for k, v in shares.items())
        detail = f"Распределение: {dist} (порог мажорного ≤ {max_class_share:.0%})"
        _record(results, "class_balance", ok, detail)
    else:
        _record(results, "class_balance", False, f"Нет колонки таргета '{target}'")

    # 3. PII / ПДн (#2) — по именам колонок и содержимому
    pii_hits: dict[str, list[str]] = {}
    for col in df.columns:
        if any(p.search(str(col)) for p in PII_PATTERNS.values()) or \
           re.search(r"email|mail|passport|card|phone|снилс|inn", str(col), re.I):
            pii_hits.setdefault("по_имени_колонки", []).append(str(col))
        sample = df[col].astype(str).head(200)
        for kind, pat in PII_PATTERNS.items():
            if sample.apply(lambda v: bool(pat.search(v))).any():
                pii_hits.setdefault(kind, []).append(str(col))
    ok = not pii_hits
    detail = "ПДн не обнаружено" if ok else f"Найдено: {json.dumps(pii_hits, ensure_ascii=False)}"
    _record(results, "no_pii", ok, detail)

    return results


def build_report(path: Path, results: list[dict]) -> dict:
    """JSON-отчёт для реестра/UI (причина блока, False Positives)."""
    passed = all(r["status"] == "PASS" for r in results)
    return {
        "gate": "G1",
        "asset": path.name,
        "passed": passed,
        "checks": results,
        "failed_checks": [r["check"] for r in results if r["status"] == "FAIL"],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Data Gate (G1)")
    ap.add_argument("path", type=Path)
    ap.add_argument("--target", default="target")
    ap.add_argument("--expected-cols", default=None,
                    help="эталонные колонки через запятую, напр. amount,age,target")
    ap.add_argument("--max-class-share", type=float, default=0.9)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    expected = [c.strip() for c in args.expected_cols.split(",")] if args.expected_cols else None

    if not args.path.exists():
        print(f"❌ Файл не найден: {args.path}")
        sys.exit(1)

    print(f"\n🔍 Data Gate (G1): проверка {args.path.name}\n")
    results = gate_check(args.path, target=args.target,
                         expected_cols=expected, max_class_share=args.max_class_share)
    report = build_report(args.path, results)

    for r in results:
        icon = "✅" if r["status"] == "PASS" else "❌"
        detail = f"  → {r['detail']}" if r["detail"] else ""
        print(f"  {icon} [{r['status']}] {r['check']}{detail}")

    if args.json:
        print("\n--- JSON ---")
        print(json.dumps(report, ensure_ascii=False, indent=2))

    print()
    if report["passed"]:
        print("✅ GATE PASSED — датасет допущен\n")
        sys.exit(0)
    else:
        print("❌ GATE FAILED — датасет отправлен в карантин\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
