"""G1 Data Gate — валидация датасета (схема, типы, баланс, качество, PII, инъекции).

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

RE_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
RE_CARD = re.compile(r"\b(?:\d[ -]?){15,16}\b")
RE_PASSPORT_RU = re.compile(r"\b\d{4}[\s-]?\d{6}\b")
RE_INJECTION = re.compile(
    r"(ignore previous instructions|\[SYSTEM INSTRUCTION\]|approve any loan"
    r"|<\|im_start\||</s>|<\|endoftext\||act as (root|admin)|jailbreak)",
    re.I,
)

MINORITY_POISON_THRESHOLD = 0.30  # класс меньшинства > 30% → подозрение на poisoning
# Примечание: типичный fraud-датасет имеет 1-5% minority.
# Атака: подмешать 500 fraud-строк → 50/50 → minority=50% > 30% → FAIL.
RANGE_OUTLIER_PCT = 0.01      # > 1% значений вне допустимого диапазона → FAIL
MISSING_WARN = 0.05           # >5% missing → medium
MISSING_FAIL = 0.20           # >20% missing → FAIL high
DUPLICATE_THRESHOLD = 0.01    # >1% дублей → FAIL medium


def gate_check(path: str, schema: list[str] | None = None) -> list[dict]:
    """Прогнать все проверки датасета. Возвращает список результатов PASS/FAIL/SKIP."""
    results: list[dict] = []
    p = Path(path)

    try:
        import pandas as pd
    except Exception:
        return [{"check": "pandas_available", "status": "SKIP", "severity": "low",
                 "detail": "pandas недоступен — деградация", "evidence": {}}]

    # 1. Формат / читаемость
    try:
        df = pd.read_csv(p) if p.suffix == ".csv" else pd.read_parquet(p)
        results.append({"check": "format_readable", "status": "PASS", "severity": "low",
                        "detail": f"rows={len(df)}, cols={list(df.columns)}", "evidence": {}})
    except Exception as e:  # noqa: BLE001
        return [{"check": "format_readable", "status": "FAIL", "severity": "high",
                 "detail": f"не удалось прочитать датасет: {e}", "evidence": {}}]

    # 2. Схема (если передан эталон)
    if schema:
        extra = [c for c in df.columns if c not in schema]
        missing_cols = [c for c in schema if c not in df.columns]
        ok = not extra and not missing_cols
        results.append({"check": "schema", "status": "PASS" if ok else "FAIL",
                        "severity": "medium",
                        "detail": "ок" if ok else f"extra={extra}, missing={missing_cols}",
                        "evidence": {"extra": extra, "missing": missing_cols}})

    # 3. Типы и диапазоны
    type_issues: list[str] = []
    range_issues: list[str] = []
    for col in df.columns:
        if df[col].dtype == object:
            try:
                pd.to_numeric(df[col], errors="raise")
                type_issues.append(f"{col}: числовые значения хранятся как строки")
            except (ValueError, TypeError):
                pass
        nums = pd.to_numeric(df[col], errors="coerce")
        if col.lower() in ("age", "возраст"):
            bad = int(((nums < 0) | (nums > 150)).sum())
            if bad / max(len(nums), 1) > RANGE_OUTLIER_PCT:
                range_issues.append(f"{col}: {bad} значений вне [0,150] ({bad/len(nums):.1%})")
        if col.lower() in ("amount", "сумма", "price", "цена"):
            bad = int((nums < 0).sum())
            if bad / max(len(nums), 1) > RANGE_OUTLIER_PCT:
                range_issues.append(f"{col}: {bad} отрицательных значений ({bad/len(nums):.1%})")
    tr_issues = type_issues + range_issues
    results.append({"check": "types_ranges",
                    "status": "FAIL" if tr_issues else "PASS",
                    "severity": "medium",
                    "detail": "; ".join(tr_issues) if tr_issues else "типы/диапазоны в норме",
                    "evidence": {"type_issues": type_issues, "range_issues": range_issues}})

    # 4. Баланс классов (анти-poisoning) — если есть target
    # Логика: для задач с естественным дисбалансом (fraud ~2%) атака = добавить много fraud-строк
    # → класс меньшинства вырастает выше порога → FAIL.
    if "target" in df.columns:
        try:
            vc = df["target"].value_counts(normalize=True)
            minority_rate = float(vc.min()) if len(vc) > 1 else 0.0
            majority_rate = float(vc.max()) if len(vc) > 1 else 1.0
            # FAIL если класс меньшинства > порога (признак искусственного "выравнивания" = poisoning)
            ok = minority_rate <= MINORITY_POISON_THRESHOLD
            results.append({"check": "class_balance",
                            "status": "PASS" if ok else "FAIL",
                            "severity": "high",
                            "detail": (f"класс меньшинства = {minority_rate:.1%} "
                                       f"(порог {MINORITY_POISON_THRESHOLD:.0%}) — "
                                       + ("OK" if ok else "АНОМАЛИЯ (вероятный poisoning)")),
                            "evidence": {"distribution": {str(k): round(v, 4) for k, v in vc.items()},
                                         "minority_rate": round(minority_rate, 4),
                                         "majority_rate": round(majority_rate, 4),
                                         "threshold": MINORITY_POISON_THRESHOLD}})
        except Exception as e:  # noqa: BLE001
            results.append({"check": "class_balance", "status": "SKIP", "severity": "high",
                            "detail": str(e), "evidence": {}})

    # 5. Пропущенные значения
    missing_pct = (df.isnull().sum() / max(len(df), 1)).to_dict()
    high_miss = {c: round(v, 4) for c, v in missing_pct.items() if v > MISSING_FAIL}
    med_miss = {c: round(v, 4) for c, v in missing_pct.items()
                if MISSING_WARN < v <= MISSING_FAIL}
    if high_miss:
        status_m, sev_m = "FAIL", "high"
        detail_m = f"критично пропущено (>{MISSING_FAIL:.0%}): {high_miss}"
    elif med_miss:
        status_m, sev_m = "FAIL", "medium"
        detail_m = f"много пропущено (>{MISSING_WARN:.0%}): {med_miss}"
    else:
        status_m, sev_m, detail_m = "PASS", "low", "пропуски в норме"
    results.append({"check": "missing_values", "status": status_m, "severity": sev_m,
                    "detail": detail_m,
                    "evidence": {"high_missing": high_miss, "medium_missing": med_miss}})

    # 6. Дубликаты
    n_dup = int(df.duplicated().sum())
    dup_pct = n_dup / max(len(df), 1)
    results.append({"check": "duplicates",
                    "status": "FAIL" if dup_pct > DUPLICATE_THRESHOLD else "PASS",
                    "severity": "medium",
                    "detail": (f"дублей: {n_dup} ({dup_pct:.1%}) — выше порога {DUPLICATE_THRESHOLD:.0%}"
                               if dup_pct > DUPLICATE_THRESHOLD else f"дублей: {n_dup} (норма)"),
                    "evidence": {"n_duplicates": n_dup, "duplicate_pct": round(dup_pct, 4)}})

    # 7. Константные колонки (единственное уникальное значение — признак ошибки данных)
    const_cols = [c for c in df.columns if df[c].nunique(dropna=True) <= 1 and len(df) > 1]
    results.append({"check": "constant_columns",
                    "status": "FAIL" if const_cols else "PASS",
                    "severity": "medium",
                    "detail": (f"константные колонки: {const_cols}" if const_cols
                               else "нет константных колонок"),
                    "evidence": {"columns": const_cols}})

    # 8. PII (email, банковские карты, российские паспорта)
    sample = df.astype(str).head(1000).agg(" ".join, axis=1).str.cat(sep=" ")
    pii_hits: list[str] = []
    pii_samples: dict[str, list[str]] = {}

    emails = RE_EMAIL.findall(sample)
    if emails:
        pii_hits.append("email")
        pii_samples["email"] = emails[:3]

    cards = RE_CARD.findall(sample)
    if cards:
        pii_hits.append("card")
        pii_samples["card"] = [c[:4] + "****" + c[-4:] for c in cards[:3]]

    passports = RE_PASSPORT_RU.findall(sample)
    if passports:
        pii_hits.append("passport_ru")
        pii_samples["passport_ru"] = [p[:2] + "**" + p[-2:] for p in passports[:3]]

    results.append({"check": "pii",
                    "status": "FAIL" if pii_hits else "PASS",
                    "severity": "high",
                    "detail": f"найдено ПДн: {pii_hits}" if pii_hits else "ПДн не найдено",
                    "evidence": {"types": pii_hits, "samples": pii_samples}})

    # 9. Prompt-инъекции (для текстовых датасетов / RAG)
    inj_match = RE_INJECTION.search(sample)
    results.append({"check": "prompt_injection",
                    "status": "FAIL" if inj_match else "PASS",
                    "severity": "critical",
                    "detail": f"найден паттерн: '{inj_match.group()[:60]}'" if inj_match else "паттернов нет",
                    "evidence": {"pattern": inj_match.group() if inj_match else None}})

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
