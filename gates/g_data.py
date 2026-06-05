"""gates/g_data.py — DATA gate: PII / poison-columns / nulls / схема в CSV-датасете.

Берёт первый dataset-вход рана (mlflow.log_input) если он скачан как CSV в work_dir,
иначе SKIP. Для real-life: датасет приходит как артефакт `dataset.csv` или прокидывается
runner-ом из ctx.dataset_path.

Логика — на основе fortress/data_gate.py из 2-го разраба, переписана под наш контракт:
не пишет ничего в БД (это делает оркестратор), возвращает структурированный результат.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

from gates.base import GateContext, GateResult, log_line, register_gate

# Маркеры «отравленных» колонок (низкобарьерный детектор, как у 2-го разраба).
POISON_MARKERS = ("poison", "backdoor", "malicious", "evil", "trigger")
# Номер банковской карты (4×4 цифры).
PII_CARD = re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b")
# Email.
PII_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# СНИЛС РФ: ddd-ddd-ddd dd.
PII_SNILS = re.compile(r"\b\d{3}-\d{3}-\d{3}[ -]\d{2}\b")

MAX_NULL_RATIO = 0.5
MAX_ROWS_SCAN = 50_000   # safeguard на большие датасеты


def _find_dataset(ctx: GateContext) -> Path | None:
    """Найти CSV для проверки: явный ctx.dataset_path → артефакты work_dir."""
    if ctx.dataset_path and ctx.dataset_path.exists():
        return ctx.dataset_path
    if not ctx.work_dir or not ctx.work_dir.exists():
        return None
    # Ищем самый «датасет-подобный» CSV в скачанных артефактах.
    candidates = list(ctx.work_dir.rglob("*.csv"))
    if not candidates:
        return None
    # приоритет: имена data*/train*/dataset* первыми
    candidates.sort(key=lambda p: (
        0 if p.name.lower().startswith(("data", "train", "dataset")) else 1, p.name))
    return candidates[0]


@register_gate("DATA", name="Data", order=10,
               description="PII (карты/email/СНИЛС), poison-колонки, доля null, схема",
               severity="high", threats=["#1", "#2", "#11", "#15"])
def run(ctx: GateContext) -> GateResult:
    gid, gname = "DATA", "Data"
    logs = [log_line(gid, gname, "start: ищу CSV-датасет для проверки")]

    path = _find_dataset(ctx)
    if path is None:
        logs.append(log_line(gid, gname, "SKIP: датасет не найден (ни ctx.dataset_path, ни *.csv в артефактах)"))
        return GateResult(id=gid, name=gname, status="SKIP",
                          detail="Датасет рана не доступен — гейт пропущен.",
                          logs=logs, evidence={"reason": "no_dataset"})

    logs.append(log_line(gid, gname, f"открыт {path.name}"))
    try:
        with path.open(newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            cols = reader.fieldnames or []
            rows = []
            for i, row in enumerate(reader):
                if i >= MAX_ROWS_SCAN:
                    logs.append(log_line(gid, gname,
                                f"limit: проверены первые {MAX_ROWS_SCAN} строк"))
                    break
                rows.append(row)
    except Exception as e:  # noqa: BLE001
        logs.append(log_line(gid, gname, f"FAIL: не смог прочитать CSV: {e}"))
        return GateResult(id=gid, name=gname, status="FAIL", severity="high",
                          detail=f"CSV нечитаем: {e}",
                          logs=logs, evidence={"error": str(e)})

    logs.append(log_line(gid, gname, f"строк: {len(rows)}, колонок: {len(cols)}"))

    # 1) poison columns
    for col in cols:
        cl = col.lower()
        if any(m in cl for m in POISON_MARKERS):
            logs.append(log_line(gid, gname, f"FAIL: poison-колонка {col!r}"))
            return GateResult(id=gid, name=gname, status="FAIL", severity="critical",
                              detail=f"Подозрительная колонка: {col}",
                              logs=logs, evidence={"poison_column": col, "columns": cols})

    if not rows:
        logs.append(log_line(gid, gname, "FAIL: пустой датасет"))
        return GateResult(id=gid, name=gname, status="FAIL",
                          detail="Датасет пустой.", logs=logs,
                          evidence={"rows": 0, "columns": cols})

    # 2) PII scan + null count (один проход)
    nulls = 0
    total_cells = 0
    pii_hits: list[dict] = []
    for ridx, row in enumerate(rows):
        for col, v in row.items():
            total_cells += 1
            sv = "" if v is None else str(v).strip()
            if sv == "":
                nulls += 1
                continue
            for kind, pat in (("card", PII_CARD), ("email", PII_EMAIL), ("snils", PII_SNILS)):
                if pat.search(sv):
                    pii_hits.append({"row": ridx, "col": col, "kind": kind,
                                     "sample": sv[:64]})
                    if len(pii_hits) >= 5:
                        break
            if len(pii_hits) >= 5:
                break
        if len(pii_hits) >= 5:
            break

    if pii_hits:
        logs.append(log_line(gid, gname, f"FAIL: PII-сработки ({len(pii_hits)})"))
        for hit in pii_hits[:3]:
            logs.append(log_line(gid, gname, f"  row={hit['row']} col={hit['col']} kind={hit['kind']}"))
        return GateResult(id=gid, name=gname, status="FAIL", severity="high",
                          detail=f"Найдены PII-паттерны ({len(pii_hits)} cэмплов).",
                          logs=logs, evidence={"pii_samples": pii_hits, "rows": len(rows)})

    # 3) null ratio
    null_ratio = nulls / total_cells if total_cells else 0.0
    logs.append(log_line(gid, gname, f"null_ratio={null_ratio:.3f} (порог {MAX_NULL_RATIO})"))
    if null_ratio > MAX_NULL_RATIO:
        logs.append(log_line(gid, gname, "FAIL: слишком много пустых ячеек"))
        return GateResult(id=gid, name=gname, status="FAIL",
                          detail=f"Доля null {null_ratio:.1%} > {MAX_NULL_RATIO:.0%}",
                          logs=logs, evidence={"null_ratio": null_ratio, "nulls": nulls,
                                               "total_cells": total_cells})

    logs.append(log_line(gid, gname, f"PASS: rows={len(rows)} cols={len(cols)} pii=0"))
    return GateResult(id=gid, name=gname, status="PASS",
                      detail=f"OK: {len(rows)} строк, {len(cols)} колонок, PII не найдены.",
                      logs=logs, evidence={"rows": len(rows), "columns": cols,
                                           "null_ratio": null_ratio, "dataset_file": path.name})
