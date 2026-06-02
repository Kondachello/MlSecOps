"""Онбординг датасета: источник → G1 → бакет → реестр → события.

Оркестратор: ВЫЗЫВАЕТ G1 (data_gate) и САМ пишет findings/events (гейт в БД не пишет).
Источники: local / s3:// / http(s):// (в т.ч. HF/Kaggle по ссылке).
Полная проверка для всех источников; fast-path только при бит-в-бит совпадении хэша.
Запрет обновления датасета в статусе prod_locked.

См. docs/05_CANONICAL_FLOW.md §5.3, docs/17_DATASET_LIFECYCLE.md. Скелет.
"""
from __future__ import annotations

import argparse
import hashlib
import sys

# Маппинг проверка → severity (держим в оркестраторе, не в гейте)
SEVERITY = {
    "schema": "high", "class_balance": "high", "pii": "critical",
    "prompt_injection": "high", "format_readable": "high",
}


def _fetch_source(src: str) -> bytes:
    """Скачать датасет из local / s3:// / http(s)://. TODO."""
    raise NotImplementedError("TODO: загрузка по схеме источника")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ingest(src: str, *, name: str, version: str, source_type: str, actor: str,
           role: str = "DS") -> dict:
    """Полный онбординг одного датасета.

    Шаги (TODO реализовать через core.*):
      1. fetch → bytes; sha = sha256(bytes)
      2. fast-path: если sha есть в verified_datasets → status=available, log_event, return
      3. сохранить во временный файл → запустить образ mlsec-gate-data (--json) → распарсить отчёт
      4. PASS → bucket=datasets, status=available, register_dataset, verified_datasets += sha
         FAIL → bucket=quarantine, status=quarantine, add_finding(per FAIL), log_event(gate_blocked)
      5. log_event(dataset_uploaded / gate_passed / gate_blocked) — actor = серверная identity
    """
    raise NotImplementedError("TODO: реализовать по шагам выше через core.db/core.storage")


def main() -> None:
    ap = argparse.ArgumentParser(description="Ingest dataset (G1)")
    ap.add_argument("source", help="local path | s3://... | http(s)://...")
    ap.add_argument("--name", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--source-type", default="local",
                    choices=["local", "internet", "corp_storage", "verified_id"])
    ap.add_argument("--actor", required=True, help="серверная identity (из auth)")
    args = ap.parse_args()
    report = ingest(args.source, name=args.name, version=args.version,
                    source_type=args.source_type, actor=args.actor)
    sys.exit(0 if report.get("passed") else 1)


if __name__ == "__main__":
    main()
