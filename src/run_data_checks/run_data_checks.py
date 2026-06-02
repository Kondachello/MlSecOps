"""Пакетный прогон демо-датасетов через G1 (для разработки/демо).

Гоняет data_gate по всем файлам в data/ и печатает сводку.
Не пишет в БД — только демонстрация работы гейта (для боевого пути есть ingest_dataset).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.gates.data_gate.data_gate import build_report, gate_check  # noqa: E402

DATA_DIR = Path(__file__).resolve().parents[2] / "data"


def main() -> None:
    files = sorted(list(DATA_DIR.glob("*.csv")) + list(DATA_DIR.glob("*.parquet")))
    if not files:
        print("Нет демо-датасетов. Сначала: python data/make_datasets.py")
        return
    for f in files:
        report = build_report(str(f), gate_check(str(f)))
        status = "PASS" if report["passed"] else f"FAIL {report['failed_checks']}"
        print(f"[{status}] {f.name}")
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
