"""G6 Observability — постоянный мониторинг прода: дрейф, деградация, подмена модели.

Закрывает #14 (drift) и усиливает #4 (детект подмены в рантайме).
См. docs/13_RUNTIME_AND_MONITORING.md §13.4. Работает постоянно (не по кнопке).
Скелет.
"""
from __future__ import annotations

import argparse

PSI_THRESHOLD = 0.25


def compute_psi(reference, current) -> float:
    """Population Stability Index между train-распределением и прод-трафиком.

    TODO: реализовать PSI (или вызвать evidently). Возвращает значение PSI.
    """
    raise NotImplementedError("TODO: PSI / evidently")


def check_model_substitution(running_artifact_path: str, expected_sha: str) -> bool:
    """Периодический ре-хэш запущенного артефакта ↔ реестр. True = подмена. TODO."""
    raise NotImplementedError("TODO: sha256(running) != expected")


def main() -> None:
    ap = argparse.ArgumentParser(description="G6 drift/substitution monitor")
    ap.add_argument("--reference", help="train-распределение/датасет")
    ap.add_argument("--current", help="прод-трафик (csv/parquet)")
    ap.parse_args()
    # TODO: psi = compute_psi(...); если psi>PSI_THRESHOLD → log_event(drift) + алерт в дашборд
    raise NotImplementedError("TODO")


if __name__ == "__main__":
    main()
