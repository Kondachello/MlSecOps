"""Smoke-тест БД и Audit Trail (hash-chain).

Проверяет: запись событий, продолжение цепочки, обнаружение разрыва (#24).
Запуск: python tests/smoke_db.py  (или через pytest). Скелет.
"""
from __future__ import annotations


def test_log_event_and_chain():
    """TODO: log_event x3 → verify_chain().ok == True; подделать строку → ok == False."""
    # from core.db import log_event, verify_chain
    # log_event("msecops", "MLSecOps", "dataset_uploaded", asset="ds@1", result="ok")
    # assert verify_chain()["ok"] is True
    pass


if __name__ == "__main__":
    test_log_event_and_chain()
    print("smoke_db: OK (скелет — реализовать после core.db)")
