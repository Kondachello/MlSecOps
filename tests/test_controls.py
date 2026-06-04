"""Консистентность каталога контролей (GRC): у каждого контроля есть тесты, угрозы, стандарты."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.common import controls as C  # noqa: E402


def test_every_control_has_threat_and_test():
    for c in C.CONTROLS:
        assert c["threats"], f"{c['id']}: нет привязки к угрозе"
        assert c["tests"], f"{c['id']}: нет тестов"
        assert c["status"] in {"live", "planned", "accepted"}, c["id"]


def test_unique_ids():
    ids = [c["id"] for c in C.CONTROLS]
    assert len(ids) == len(set(ids)), "дубли ID контролей"


def test_coverage_math():
    cov = C.coverage()
    assert cov["live"] + cov["accepted"] + cov["planned"] == cov["total"]
    assert 0 <= cov["pct"] <= 100


def test_risk_acceptance_increases_closed():
    before = C.coverage()["closed"]
    planned = next((c for c in C.CONTROLS if c["status"] == "planned"), None)
    if planned:
        C.set_accepted(planned["id"], "tester", "demo")
        assert C.coverage()["closed"] == before + 1
        C.RISK_ACCEPTED.pop(planned["id"], None)  # cleanup


if __name__ == "__main__":
    test_every_control_has_threat_and_test()
    test_unique_ids()
    test_coverage_math()
    test_risk_acceptance_increases_closed()
    print("controls: OK")
