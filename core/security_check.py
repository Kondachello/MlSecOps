"""core/security_check.py — security check артефакта MLflow (цепочка гейтов).

Тонкий фасад: формирует контекст рана, вызывает `gates_pipeline.run_pipeline` (который
делегирует в gates/runner.py — реальные гейты с Docker- или inline-режимом запуска),
печатает короткое summary в консоль бэка.

ЗАПУСК ТОЛЬКО по кнопке UI (страница артефакта / «Мои артефакты»), НЕ из IDE.

Контракт результата (стабильный для бэка/UI):
    {
      "passed": bool,
      "run_id": str,
      "tier": "LOW|MED|HIGH",
      "selected": [<gate_id>, ...],
      "gates": [ {id, name, status, severity, threats, description, detail, logs[],
                  evidence, duration_ms} ],
      "placeholder": False,   # уже не плейсхолдер — гейты настоящие
      "debug": {...}
    }
Бэкенд кладёт это в artifact_acl.check_detail; из FAIL-гейтов заводит инциденты.
"""
from __future__ import annotations

from typing import Optional

from core import gates_pipeline

# Ключевые слова критичных доменов → Tier=HIGH (плейсхолдер классификации критичности).
# В реальной системе Tier берётся из паспорта модели / реестра use-case'ов.
_HIGH_TIER_HINTS = ("credit", "fraud", "scoring", "loan", "kyc", "antifraud", "risk")


def compute_tier(run_meta: Optional[dict] = None) -> str:
    """Оценить Tier артефакта (LOW|MED|HIGH) — плейсхолдер по имени/тегам.

    HIGH → требует ручного Approve (HITL) перед продом.
    """
    meta = run_meta or {}
    hay = " ".join(str(meta.get(k, "")) for k in ("run_name", "experiment", "owner")).lower()
    params = " ".join(str(v) for v in (meta.get("params", {}) or {}).values()).lower()
    blob = f"{hay} {params}"
    if any(h in blob for h in _HIGH_TIER_HINTS):
        return "HIGH"
    return "MED"


def run_artifact_check(run_id: str, run_meta: Optional[dict] = None,
                       only: Optional[list[str]] = None,
                       from_gate: Optional[str] = None) -> dict:
    """Прогнать цепочку гейтов на артефакте.

    only=[ids] — подмножество (для rerun одного гейта);
    from_gate=ID — рестарт цепочки с указанного гейта до конца.
    """
    meta = dict(run_meta or {})
    meta.setdefault("run_id", run_id)
    pipe = gates_pipeline.run_pipeline(meta, only=only, from_gate=from_gate)
    result = {
        "passed": pipe.get("passed", False),
        "run_id": run_id,
        "tier": compute_tier(meta),
        "selected": pipe.get("selected", []),
        "gates": pipe.get("gates", []),
        "placeholder": pipe.get("placeholder", False),
        "debug": {
            "experiment_id": meta.get("experiment_id"),
            "owner": meta.get("owner"),
            "run_name": meta.get("run_name"),
            "n_params": len(meta.get("params", {}) or {}),
            "n_metrics": len(meta.get("metrics", {}) or {}),
            **(pipe.get("debug") or {}),
        },
    }

    print(f"[security_check] run_id={run_id} owner={meta.get('owner')} "
          f"-> {'PASS' if result['passed'] else 'FAIL'} "
          f"({len(result['gates'])} gates, mode={result['debug'].get('runner_mode', '?')})")
    for g in result["gates"]:
        print(f"[security_check]   {g['status']:4} {g['id']} {g.get('name','')}: {g.get('detail','')}")

    return result


if __name__ == "__main__":
    import json
    fake = {"experiment_id": "1", "owner": "vasya", "run_name": "demo-session",
            "params": {"n_estimators": "50"}, "metrics": {"accuracy": 0.93}}
    res = run_artifact_check("dummy_run_id", fake)
    print("\nРезультат:\n" + json.dumps(res, ensure_ascii=False, indent=2, default=str))
