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

import time
from typing import Optional

from core import db, gates_pipeline

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
                       from_gate: Optional[str] = None,
                       *, actor: Optional[str] = None,
                       trigger: str = "artifact") -> dict:
    """Прогнать цепочку гейтов на артефакте + записать pipeline_run в БД (история CI).

    only=[ids] — подмножество (для rerun одного гейта);
    from_gate=ID — рестарт цепочки с указанного гейта до конца.
    actor — кто запустил (для журнала); по умолчанию из run_meta.owner.
    trigger — тип запуска: artifact (по кнопке на ране) / manual_ui / git_push / ci_scheduled.
    """
    meta = dict(run_meta or {})
    meta.setdefault("run_id", run_id)
    actor = actor or meta.get("owner") or "system"
    selected_ids = only or ([from_gate] if from_gate else None)
    # 1) Открываем pipeline_run (status='running'): он попадает в «История CI» сразу.
    pr_id: Optional[int] = None
    try:
        pr_id = db.create_pipeline_run(trigger=trigger, source=run_id, actor=actor,
                                       gate_ids=selected_ids)
    except Exception as e:  # noqa: BLE001 — не валим прогон гейтов если БД недоступна
        print(f"[security_check] WARN create_pipeline_run skipped: {e}")
    t0 = time.monotonic()
    pipe = gates_pipeline.run_pipeline(meta, only=only, from_gate=from_gate)
    duration_ms = int((time.monotonic() - t0) * 1000)
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

    # 2) Закрываем pipeline_run финальным статусом + полным detail (с гейтами/логами).
    if pr_id is not None:
        try:
            db.finish_pipeline_run(pr_id,
                                   status=("passed" if result["passed"] else "failed"),
                                   detail=result, duration_ms=duration_ms)
        except Exception as e:  # noqa: BLE001
            print(f"[security_check] WARN finish_pipeline_run skipped: {e}")

    return result


if __name__ == "__main__":
    import json
    fake = {"experiment_id": "1", "owner": "vasya", "run_name": "demo-session",
            "params": {"n_estimators": "50"}, "metrics": {"accuracy": 0.93}}
    res = run_artifact_check("dummy_run_id", fake)
    print("\nРезультат:\n" + json.dumps(res, ensure_ascii=False, indent=2, default=str))
