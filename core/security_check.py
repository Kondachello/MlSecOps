"""core/security_check.py — security check артефакта MLflow (цепочка гейтов).

Прогон конфигурируемой через YAML цепочки гейтов (см. config/gates.yml и core/gates_pipeline.py)
на артефакте (MLflow run = «сессия разработки»). СЕЙЧАС логика гейтов — ПЛЕЙСХОЛДЕР (гейты
отдают PASS из конфига) + текстовые логи; структура результата реальная.

Запускается ТОЛЬКО по кнопке из нашего сервиса (страница артефакта / «Мои артефакты»), не из IDE.

Контракт результата:
    {
      "passed": bool,
      "run_id": str,
      "gates": [ {id, name, description, status: PASS|FAIL|SKIP, severity, threats, detail, logs[]} ],
      "placeholder": True,
      "debug": {...}
    }
Бэкенд кладёт этот результат в artifact_acl.check_detail, а из FAIL-гейтов заводит инциденты.
"""
from __future__ import annotations

from typing import Optional

from core import gates_pipeline

# Ключевые слова критичных доменов → Tier=HIGH (ПЛЕЙСХОЛДЕР классификации критичности).
# В реальной системе Tier берётся из паспорта модели / реестра use-case'ов.
_HIGH_TIER_HINTS = ("credit", "fraud", "scoring", "loan", "kyc", "antifraud", "risk")


def compute_tier(run_meta: Optional[dict] = None) -> str:
    """Оценить Tier артефакта (LOW|MED|HIGH) — ПЛЕЙСХОЛДЕР по имени/тегам.

    HIGH → требует ручного Approve (HITL) перед продом. Точка расширения: реальный
    Tier — из паспорта модели (бизнес-критичность), а не из эвристики по имени.
    """
    meta = run_meta or {}
    hay = " ".join(str(meta.get(k, "")) for k in ("run_name", "experiment", "owner")).lower()
    params = " ".join(str(v) for v in (meta.get("params", {}) or {}).values()).lower()
    blob = f"{hay} {params}"
    if any(h in blob for h in _HIGH_TIER_HINTS):
        return "HIGH"
    return "MED"


def run_artifact_check(run_id: str, run_meta: Optional[dict] = None,
                       only: Optional[list[str]] = None) -> dict:
    """Прогнать цепочку гейтов на артефакте. only=[ids] — подмножество (для rerun одного гейта).

    run_meta — плоский dict рана из mlflow_utils.get_run (owner/run_name/params/metrics), может быть None.
    """
    meta = run_meta or {}
    pipe = gates_pipeline.run_pipeline(meta, only=only)
    result = {
        "passed": pipe["passed"],
        "run_id": run_id,
        "tier": compute_tier(meta),
        "gates": pipe["gates"],
        "placeholder": True,
        "debug": {
            "experiment_id": meta.get("experiment_id"),
            "owner": meta.get("owner"),
            "run_name": meta.get("run_name"),
            "n_params": len(meta.get("params", {}) or {}),
            "n_metrics": len(meta.get("metrics", {}) or {}),
            "config": gates_pipeline.GATES_CONFIG,
            "note": "Логика гейтов не реализована — конфиг-driven плейсхолдер (config/gates.yml).",
        },
    }

    # Дебаг-вывод в консоль бэка — видно, что проверка реально запускалась.
    print(f"[security_check] run_id={run_id} owner={meta.get('owner')} "
          f"-> {'PASS' if result['passed'] else 'FAIL'} "
          f"({len(result['gates'])} gates, placeholder)")
    for g in result["gates"]:
        print(f"[security_check]   {g['status']:4} {g['id']} {g['name']}: {g['detail']}")

    return result


if __name__ == "__main__":
    import json
    fake = {"experiment_id": "1", "owner": "vasya", "run_name": "demo-session",
            "params": {"n_estimators": "50"}, "metrics": {"accuracy": 0.93}}
    res = run_artifact_check("run-abc123", fake)
    print("\nРезультат:\n" + json.dumps(res, ensure_ascii=False, indent=2))
