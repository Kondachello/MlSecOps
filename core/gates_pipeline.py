"""core/gates_pipeline.py — конфигурируемый через YAML пайплайн security-гейтов.

Цепочка гейтов задаётся в `config/gates.yml` (путь переопределяется env GATES_CONFIG).
СЕЙЧАС логика гейтов — ПЛЕЙСХОЛДЕР: каждый гейт возвращает исход из конфига (`result`,
по умолчанию PASS) + текстовые логи. Структура реальная — под будущую настоящую логику.

Где подключать настоящие гейты: функция `run_gate()` — единственная точка, где плейсхолдер
заменяется на реальный вызов (например, `src/gates/<name>` или docker-образ гейта).

Используется:
  • core/security_check.run_artifact_check — прогон всей цепочки на артефакте;
  • бэкенд (rerun одного гейта) — через run_single().
"""
from __future__ import annotations

import datetime as _dt
import os
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parents[1]
GATES_CONFIG = os.getenv("GATES_CONFIG", str(_REPO_ROOT / "config" / "gates.yml"))

# Встроенный дефолт на случай, если YAML недоступен/PyYAML не установлен (graceful).
_DEFAULT_PIPELINE: list[dict] = [
    {"id": "G1", "name": "Data", "description": "Схема, баланс классов, PII, инъекции",
     "enabled": True, "severity": "high", "threats": ["#1", "#2", "#11", "#15"], "result": "pass"},
    {"id": "G2", "name": "Code", "description": "Секреты, CVE, опасный код",
     "enabled": True, "severity": "critical", "threats": ["#8", "#10"], "result": "pass"},
    {"id": "G3", "name": "Supply", "description": "Typosquatting, пиннинг, источник",
     "enabled": True, "severity": "high", "threats": ["#9", "#3"], "result": "pass"},
    {"id": "G4", "name": "Model", "description": "Формат весов, скан, SHA, подпись",
     "enabled": True, "severity": "critical", "threats": ["#3", "#4", "#26"], "result": "pass"},
    {"id": "G5", "name": "Registry", "description": "Паспорт, lineage, Tier",
     "enabled": True, "severity": "medium", "threats": ["#20", "#23"], "result": "pass"},
]


def load_pipeline() -> list[dict]:
    """Прочитать цепочку гейтов из YAML; при любой ошибке — встроенный дефолт."""
    try:
        import yaml  # PyYAML (тянется mlflow); fallback ниже, если нет
        with open(GATES_CONFIG, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        gates = cfg.get("pipeline") or []
        if gates:
            return gates
    except Exception:  # noqa: BLE001
        pass
    return _DEFAULT_PIPELINE


def _norm_status(value: str) -> str:
    s = str(value or "pass").upper()
    return s if s in ("PASS", "FAIL", "SKIP") else "PASS"


def run_gate(gate: dict, run_meta: Optional[dict] = None) -> dict:
    """Прогнать ОДИН гейт (ПЛЕЙСХОЛДЕР). Вернуть структурированный результат + логи.

    Точка расширения: здесь плейсхолдер (исход из конфига) заменяется реальной логикой гейта.
    """
    meta = run_meta or {}
    gid = gate.get("id", "?")
    name = gate.get("name", "")
    status = _norm_status(gate.get("result", "pass"))
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%H:%M:%S")
    logs = [
        f"[{ts}] [{gid} {name}] start (placeholder gate, config-driven)",
        f"[{ts}] [{gid} {name}] target: run={meta.get('run_name') or meta.get('run_id') or '?'} "
        f"owner={meta.get('owner', '?')}",
        f"[{ts}] [{gid} {name}] checks: {gate.get('description', '')}",
        f"[{ts}] [{gid} {name}] result = {status} (логика гейта пока не реализована)",
    ]
    return {
        "id": gid,
        "name": name,
        "description": gate.get("description", ""),
        "status": status,
        "severity": gate.get("severity", "medium"),
        "threats": gate.get("threats", []),
        "detail": f"{name}: {gate.get('description', '')} — placeholder {status}",
        "logs": logs,
        "placeholder": True,
    }


def run_pipeline(run_meta: Optional[dict] = None, only: Optional[list[str]] = None) -> dict:
    """Прогнать цепочку (только enabled; only=[ids] — подмножество гейтов).

    Возвращает {"passed": bool, "gates": [<run_gate>...]}.
    passed = ни один гейт не FAIL (SKIP не валит).
    """
    gates_cfg = [g for g in load_pipeline() if g.get("enabled", True)]
    if only:
        wanted = set(only)
        gates_cfg = [g for g in gates_cfg if g.get("id") in wanted]
    results = [run_gate(g, run_meta) for g in gates_cfg]
    passed = all(r["status"] != "FAIL" for r in results)
    return {"passed": passed, "gates": results}


def run_single(gate_id: str, run_meta: Optional[dict] = None) -> Optional[dict]:
    """Прогнать один гейт по id (для кнопки «перезапустить гейт»). None, если id неизвестен."""
    for g in load_pipeline():
        if g.get("id") == gate_id:
            return run_gate(g, run_meta)
    return None


if __name__ == "__main__":
    import json
    demo = run_pipeline({"owner": "vasya", "run_name": "demo-session", "run_id": "run-abc"})
    print(json.dumps(demo, ensure_ascii=False, indent=2))
