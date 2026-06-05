"""core/gates_pipeline.py — фасад между бэкендом и реальным gates-runner-ом.

Реализация гейтов живёт в `gates/` (см. gates/runner.py). Этот модуль:
  • выбирает режим запуска: docker (через `docker compose exec gates-runner`)
    или inline-Python (subprocess в текущем env), и парсит JSON из stdout;
  • совместим со старым API: run_pipeline / run_single (вызывается из security_check).

Режим: env GATES_EXEC_MODE = docker|inline|auto (default auto).
  auto: пытаемся detect — если есть `docker compose ps gates-runner` → docker, иначе inline.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parents[1]

GATES_EXEC_MODE = os.getenv("GATES_EXEC_MODE", "auto").lower()
GATES_COMPOSE_SERVICE = os.getenv("GATES_COMPOSE_SERVICE", "gates-runner")
GATES_COMPOSE_FILE = os.getenv("GATES_COMPOSE_FILE",
                                str(_REPO_ROOT / "infra" / "docker-compose.yml"))
GATES_RUNNER_TIMEOUT = int(os.getenv("GATES_RUNNER_TIMEOUT", "300"))

# Для совместимости со старыми импортами (security_check читал GATES_CONFIG).
GATES_CONFIG = os.getenv("GATES_CONFIG", str(_REPO_ROOT / "config" / "gates.yml"))


# ─────────────────────────── выбор режима ──────────────────────────────
def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(
            ["docker", "compose", "-f", GATES_COMPOSE_FILE, "ps",
             "--services", "--filter", "status=running"],
            capture_output=True, text=True, timeout=10)
    except Exception:  # noqa: BLE001
        return False
    return r.returncode == 0 and GATES_COMPOSE_SERVICE in r.stdout.splitlines()


def _resolve_mode() -> str:
    if GATES_EXEC_MODE in ("docker", "inline"):
        return GATES_EXEC_MODE
    return "docker" if _docker_available() else "inline"


# ─────────────────────────── вызов runner-а ────────────────────────────
def _build_args(run_id: str, *, only: Optional[list[str]],
                from_gate: Optional[str]) -> list[str]:
    args = ["--run-id", run_id]
    if only:
        args += ["--only", ",".join(only)]
    if from_gate:
        args += ["--from", from_gate]
    return args


def _invoke_runner(run_id: str, *, only: Optional[list[str]],
                   from_gate: Optional[str]) -> dict:
    """Запустить gates.runner в выбранном режиме, вернуть распарсенный агрегат."""
    mode = _resolve_mode()
    runner_args = _build_args(run_id, only=only, from_gate=from_gate)

    if mode == "docker":
        # Долгоживущий контейнер gates-runner в compose; exec — не плодит контейнеры.
        cmd = ["docker", "compose", "-f", GATES_COMPOSE_FILE, "exec", "-T",
               GATES_COMPOSE_SERVICE,
               "python", "-m", "gates.runner", *runner_args]
    else:
        cmd = [sys.executable, "-m", "gates.runner", *runner_args]

    env = {**os.environ, "PYTHONPATH": str(_REPO_ROOT)}
    try:
        proc = subprocess.run(cmd, cwd=str(_REPO_ROOT), env=env, capture_output=True,
                              text=True, timeout=GATES_RUNNER_TIMEOUT, encoding="utf-8",
                              errors="replace")
    except subprocess.TimeoutExpired:
        return _runner_error_result(run_id, only, from_gate,
                                    f"runner timeout (>{GATES_RUNNER_TIMEOUT}s)")
    except FileNotFoundError as e:
        return _runner_error_result(run_id, only, from_gate, f"runner not found: {e}")

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    # Извлечь JSON-блок между маркерами; runner печатает их даже на rc=1 (FAIL).
    try:
        from gates.runner import RESULT_BEGIN, RESULT_END
    except Exception:  # noqa: BLE001
        RESULT_BEGIN, RESULT_END = "===GATES_RESULT_BEGIN===", "===GATES_RESULT_END==="

    if RESULT_BEGIN in stdout and RESULT_END in stdout:
        chunk = stdout.split(RESULT_BEGIN, 1)[1].split(RESULT_END, 1)[0].strip()
        try:
            agg = json.loads(chunk)
            # Прицепим короткий лог runner'а (для дебага в UI).
            head_lines = [ln for ln in stdout.splitlines()
                          if ln.startswith("[runner]")][:30]
            agg.setdefault("debug", {})["runner_mode"] = mode
            agg["debug"]["runner_log"] = head_lines
            return agg
        except json.JSONDecodeError as e:
            return _runner_error_result(run_id, only, from_gate,
                                        f"runner stdout JSON parse failed: {e}",
                                        stdout_tail=stdout[-2000:], stderr_tail=stderr[-2000:])

    return _runner_error_result(run_id, only, from_gate,
                                f"runner did not emit result block (rc={proc.returncode})",
                                stdout_tail=stdout[-2000:], stderr_tail=stderr[-2000:])


def _runner_error_result(run_id: str, only, from_gate, message: str,
                         stdout_tail: str = "", stderr_tail: str = "") -> dict:
    """Сформировать FAIL-агрегат когда runner не смог стартовать/вернуть результат."""
    return {
        "run_id": run_id,
        "selected": only or ([from_gate] if from_gate else []),
        "passed": False,
        "gates": [{
            "id": "RUNNER", "name": "Gates runner", "status": "FAIL",
            "severity": "high", "threats": [], "description": "оркестратор гейтов",
            "detail": message,
            "logs": [message] +
                    ([f"--- stdout tail ---\n{stdout_tail}"] if stdout_tail else []) +
                    ([f"--- stderr tail ---\n{stderr_tail}"] if stderr_tail else []),
            "evidence": {"runner_error": True},
            "duration_ms": 0,
        }],
        "placeholder": False,
        "debug": {"runner_error": message},
    }


# ─────────────────────────── публичный API (для security_check) ────────
def run_pipeline(run_meta: Optional[dict] = None, only: Optional[list[str]] = None,
                 from_gate: Optional[str] = None) -> dict:
    """Прогнать цепочку гейтов на ране. run_meta.run_id ОБЯЗАТЕЛЕН.

    Совместимо с тем, что было: возвращает {passed, gates: [...]}; новое поле
    `selected` показывает выбранные id (для UI).
    """
    meta = run_meta or {}
    run_id = meta.get("run_id") or meta.get("runId")
    if not run_id:
        return _runner_error_result("", only, from_gate, "run_id обязателен для запуска гейтов")
    agg = _invoke_runner(run_id, only=only, from_gate=from_gate)
    return agg


def run_single(gate_id: str, run_meta: Optional[dict] = None) -> Optional[dict]:
    """Перезапустить ОДИН гейт по id. None, если runner ничего не вернул."""
    agg = run_pipeline(run_meta=run_meta, only=[gate_id])
    gates = agg.get("gates") or []
    return gates[0] if gates else None


def load_pipeline() -> list[dict]:
    """Список зарегистрированных гейтов (для UI/выпадашек). Совместимо со старым API."""
    # Импортируем здесь, чтобы не тянуть gates/ когда оркестратор не нужен (тесты).
    try:
        from gates.base import GATE_REGISTRY, _ensure_gates_loaded, ordered_gate_ids
        _ensure_gates_loaded()
        return [{
            "id": g.id, "name": g.name, "description": g.description,
            "severity": g.severity, "threats": list(g.threats),
            "enabled": True, "order": g.order,
        } for g in sorted([GATE_REGISTRY[i] for i in ordered_gate_ids()],
                          key=lambda s: s.order)]
    except Exception:  # noqa: BLE001 — деградируем, если gates/ ещё не доступны
        return []


if __name__ == "__main__":
    # Дев-самопроверка: показать выбранный режим + список гейтов.
    print(f"mode = {_resolve_mode()} (env GATES_EXEC_MODE={GATES_EXEC_MODE})")
    for g in load_pipeline():
        print(f"  {g['id']} {g['name']} (order {g['order']}, severity {g['severity']})")
