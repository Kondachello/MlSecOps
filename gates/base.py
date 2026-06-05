"""gates/base.py — контракт security-гейта + регистр.

GateContext — единый вход для всех гейтов: метаданные рана + скачанные артефакты + work_dir.
GateResult — единый выход: status / logs / detail / severity / duration.

Каждый гейт регистрируется в GATE_REGISTRY декоратором @register_gate("G5", ...), чтобы
runner.py мог их перечислить, упорядочить и прогнать (вся цепочка / one / from-point).
"""
from __future__ import annotations

import datetime as _dt
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Optional

Status = Literal["PASS", "FAIL", "SKIP"]


@dataclass
class GateContext:
    """Вход гейта. Заполняется runner-ом ПЕРЕД вызовом run()."""
    run_id: str
    work_dir: Path              # временная папка со скачанными артефактами рана
    run_meta: dict              # owner / params / metrics / tags из MLflow
    dataset_path: Optional[Path] = None   # CSV/parquet первого dataset-input (если есть)
    repo_root: Optional[Path] = None      # путь к репо платформы (для G0 fallback)


@dataclass
class GateResult:
    """Выход гейта. runner агрегирует это в JSON для бэка/UI."""
    id: str                     # "G5"
    name: str                   # "Model scan"
    status: Status              # PASS|FAIL|SKIP
    severity: str = "medium"    # critical|high|medium|low
    threats: list[str] = field(default_factory=list)
    detail: str = ""            # короткое summary для UI
    logs: list[str] = field(default_factory=list)   # построчные логи
    evidence: dict = field(default_factory=dict)    # машиночитаемые улики (для инцидентов)
    duration_ms: int = 0
    description: str = ""       # для UI: что гейт проверяет

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "status": self.status,
            "severity": self.severity, "threats": self.threats,
            "detail": self.detail, "logs": self.logs, "evidence": self.evidence,
            "duration_ms": self.duration_ms, "description": self.description,
        }


@dataclass
class _GateSpec:
    id: str
    name: str
    order: int                  # порядок в цепочке (DATA=10, G0=20, G5=30, G7=40, G8=50)
    description: str
    severity: str
    threats: list[str]
    fn: Callable[[GateContext], GateResult]


GATE_REGISTRY: dict[str, _GateSpec] = {}


def register_gate(gate_id: str, *, name: str, order: int, description: str,
                  severity: str = "medium", threats: Optional[list[str]] = None):
    """Декоратор регистрации гейта в реестре."""
    def deco(fn):
        GATE_REGISTRY[gate_id] = _GateSpec(
            id=gate_id, name=name, order=order, description=description,
            severity=severity, threats=threats or [], fn=fn)
        return fn
    return deco


def _ts() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%H:%M:%S")


def log_line(gate_id: str, name: str, message: str) -> str:
    """Однородный формат строки лога: '[HH:MM:SS] [G5 Model scan] message'."""
    return f"[{_ts()}] [{gate_id} {name}] {message}"


def run_one(gate_id: str, ctx: GateContext) -> GateResult:
    """Запустить ОДИН гейт по id. Замеряет duration, ловит исключения → FAIL."""
    spec = GATE_REGISTRY.get(gate_id)
    if not spec:
        return GateResult(id=gate_id, name="?", status="FAIL",
                          detail=f"unknown gate {gate_id}",
                          logs=[log_line(gate_id, "?", f"unknown gate id {gate_id}")])
    t0 = time.monotonic()
    try:
        res = spec.fn(ctx)
        # фиксируем метаданные из spec (на случай если гейт их не заполнил)
        res.id = spec.id
        res.name = res.name or spec.name
        res.description = res.description or spec.description
        if not res.threats:
            res.threats = list(spec.threats)
        if res.severity == "medium" and spec.severity != "medium":
            res.severity = spec.severity
    except Exception as e:  # noqa: BLE001
        res = GateResult(
            id=spec.id, name=spec.name, status="FAIL", severity=spec.severity,
            threats=list(spec.threats), description=spec.description,
            detail=f"gate crashed: {type(e).__name__}: {e}",
            logs=[log_line(spec.id, spec.name, f"FAIL crashed: {type(e).__name__}: {e}")],
            evidence={"exception": f"{type(e).__name__}: {e}"},
        )
    res.duration_ms = int((time.monotonic() - t0) * 1000)
    return res


def ordered_gate_ids() -> list[str]:
    """Все зарегистрированные id в порядке цепочки (по order, затем по id)."""
    return [g.id for g in sorted(GATE_REGISTRY.values(), key=lambda s: (s.order, s.id))]


def _ensure_gates_loaded() -> None:
    """Импортировать все гейты, чтобы декораторы зарегистрировали их в REGISTRY."""
    from gates import g_data, g0_secrets, g5_modelscan, g7_sign, g8_quality  # noqa: F401
