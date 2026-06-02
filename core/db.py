"""core/db.py — доступ к Postgres: Audit Trail (hash-chain), реестр, находки, RBAC.

КОНВЕНЦИИ (docs/IMPLEMENTATION_PLAN.md, docs/09_DATA_MODEL.md):
- log_event() — ЕДИНСТВЕННАЯ точка записи в events; считает hash-chain.
- Гейты сами в БД не пишут — пишет оркестратор (ingest / Gatekeeper).
- На роли приложения отозваны UPDATE/DELETE на events (append-only).

Это СКЕЛЕТ: сигнатуры и контракты зафиксированы, реализация помечена TODO.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Optional

GENESIS_HASH = "0" * 64


# --- подключение -------------------------------------------------------------
def get_conn():
    """Вернуть соединение с Postgres (psycopg). TODO: пул соединений.

    Берёт параметры из окружения (POSTGRES_*). Graceful: при недоступной БД
    вызывающий код должен деградировать (SKIP/предупреждение), не падать.
    """
    raise NotImplementedError("TODO: psycopg.connect(...) из POSTGRES_* env")


# --- Audit Trail (hash-chain) ------------------------------------------------
def _canonical_payload(actor: str, role: str, action: str, asset: Optional[str],
                        result: str, reason: Optional[str], details: Optional[dict]) -> str:
    """Канонизированное представление события для хэширования (стабильный порядок)."""
    return json.dumps(
        {"actor": actor, "role": role, "action": action, "asset": asset,
         "result": result, "reason": reason, "details": details or {}},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )


def _row_hash(prev_hash: str, payload: str) -> str:
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


def log_event(actor: str, role: str, action: str, *, asset: Optional[str] = None,
              result: str = "ok", reason: Optional[str] = None,
              details: Optional[dict] = None) -> None:
    """Записать событие в Audit Trail с продолжением hash-chain.

    actor   — СЕРВЕРНАЯ identity (из auth-прокси), НЕ клиентское поле.
    result  — один из {ok, blocked, pending, error}.
    reason  — обязателен для изменяющих действий (justification).

    TODO: SELECT последнего row_hash (или GENESIS) → вычислить row_hash → INSERT.
    """
    assert result in {"ok", "blocked", "pending", "error"}, result
    payload = _canonical_payload(actor, role, action, asset, result, reason, details)
    # prev = SELECT row_hash FROM events ORDER BY id DESC LIMIT 1  (или GENESIS_HASH)
    # row = _row_hash(prev, payload)
    # INSERT INTO events(...) VALUES (...)
    raise NotImplementedError("TODO: реализовать INSERT с hash-chain")


def verify_chain() -> dict:
    """Пройти events по порядку, пересчитать хэши, найти разрыв (демо угрозы #24).

    Возвращает {"ok": bool, "broken_at": Optional[int]}.
    TODO: SELECT * ORDER BY id; пересчёт row_hash; сравнение.
    """
    raise NotImplementedError("TODO")


# --- реестр (datasets / models / model_versions) -----------------------------
def register_dataset(name: str, version: str, sha256: str, source_type: str,
                     status: str, bucket: str, owner: str) -> int:
    """INSERT в datasets. TODO."""
    raise NotImplementedError("TODO")


def register_model(name: str, version: str, *, tier: str, status: str, source: str,
                   owner: str, card: dict, sha256: Optional[str] = None) -> int:
    """Зарегистрировать модель И в Postgres, И (через mlflow_utils) в MLflow Registry.

    Перед регистрацией прогоняется G5 (registry_gate) — блок при FAIL.
    TODO: INSERT models + вызов mlflow_utils.register_model_version().
    """
    raise NotImplementedError("TODO")


def add_model_version(model_name: str, version: str, *, dataset_name: Optional[str],
                      dataset_version: Optional[str], dataset_sha256: Optional[str],
                      git_sha: Optional[str], run_id: Optional[str],
                      trained_in_ci: bool, sha256: Optional[str], status: str) -> int:
    """INSERT в model_versions (lineage). trained_in_ci проставляет CI, не клиент. TODO."""
    raise NotImplementedError("TODO")


def set_status(asset_type: str, name: str, version: str, status: str) -> None:
    """Сменить статус актива (datasets/models). TODO + log_event вызывающим."""
    raise NotImplementedError("TODO")


# --- находки (общая сущность сработок) ---------------------------------------
def add_finding(gate: str, asset_type: str, asset: str, rule: str, severity: str,
                evidence: dict, *, run_no: int = 1, status: str = "open") -> int:
    """INSERT в findings. severity ∈ {critical,high,medium,low}. TODO."""
    assert severity in {"critical", "high", "medium", "low"}, severity
    raise NotImplementedError("TODO")


def mark_false_positive(finding_id: int, marked_by: str, reason: str) -> None:
    """Отметить находку как false_positive (только MLSecOps). TODO + log_event."""
    raise NotImplementedError("TODO")


# --- RBAC --------------------------------------------------------------------
def register_user(username: str, email: Optional[str] = None) -> int:
    raise NotImplementedError("TODO")


def assign_role(user_id: int, role: str) -> None:
    assert role in {"DS", "DE", "MLSecOps", "Product", "CEO"}, role
    raise NotImplementedError("TODO")


def grant_access(user_id: int, dataset_name: str, dataset_version: str,
                 *, can_export: bool, granted_by: str) -> None:
    raise NotImplementedError("TODO")


def has_dataset_access(user_id: int, dataset_name: str, dataset_version: str) -> bool:
    raise NotImplementedError("TODO")
