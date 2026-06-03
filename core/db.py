"""core/db.py — Postgres: Audit Trail (hash-chain), реестр, findings, RBAC.

Единственная точка записи в events — log_event(). Гейты в БД не пишут; оркестратор вызывает
ingest_gate_report() после парсинга JSON гейта.
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from typing import Any, Iterator, Optional

GENESIS_HASH = "0" * 64

_SEVERITY_FROM_CHECK = {
    "secrets": "critical",
    "cve_deps": "critical",
    "trivy_image": "critical",
    "weights_scan": "critical",
    "name_allowlist": "critical",
    "card_completeness": "high",
    "lineage": "high",
    "sast": "high",
    "pii": "high",
    "class_balance": "high",
}


def _pg_params() -> dict[str, Any]:
    return {
        "host": os.getenv("POSTGRES_HOST", "localhost"),
        "port": int(os.getenv("POSTGRES_PORT", "5432")),
        "dbname": os.getenv("POSTGRES_DB", "mlsec"),
        "user": os.getenv("POSTGRES_USER", "mlsec_app"),
        "password": os.getenv("POSTGRES_PASSWORD", "change_me"),
    }


def get_conn():
    """Соединение с Postgres (psycopg3)."""
    import psycopg

    return psycopg.connect(**_pg_params())


@contextmanager
def db_cursor() -> Iterator[Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            yield cur
        conn.commit()


def ping() -> bool:
    """Проверка доступности БД (для smoke / health)."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return True
    except Exception:
        return False


# --- Audit Trail (hash-chain) ------------------------------------------------
def _canonical_payload(
    actor: str,
    role: str,
    action: str,
    asset: Optional[str],
    result: str,
    reason: Optional[str],
    details: Optional[dict],
) -> str:
    return json.dumps(
        {
            "actor": actor,
            "role": role,
            "action": action,
            "asset": asset,
            "result": result,
            "reason": reason,
            "details": details or {},
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _row_hash(prev_hash: str, payload: str) -> str:
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


def log_event(
    actor: str,
    role: str,
    action: str,
    *,
    asset: Optional[str] = None,
    result: str = "ok",
    reason: Optional[str] = None,
    details: Optional[dict] = None,
) -> int:
    """Записать событие в events с hash-chain. Возвращает id события."""
    assert result in {"ok", "blocked", "pending", "error"}, result
    payload = _canonical_payload(actor, role, action, asset, result, reason, details)
    with db_cursor() as cur:
        cur.execute(
            "SELECT row_hash FROM events ORDER BY id DESC LIMIT 1",
        )
        row = cur.fetchone()
        prev = row[0] if row else GENESIS_HASH
        row_hash = _row_hash(prev, payload)
        cur.execute(
            """
            INSERT INTO events (actor, role, action, asset, result, reason, details, prev_hash, row_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
            RETURNING id
            """,
            (
                actor,
                role,
                action,
                asset,
                result,
                reason,
                json.dumps(details or {}, ensure_ascii=False),
                prev,
                row_hash,
            ),
        )
        return int(cur.fetchone()[0])


def verify_chain() -> dict:
    """Пересчитать hash-chain. Возвращает {"ok": bool, "broken_at": id|None}."""
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, actor, role, action, asset, result, reason, details, prev_hash, row_hash "
            "FROM events ORDER BY id",
        )
        rows = cur.fetchall()
    prev = GENESIS_HASH
    for row in rows:
        eid, actor, role, action, asset, result, reason, details, prev_hash, row_hash = row
        if prev_hash != prev:
            return {"ok": False, "broken_at": eid, "reason": "prev_hash mismatch"}
        payload = _canonical_payload(
            actor,
            role,
            action,
            asset,
            result,
            reason,
            details if isinstance(details, dict) else json.loads(details or "{}"),
        )
        expected = _row_hash(prev, payload)
        if row_hash != expected:
            return {"ok": False, "broken_at": eid, "reason": "row_hash mismatch"}
        prev = row_hash
    return {"ok": True, "broken_at": None}


# --- findings + bridge from gate JSON ----------------------------------------
def add_finding(
    gate: str,
    asset_type: str,
    asset: str,
    rule: str,
    severity: str,
    evidence: dict,
    *,
    run_no: int = 1,
    status: str = "open",
) -> int:
    assert severity in {"critical", "high", "medium", "low"}, severity
    assert asset_type in {"dataset", "code", "model", "dependency", "runtime"}, asset_type
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO findings (gate, asset_type, asset, rule, severity, evidence, status, run_no)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s)
            RETURNING id
            """,
            (gate, asset_type, asset, rule, severity, json.dumps(evidence, ensure_ascii=False), status, run_no),
        )
        return int(cur.fetchone()[0])


def ingest_gate_report(report: dict, asset_type: str) -> list[int]:
    """Разобрать JSON гейта (stdout) и записать findings для каждого FAIL check."""
    ids: list[int] = []
    gate = report.get("gate", "?")
    asset = report.get("asset", "?")
    for check in report.get("checks", []):
        if check.get("status") != "FAIL":
            continue
        rule = check.get("check", "unknown")
        severity = check.get("severity") or _SEVERITY_FROM_CHECK.get(rule, "medium")
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "medium"
        ids.append(
            add_finding(
                gate=gate,
                asset_type=asset_type,
                asset=asset,
                rule=rule,
                severity=severity,
                evidence=check.get("evidence") or {},
            )
        )
    return ids


# --- реестр ------------------------------------------------------------------
def register_dataset(
    name: str,
    version: str,
    sha256: str,
    source_type: str,
    status: str,
    bucket: str,
    owner: str,
) -> int:
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO datasets (name, version, sha256, source_type, status, bucket, owner)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (name, version) DO UPDATE SET
              sha256 = EXCLUDED.sha256,
              source_type = EXCLUDED.source_type,
              status = EXCLUDED.status,
              bucket = EXCLUDED.bucket,
              owner = EXCLUDED.owner
            RETURNING id
            """,
            (name, version, sha256, source_type, status, bucket, owner),
        )
        return int(cur.fetchone()[0])


def get_dataset_status(name: str, version: str) -> Optional[str]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT status FROM datasets WHERE name = %s AND version = %s",
            (name, version),
        )
        row = cur.fetchone()
        return row[0] if row else None


def register_model(
    name: str,
    version: str,
    *,
    tier: str,
    status: str,
    source: str,
    owner: str,
    card: dict,
    sha256: Optional[str] = None,
) -> int:
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO models (name, version, tier, status, source, sha256, owner, card)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            ON CONFLICT (name, version) DO UPDATE SET
              tier = EXCLUDED.tier,
              status = EXCLUDED.status,
              source = EXCLUDED.source,
              sha256 = EXCLUDED.sha256,
              owner = EXCLUDED.owner,
              card = EXCLUDED.card
            RETURNING id
            """,
            (name, version, tier, status, source, sha256, owner, json.dumps(card, ensure_ascii=False)),
        )
        return int(cur.fetchone()[0])


def get_model_status(name: str, version: str) -> Optional[str]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT status FROM models WHERE name = %s AND version = %s",
            (name, version),
        )
        row = cur.fetchone()
        return row[0] if row else None


def set_status(asset_type: str, name: str, version: str, status: str) -> None:
    table = "datasets" if asset_type == "dataset" else "models"
    with db_cursor() as cur:
        cur.execute(
            f"UPDATE {table} SET status = %s WHERE name = %s AND version = %s",
            (status, name, version),
        )


# --- RBAC --------------------------------------------------------------------
def register_user(username: str, email: Optional[str] = None) -> int:
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO users (username, email) VALUES (%s, %s)
            ON CONFLICT (username) DO UPDATE SET email = COALESCE(EXCLUDED.email, users.email)
            RETURNING id
            """,
            (username, email),
        )
        return int(cur.fetchone()[0])


def assign_role(user_id: int, role: str) -> None:
    assert role in {"DS", "DE", "MLSecOps", "Product", "CEO"}, role
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO roles (user_id, role) VALUES (%s, %s)
            ON CONFLICT (user_id, role) DO NOTHING
            """,
            (user_id, role),
        )


def get_roles(username: str) -> set[str]:
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT r.role FROM roles r
            JOIN users u ON u.id = r.user_id
            WHERE u.username = %s
            """,
            (username,),
        )
        return {row[0] for row in cur.fetchall()}


def grant_access(
    user_id: int,
    dataset_name: str,
    dataset_version: str,
    *,
    can_export: bool,
    granted_by: str,
) -> None:
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO dataset_access (user_id, dataset_name, dataset_version, can_export, granted_by)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (user_id, dataset_name, dataset_version) DO UPDATE SET
              can_export = EXCLUDED.can_export,
              granted_by = EXCLUDED.granted_by,
              ts = now()
            """,
            (user_id, dataset_name, dataset_version, can_export, granted_by),
        )


def has_dataset_access(user_id: int, dataset_name: str, dataset_version: str) -> bool:
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT 1 FROM dataset_access
            WHERE user_id = %s AND dataset_name = %s AND dataset_version = %s
            """,
            (user_id, dataset_name, dataset_version),
        )
        return cur.fetchone() is not None


def mark_false_positive(finding_id: int, marked_by: str, reason: str) -> None:
    with db_cursor() as cur:
        cur.execute(
            """
            UPDATE findings SET status = 'false_positive', marked_by = %s
            WHERE id = %s
            """,
            (marked_by, finding_id),
        )


def add_model_version(
    model_name: str,
    version: str,
    *,
    dataset_name: Optional[str],
    dataset_version: Optional[str],
    dataset_sha256: Optional[str],
    git_sha: Optional[str],
    run_id: Optional[str],
    trained_in_ci: bool,
    sha256: Optional[str],
    status: str,
) -> int:
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO model_versions (
              model_name, version, dataset_name, dataset_version, dataset_sha256,
              git_sha, run_id, trained_in_ci, sha256, status
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (model_name, version) DO UPDATE SET
              dataset_name = EXCLUDED.dataset_name,
              dataset_version = EXCLUDED.dataset_version,
              dataset_sha256 = EXCLUDED.dataset_sha256,
              git_sha = EXCLUDED.git_sha,
              run_id = EXCLUDED.run_id,
              trained_in_ci = EXCLUDED.trained_in_ci,
              sha256 = EXCLUDED.sha256,
              status = EXCLUDED.status
            RETURNING id
            """,
            (
                model_name,
                version,
                dataset_name,
                dataset_version,
                dataset_sha256,
                git_sha,
                run_id,
                trained_in_ci,
                sha256,
                status,
            ),
        )
        return int(cur.fetchone()[0])
