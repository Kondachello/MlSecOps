"""core/db.py — доступ к БД: Audit Trail (hash-chain), реестр, находки, RBAC.

КОНВЕНЦИИ (docs/IMPLEMENTATION_PLAN.md, docs/09_DATA_MODEL.md):
- log_event() — ЕДИНСТВЕННАЯ точка записи в events; считает hash-chain.
- Гейты сами в БД не пишут — пишет оркестратор (ingest / Gatekeeper).
- На роли приложения отозваны UPDATE/DELETE на events (append-only).

ДВА БЭКЕНДА (выбор через env DB_BACKEND):
- "sqlite"  (по умолчанию) — мгновенный локальный дев/тест без Docker.
                              Файл в SQLITE_PATH (по умолчанию ./mlsec_dev.db).
- "postgres" — боевой/compose режим (psycopg + POSTGRES_* env, схема из infra/init.sql).

Плейсхолдеры в SQL пишем стилем '?'; для Postgres транслируем в '%s'.
JSON-поля (details/card/evidence) храним через _json_param/_json_load (TEXT в sqlite, JSONB в pg).
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional

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

DB_BACKEND = os.getenv("DB_BACKEND", "sqlite").lower()
_REPO_ROOT = Path(__file__).resolve().parents[1]
SQLITE_PATH = os.getenv("SQLITE_PATH", str(_REPO_ROOT / "mlsec_dev.db"))


def _is_pg() -> bool:
    return DB_BACKEND in ("postgres", "postgresql", "pg")


# --- подключение -------------------------------------------------------------
def get_conn():
    """Вернуть соединение с БД (psycopg для Postgres, sqlite3 для дев).

    Параметры Postgres берутся из окружения POSTGRES_*. SQLite — из SQLITE_PATH.
    """
    if _is_pg():
        import psycopg  # импорт лениво: в sqlite-режиме psycopg может быть не установлен
        return psycopg.connect(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", "5432")),
            dbname=os.getenv("POSTGRES_DB", "mlsec"),
            user=os.getenv("POSTGRES_USER", "mlsec_app"),
            password=os.getenv("POSTGRES_PASSWORD", ""),
        )
    import sqlite3
    conn = sqlite3.connect(SQLITE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _sql(query: str) -> str:
    """Транслировать плейсхолдеры '?' → '%s' для Postgres (psycopg)."""
    return query.replace("?", "%s") if _is_pg() else query


def _json_param(value: Optional[dict]):
    """Параметр для JSON-колонки: Jsonb для pg, json-строка для sqlite."""
    if value is None:
        return None
    if _is_pg():
        from psycopg.types.json import Jsonb
        return Jsonb(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _json_load(value: Any) -> Optional[dict]:
    """Прочитать JSON-колонку обратно в dict (sqlite отдаёт строку, pg — уже dict)."""
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    return json.loads(value)


@contextmanager
def _tx(commit: bool = False):
    """Контекст с курсором; коммит при commit=True; соединение всегда закрывается."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        yield cur
        if commit:
            conn.commit()
    finally:
        conn.close()


def ping() -> bool:
    """Проверка доступности БД (для smoke / health)."""
    try:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            return True
        finally:
            conn.close()
    except Exception:
        return False


# --- схема (только для sqlite-дев; в Postgres схему ставит infra/init.sql) ----
_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor     TEXT NOT NULL,
    role      TEXT NOT NULL,
    action    TEXT NOT NULL,
    asset     TEXT,
    result    TEXT NOT NULL CHECK (result IN ('ok','blocked','pending','error')),
    reason    TEXT,
    details   TEXT,
    prev_hash TEXT NOT NULL,
    row_hash  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS datasets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('local','internet','corp_storage','verified_id')),
    status      TEXT NOT NULL CHECK (status IN ('registered','available','quarantine','prod_locked')),
    bucket      TEXT NOT NULL,
    owner       TEXT NOT NULL,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name, version)
);
CREATE TABLE IF NOT EXISTS verified_datasets (
    sha256      TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    verified_at TEXT DEFAULT CURRENT_TIMESTAMP,
    signed      INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS models (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    tier        TEXT NOT NULL CHECK (tier IN ('LOW','MED','HIGH')),
    status      TEXT NOT NULL CHECK (status IN
                  ('registered','quarantine','pending_hitl','approved','prod','previous','retired')),
    source      TEXT NOT NULL CHECK (source IN ('ci_trained','external')),
    sha256      TEXT,
    signed      INTEGER DEFAULT 0,
    owner       TEXT NOT NULL,
    approved_by TEXT,
    card        TEXT NOT NULL,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name, version)
);
CREATE TABLE IF NOT EXISTS hitl_approvals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name  TEXT NOT NULL,
    version     TEXT NOT NULL,
    approver    TEXT NOT NULL,
    reason      TEXT,
    approved_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (model_name, version, approver)
);
CREATE TABLE IF NOT EXISTS model_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name      TEXT NOT NULL,
    version         TEXT NOT NULL,
    dataset_name    TEXT,
    dataset_version TEXT,
    dataset_sha256  TEXT,
    git_sha         TEXT,
    run_id          TEXT,
    mlflow_version  TEXT,
    trained_in_ci   INTEGER NOT NULL,
    sha256          TEXT,
    status          TEXT NOT NULL,
    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (model_name, version)
);
CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT DEFAULT CURRENT_TIMESTAMP,
    gate       TEXT NOT NULL,
    asset_type TEXT NOT NULL CHECK (asset_type IN ('dataset','code','model','dependency','runtime')),
    asset      TEXT NOT NULL,
    rule       TEXT NOT NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    evidence   TEXT,
    status     TEXT NOT NULL CHECK (status IN ('open','false_positive','fixed')),
    marked_by  TEXT,
    run_no     INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT,
    password_hash TEXT,
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS roles (
    user_id INTEGER REFERENCES users(id),
    role    TEXT NOT NULL CHECK (role IN ('DS','DE','MLSecOps','Product','CEO')),
    PRIMARY KEY (user_id, role)
);
CREATE TABLE IF NOT EXISTS dataset_access (
    user_id         INTEGER REFERENCES users(id),
    dataset_name    TEXT NOT NULL,
    dataset_version TEXT NOT NULL,
    can_export      INTEGER DEFAULT 0,
    granted_by      TEXT NOT NULL,
    ts              TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, dataset_name, dataset_version)
);
"""


def _bool_param(flag: bool):
    """SQLite — 0/1; Postgres — BOOLEAN."""
    return flag if _is_pg() else (1 if flag else 0)


_PG_MIGRATIONS = (
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT",
)


def _apply_pg_migrations() -> None:
    """Догоняем схему Postgres после init.sql (старые volumes без password_hash)."""
    with _tx(commit=True) as cur:
        for stmt in _PG_MIGRATIONS:
            cur.execute(stmt)


def init_db() -> None:
    """Создать схему для SQLite-дев (идемпотентно). В Postgres — init.sql + миграции."""
    if _is_pg():
        _apply_pg_migrations()
        return
    conn = get_conn()
    try:
        conn.executescript(_SQLITE_SCHEMA)
        conn.commit()
    finally:
        conn.close()


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
    """
    assert result in {"ok", "blocked", "pending", "error"}, result
    payload = _canonical_payload(actor, role, action, asset, result, reason, details)
    with _tx(commit=True) as cur:
        cur.execute("SELECT row_hash FROM events ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        prev = row[0] if row else GENESIS_HASH
        row_hash = _row_hash(prev, payload)
        cur.execute(
            _sql("""INSERT INTO events
                    (actor, role, action, asset, result, reason, details, prev_hash, row_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""),
            (actor, role, action, asset, result, reason,
             _json_param(details), prev, row_hash),
        )


def list_events(limit: int = 100) -> list[dict]:
    """Последние события Audit Trail (новые сверху) — для UI «История событий»."""
    with _tx() as cur:
        cur.execute(
            "SELECT id, ts, actor, role, action, asset, result, reason, details "
            "FROM events ORDER BY id DESC LIMIT " + str(int(limit)))
        rows = cur.fetchall()
    return [
        {"id": int(r[0]), "ts": r[1], "actor": r[2], "role": r[3], "action": r[4],
         "asset": r[5], "result": r[6], "reason": r[7], "details": _json_load(r[8])}
        for r in rows
    ]


def verify_chain() -> dict:
    """Пройти events по порядку, пересчитать хэши, найти разрыв (демо угрозы #24).

    Возвращает {"ok": bool, "broken_at": Optional[int], "count": int}.
    """
    with _tx() as cur:
        cur.execute(
            "SELECT id, actor, role, action, asset, result, reason, details, prev_hash, row_hash "
            "FROM events ORDER BY id")
        rows = cur.fetchall()
    prev = GENESIS_HASH
    for r in rows:
        (rid, actor, role, action, asset, result, reason, details, prev_hash, row_hash) = r
        payload = _canonical_payload(actor, role, action, asset, result, reason,
                                     _json_load(details))
        expected = _row_hash(prev, payload)
        if prev_hash != prev or row_hash != expected:
            return {"ok": False, "broken_at": rid, "count": len(rows)}
        prev = row_hash
    return {"ok": True, "broken_at": None, "count": len(rows)}


# --- реестр (datasets / models / model_versions) -----------------------------
def register_dataset(name: str, version: str, sha256: str, source_type: str,
                     status: str, bucket: str, owner: str) -> int:
    """INSERT/UPDATE datasets."""
    with _tx(commit=True) as cur:
        if _is_pg():
            cur.execute(
                _sql(
                    """INSERT INTO datasets (name, version, sha256, source_type, status, bucket, owner)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT (name, version) DO UPDATE SET
                         sha256=EXCLUDED.sha256, status=EXCLUDED.status, bucket=EXCLUDED.bucket
                       RETURNING id"""
                ),
                (name, version, sha256, source_type, status, bucket, owner),
            )
            return int(cur.fetchone()[0])
        cur.execute(
            _sql(
                """INSERT INTO datasets (name, version, sha256, source_type, status, bucket, owner)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(name, version) DO UPDATE SET
                     sha256=excluded.sha256, status=excluded.status, bucket=excluded.bucket"""
            ),
            (name, version, sha256, source_type, status, bucket, owner),
        )
        cur.execute(_sql("SELECT id FROM datasets WHERE name=? AND version=?"), (name, version))
        return int(cur.fetchone()[0])


def mark_dataset_verified(name: str, version: str, sha256: str, *, signed: bool = False) -> None:
    with _tx(commit=True) as cur:
        cur.execute(
            _sql(
                """INSERT INTO verified_datasets (sha256, name, version, signed)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(sha256) DO UPDATE SET name=excluded.name, version=excluded.version"""
            ),
            (sha256, name, version, _bool_param(signed)),
        )


def register_model(name: str, version: str, *, tier: str, status: str, source: str,
                   owner: str, card: dict, sha256: Optional[str] = None,
                   approved_by: Optional[str] = None) -> int:
    """UPSERT models (реестр)."""
    with _tx(commit=True) as cur:
        if _is_pg():
            cur.execute(
                _sql(
                    """INSERT INTO models (name, version, tier, status, source, sha256, owner, approved_by, card)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT (name, version) DO UPDATE SET
                         tier=EXCLUDED.tier, status=EXCLUDED.status, source=EXCLUDED.source,
                         sha256=EXCLUDED.sha256, approved_by=EXCLUDED.approved_by, card=EXCLUDED.card
                       RETURNING id"""
                ),
                (name, version, tier, status, source, sha256, owner, approved_by, _json_param(card)),
            )
            return int(cur.fetchone()[0])
        cur.execute(
            _sql(
                """INSERT INTO models (name, version, tier, status, source, sha256, owner, approved_by, card)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(name, version) DO UPDATE SET
                     tier=excluded.tier, status=excluded.status, source=excluded.source,
                     sha256=excluded.sha256, approved_by=excluded.approved_by, card=excluded.card"""
            ),
            (name, version, tier, status, source, sha256, owner, approved_by, _json_param(card)),
        )
        cur.execute(_sql("SELECT id FROM models WHERE name=? AND version=?"), (name, version))
        return int(cur.fetchone()[0])


def add_model_version(model_name: str, version: str, *, dataset_name: Optional[str],
                      dataset_version: Optional[str], dataset_sha256: Optional[str],
                      git_sha: Optional[str], run_id: Optional[str],
                      trained_in_ci: bool, sha256: Optional[str], status: str) -> int:
    with _tx(commit=True) as cur:
        flag = trained_in_ci if _is_pg() else (1 if trained_in_ci else 0)
        if _is_pg():
            cur.execute(
                _sql(
                    """INSERT INTO model_versions
                       (model_name, version, dataset_name, dataset_version, dataset_sha256,
                        git_sha, run_id, trained_in_ci, sha256, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT (model_name, version) DO UPDATE SET
                         dataset_name=EXCLUDED.dataset_name, dataset_version=EXCLUDED.dataset_version,
                         dataset_sha256=EXCLUDED.dataset_sha256, git_sha=EXCLUDED.git_sha,
                         run_id=EXCLUDED.run_id, trained_in_ci=EXCLUDED.trained_in_ci,
                         sha256=EXCLUDED.sha256, status=EXCLUDED.status
                       RETURNING id"""
                ),
                (model_name, version, dataset_name, dataset_version, dataset_sha256,
                 git_sha, run_id, flag, sha256, status),
            )
            return int(cur.fetchone()[0])
        cur.execute(
            _sql(
                """INSERT INTO model_versions
                   (model_name, version, dataset_name, dataset_version, dataset_sha256,
                    git_sha, run_id, trained_in_ci, sha256, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(model_name, version) DO UPDATE SET
                     dataset_name=excluded.dataset_name, dataset_version=excluded.dataset_version,
                     dataset_sha256=excluded.dataset_sha256, git_sha=excluded.git_sha,
                     run_id=excluded.run_id, trained_in_ci=excluded.trained_in_ci,
                     sha256=excluded.sha256, status=excluded.status"""
            ),
            (model_name, version, dataset_name, dataset_version, dataset_sha256,
             git_sha, run_id, flag, sha256, status),
        )
        cur.execute(
            _sql("SELECT id FROM model_versions WHERE model_name=? AND version=?"),
            (model_name, version),
        )
        return int(cur.fetchone()[0])


def set_status(asset_type: str, name: str, version: str, status: str) -> None:
    table = "datasets" if asset_type == "dataset" else "models"
    with _tx(commit=True) as cur:
        cur.execute(
            _sql(f"UPDATE {table} SET status = ? WHERE name = ? AND version = ?"),
            (status, name, version),
        )


def get_model(name: str, version: str) -> Optional[dict]:
    with _tx() as cur:
        cur.execute(
            _sql(
                "SELECT name, version, tier, status, source, sha256, owner, approved_by, card "
                "FROM models WHERE name=? AND version=?"
            ),
            (name, version),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "name": row[0], "version": row[1], "tier": row[2], "status": row[3],
        "source": row[4], "sha256": row[5], "owner": row[6], "approved_by": row[7],
        "card": _json_load(row[8]),
    }


def list_registry() -> dict:
    with _tx() as cur:
        cur.execute(
            "SELECT name, version, sha256, status, bucket, owner FROM datasets ORDER BY id DESC"
        )
        datasets = [
            {"name": r[0], "version": r[1], "sha256": r[2], "status": r[3],
             "bucket": r[4], "owner": r[5]}
            for r in cur.fetchall()
        ]
        cur.execute(
            _sql(
                "SELECT name, version, tier, status, source, sha256, owner, approved_by "
                "FROM models ORDER BY id DESC"
            )
        )
        models = [
            {"name": r[0], "version": r[1], "tier": r[2], "status": r[3],
             "source": r[4], "sha256": r[5], "owner": r[6], "approved_by": r[7],
             "approvals_required": _hitl_required(r[2], r[4]),
             "approvals_count": hitl_approval_count(r[0], r[1])}
            for r in cur.fetchall()
        ]
    return {"datasets": datasets, "models": models}


def list_models_ui() -> list[dict]:
    """Модели в формате Streamlit UI (реестр Postgres/SQLite)."""
    with _tx() as cur:
        cur.execute(
            _sql(
                "SELECT m.name, m.version, m.tier, m.status, m.sha256, m.owner, m.source, "
                "mv.dataset_name, mv.dataset_version, mv.trained_in_ci, mv.git_sha, mv.run_id "
                "FROM models m "
                "LEFT JOIN model_versions mv ON m.name = mv.model_name AND m.version = mv.version "
                "ORDER BY m.id DESC"
            )
        )
        rows = cur.fetchall()
    out: list[dict] = []
    for r in rows:
        ds = f"{r[7]}@{r[8]}" if r[7] and r[8] else ""
        tci = bool(r[9]) if not _is_pg() else bool(r[9])
        out.append({
            "name": r[0],
            "version": r[1],
            "tier": r[2] or "MED",
            "status": r[3] or "registered",
            "sha256": r[4] or "",
            "owner": r[5] or "",
            "trained_in_ci": tci or (r[6] == "ci_trained"),
            "dataset": ds,
            "git_sha": r[10] or "",
            "run_id": r[11] or "",
        })
    return out


def list_model_versions_ui(model_name: str) -> list[dict]:
    """Версии модели для UI «Паспорт» / «Реестр»."""
    with _tx() as cur:
        cur.execute(
            _sql(
                "SELECT mv.version, mv.status, m.tier, m.owner, mv.dataset_name, mv.dataset_version, "
                "mv.git_sha, mv.run_id, mv.sha256, mv.trained_in_ci "
                "FROM model_versions mv "
                "JOIN models m ON m.name = mv.model_name AND m.version = mv.version "
                "WHERE mv.model_name = ? ORDER BY mv.id DESC"
            ),
            (model_name,),
        )
        rows = cur.fetchall()
    versions: list[dict] = []
    for r in rows:
        ds = f"{r[4]}@{r[5]}" if r[4] and r[5] else ""
        tci = bool(r[9]) if not _is_pg() else bool(r[9])
        versions.append({
            "version": r[0],
            "status": r[1] or "candidate",
            "tier": r[2] or "MED",
            "author": r[3] or "",
            "dataset": ds,
            "git_sha": r[6] or "",
            "run_id": r[7] or "",
            "sha256": r[8] or "",
            "accuracy": 0.0,
            "ts": "",
            "change": "",
            "approved_by": None,
            "approve_reason": None,
            "gates": {},
            "trained_in_ci": tci,
        })
    return versions


def set_finding_status(finding_id: int, status: str) -> None:
    assert status in {"open", "false_positive", "fixed"}, status
    with _tx(commit=True) as cur:
        cur.execute(_sql("UPDATE findings SET status = ? WHERE id = ?"), (status, finding_id))


def _hitl_required(tier: str, source: str) -> int:
    import os
    if source == "external":
        return int(os.getenv("HITL_APPROVALS_EXTERNAL", "2"))
    if (tier or "").upper() == "HIGH":
        return int(os.getenv("HITL_APPROVALS_HIGH", "2"))
    return int(os.getenv("HITL_APPROVALS_DEFAULT", "1"))


def hitl_approval_count(model_name: str, version: str) -> int:
    with _tx() as cur:
        cur.execute(
            _sql(
                "SELECT COUNT(DISTINCT approver) FROM hitl_approvals "
                "WHERE model_name=? AND version=?"
            ),
            (model_name, version),
        )
        row = cur.fetchone()
    return int(row[0]) if row else 0


def record_hitl_approval(model_name: str, version: str, approver: str,
                         reason: Optional[str] = None) -> int:
    with _tx(commit=True) as cur:
        try:
            cur.execute(
                _sql(
                    "INSERT INTO hitl_approvals (model_name, version, approver, reason) "
                    "VALUES (?, ?, ?, ?)"
                ),
                (model_name, version, approver, reason),
            )
        except Exception:
            pass
    return hitl_approval_count(model_name, version)


def try_finalize_hitl(model_name: str, version: str) -> Optional[str]:
    """Если набрано достаточно approve — перевести pending_hitl → approved."""
    m = get_model(model_name, version)
    if not m or m["status"] != "pending_hitl":
        return m["status"] if m else None
    need = _hitl_required(m["tier"], m["source"])
    have = hitl_approval_count(model_name, version)
    if have >= need:
        set_status("model", model_name, version, "approved")
        return "approved"
    return "pending_hitl"


# --- находки (общая сущность сработок) ---------------------------------------
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
    """INSERT в findings. severity ∈ {critical,high,medium,low}."""
    assert severity in {"critical", "high", "medium", "low"}, severity
    assert asset_type in {"dataset", "code", "model", "dependency", "runtime"}, asset_type
    with _tx(commit=True) as cur:
        if _is_pg():
            cur.execute(
                _sql(
                    """INSERT INTO findings (gate, asset_type, asset, rule, severity, evidence, status, run_no)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id"""
                ),
                (gate, asset_type, asset, rule, severity, _json_param(evidence), status, run_no),
            )
            return int(cur.fetchone()[0])
        cur.execute(
            _sql(
                """INSERT INTO findings (gate, asset_type, asset, rule, severity, evidence, status, run_no)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""
            ),
            (gate, asset_type, asset, rule, severity, _json_param(evidence), status, run_no),
        )
        return int(cur.lastrowid)


def list_findings(*, status: Optional[str] = None, limit: int = 200) -> list[dict]:
    """Список находок для UI (новые сверху)."""
    q = "SELECT id, gate, asset_type, asset, rule, severity, evidence, status, run_no, ts FROM findings"
    params: list = []
    if status:
        q += " WHERE status = ?"
        params.append(status)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with _tx() as cur:
        cur.execute(_sql(q), tuple(params))
        rows = cur.fetchall()
    out: list[dict] = []
    for r in rows:
        out.append({
            "id": r[0],
            "gate": r[1],
            "asset_type": r[2],
            "asset": r[3],
            "rule": r[4],
            "severity": r[5],
            "evidence": _json_load(r[6]),
            "status": r[7],
            "run_no": r[8],
            "ts": r[9],
        })
    return out


_GATE_ASSET_TYPE = {
    "G1": "dataset",
    "G2": "code",
    "G3": "dependency",
    "G4": "model",
    "G5": "model",
}


def asset_type_for_gate(gate: str) -> str:
    return _GATE_ASSET_TYPE.get(gate, "code")


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


def mark_false_positive(finding_id: int, marked_by: str, reason: str) -> None:
    """Отметить находку как false_positive (только MLSecOps)."""
    with _tx(commit=True) as cur:
        cur.execute(
            _sql(
                "UPDATE findings SET status = 'false_positive', marked_by = ? WHERE id = ?"
            ),
            (marked_by, finding_id),
        )


# --- RBAC --------------------------------------------------------------------
def register_user(username: str, email: Optional[str] = None,
                  password_hash: Optional[str] = None) -> int:
    """Создать пользователя (идемпотентно по username). Вернуть его id.

    password_hash — bcrypt-хэш (считается в core.identity), НЕ сырой пароль.
    Если пользователь уже есть — вернуть существующий id (без перезаписи).
    """
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?) "
                 "ON CONFLICT (username) DO NOTHING"),
            (username, email, password_hash),
        )
        cur.execute(_sql("SELECT id FROM users WHERE username = ?"), (username,))
        return int(cur.fetchone()[0])


def get_user(username: str) -> Optional[dict]:
    """Вернуть пользователя {id, username, email, password_hash} или None."""
    with _tx() as cur:
        cur.execute(
            _sql("SELECT id, username, email, password_hash FROM users WHERE username = ?"),
            (username,))
        row = cur.fetchone()
    if not row:
        return None
    return {"id": int(row[0]), "username": row[1], "email": row[2], "password_hash": row[3]}


def set_password(username: str, password_hash: str) -> None:
    """Обновить bcrypt-хэш пароля пользователя."""
    with _tx(commit=True) as cur:
        cur.execute(_sql("UPDATE users SET password_hash = ? WHERE username = ?"),
                    (password_hash, username))


def list_users() -> list[dict]:
    """Список всех пользователей с их ролями (для админки)."""
    with _tx() as cur:
        cur.execute("SELECT id, username, email FROM users ORDER BY id")
        users = [{"id": int(r[0]), "username": r[1], "email": r[2]} for r in cur.fetchall()]
        for u in users:
            cur.execute(_sql("SELECT role FROM roles WHERE user_id = ?"), (u["id"],))
            u["roles"] = sorted(r[0] for r in cur.fetchall())
    return users


def assign_role(user_id: int, role: str) -> None:
    """Назначить роль пользователю (идемпотентно)."""
    assert role in {"DS", "DE", "MLSecOps", "Product", "CEO"}, role
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("INSERT INTO roles (user_id, role) VALUES (?, ?) "
                 "ON CONFLICT (user_id, role) DO NOTHING"),
            (user_id, role),
        )


def revoke_role(user_id: int, role: str) -> None:
    """Снять роль с пользователя."""
    with _tx(commit=True) as cur:
        cur.execute(_sql("DELETE FROM roles WHERE user_id = ? AND role = ?"), (user_id, role))


def get_roles(username: str) -> set[str]:
    """Роли пользователя по username. Пустое множество, если юзера/ролей нет."""
    with _tx() as cur:
        cur.execute(
            _sql("SELECT r.role FROM roles r JOIN users u ON u.id = r.user_id "
                 "WHERE u.username = ?"),
            (username,))
        return {row[0] for row in cur.fetchall()}


def grant_access(user_id: int, dataset_name: str, dataset_version: str,
                 *, can_export: bool, granted_by: str) -> None:
    """Выдать доступ к датасету (идемпотентно; обновляет can_export)."""
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("""INSERT INTO dataset_access
                    (user_id, dataset_name, dataset_version, can_export, granted_by)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (user_id, dataset_name, dataset_version)
                    DO UPDATE SET can_export = excluded.can_export"""),
            (user_id, dataset_name, dataset_version, _bool_param(can_export), granted_by),
        )


def has_dataset_access(user_id: int, dataset_name: str, dataset_version: str) -> bool:
    """Есть ли у пользователя запись доступа к датасету."""
    with _tx() as cur:
        cur.execute(
            _sql("SELECT 1 FROM dataset_access "
                 "WHERE user_id = ? AND dataset_name = ? AND dataset_version = ?"),
            (user_id, dataset_name, dataset_version))
        return cur.fetchone() is not None


# --- демо/самопроверка -------------------------------------------------------
if __name__ == "__main__":
    # Короткий сценарий: чистая sqlite-БД → регистрация → роль → доступ →
    # запись событий в hash-chain → проверка целостности → имитация подделки.
    import tempfile

    SQLITE_PATH = str(Path(tempfile.gettempdir()) / "mlsec_db_demo.db")
    if Path(SQLITE_PATH).exists():
        Path(SQLITE_PATH).unlink()

    print(f"DB_BACKEND={DB_BACKEND}  file={SQLITE_PATH}\n")
    init_db()

    # 1) Регистрация пользователя + роль DS
    uid = register_user("ivanov", "ivanov@example.com", password_hash="<bcrypt-hash-here>")
    assign_role(uid, "DS")
    print(f"1) register_user('ivanov') -> id={uid}")
    print(f"   get_roles('ivanov') = {get_roles('ivanov')}")
    print(f"   get_user('ivanov')  = {get_user('ivanov')}")

    # 2) Идемпотентность: повторная регистрация не плодит дублей
    uid2 = register_user("ivanov", "ivanov@example.com")
    print(f"\n2) повторный register_user -> id={uid2} (тот же: {uid == uid2})")

    # 3) Выдача доступа к датасету
    grant_access(uid, "fraud_logs", "v1", can_export=False, granted_by="msecops")
    print(f"\n3) has_dataset_access(fraud_logs@v1) = "
          f"{has_dataset_access(uid, 'fraud_logs', 'v1')}")
    print(f"   has_dataset_access(other@v1)      = "
          f"{has_dataset_access(uid, 'other', 'v1')}")

    # 4) Audit Trail: несколько событий → проверка цепочки
    log_event("msecops", "MLSecOps", "user_registered", asset="ivanov", result="ok",
              reason="онбординг DS")
    log_event("msecops", "MLSecOps", "role_assigned", asset="ivanov", result="ok",
              reason="выдана роль DS", details={"role": "DS"})
    log_event("ivanov", "DS", "login", result="ok")
    chk = verify_chain()
    print(f"\n4) записано 3 события; verify_chain() = {chk}")

    # 5) Имитация подделки лога: меняем reason в одной строке напрямую (в обход log_event)
    conn = get_conn()
    conn.execute("UPDATE events SET reason = 'ПОДДЕЛКА' WHERE id = 2")
    conn.commit()
    conn.close()
    chk2 = verify_chain()
    print(f"5) после ручной правки строки id=2: verify_chain() = {chk2}")
    print(f"   -> разрыв цепочки обнаружен на id={chk2['broken_at']}: "
          f"{'OK, защита работает' if not chk2['ok'] else 'ОШИБКА: подделка не замечена'}")
