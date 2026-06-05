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
    # timeout/busy_timeout: устойчивость к конкуренции (Streamlit + backend + сиды пишут параллельно).
    # WAL НЕ включаем глобально — на части ФС (сетевые/смонтированные) WAL даёт "disk I/O error".
    conn = sqlite3.connect(SQLITE_PATH, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.execute("PRAGMA busy_timeout = 10000")
    except Exception:  # noqa: BLE001
        pass
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
CREATE TABLE IF NOT EXISTS experiment_owner (
    experiment_id TEXT PRIMARY KEY,       -- MLflow experiment_id
    owner         TEXT NOT NULL,          -- первый писатель = владелец (серверный штамп прокси)
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS artifact_acl (
    run_id        TEXT PRIMARY KEY,       -- MLflow run = «сессия разработки» (data+код+модель)
    experiment_id TEXT NOT NULL,
    owner         TEXT NOT NULL,          -- кто залогировал ран (серверный штамп прокси)
    session_name  TEXT,
    check_status  TEXT NOT NULL DEFAULT 'none'
                  CHECK (check_status IN ('none','pending','passed','failed')),
    check_detail  TEXT,                   -- JSON: результат security check (цепочка гейтов)
    tier          TEXT,                   -- LOW|MED|HIGH (проставляется на security check; HIGH → HITL)
    stage         TEXT NOT NULL DEFAULT 'none'
                  CHECK (stage IN ('none','pending_approve','approved','prod','previous','retired')),
    approved_by   TEXT,                   -- кто подтвердил (HITL, для Tier=HIGH)
    deployed_by   TEXT,                   -- кто инициировал выкатку/перевёл в прод
    share_status  TEXT NOT NULL DEFAULT 'private'
                  CHECK (share_status IN ('private','shared')),
    share_level   INTEGER,                -- клиренс-уровень видимости (NULL пока приватный)
    share_roles   TEXT,                   -- JSON-список кастомных ролей (переопределяет share_level)
    shared_by     TEXT,
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at    TEXT DEFAULT CURRENT_TIMESTAMP
);
"""

# Колонки artifact_acl, добавленные после первого релиза (для миграции существующих sqlite-БД).
# Postgres-схему (infra/init.sql) держим в синхроне вручную.
_ACL_MIGRATIONS = [
    ("tier", "TEXT"),
    ("stage", "TEXT NOT NULL DEFAULT 'none'"),
    ("approved_by", "TEXT"),
    ("deployed_by", "TEXT"),
]


def init_db() -> None:
    """Создать схему для SQLite-дев (идемпотентно). В Postgres схему ставит init.sql."""
    if _is_pg():
        return  # схема уже применена docker-entrypoint'ом из infra/init.sql
    conn = get_conn()
    try:
        conn.executescript(_SQLITE_SCHEMA)
        # Лёгкая миграция: для уже существующих БД добавляем недостающие колонки artifact_acl.
        cur = conn.execute("PRAGMA table_info(artifact_acl)")
        have = {row[1] for row in cur.fetchall()}
        for col, decl in _ACL_MIGRATIONS:
            if col not in have:
                conn.execute(f"ALTER TABLE artifact_acl ADD COLUMN {col} {decl}")
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
    """INSERT в datasets (онбординг датасета). Идемпотентно по (name, version)."""
    assert source_type in {"local", "internet", "corp_storage", "verified_id"}, source_type
    assert status in {"registered", "available", "quarantine", "prod_locked"}, status
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("""INSERT INTO datasets (name, version, sha256, source_type, status, bucket, owner)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (name, version) DO UPDATE SET
                        sha256 = excluded.sha256, status = excluded.status"""),
            (name, version, sha256, source_type, status, bucket, owner))
        cur.execute(_sql("SELECT id FROM datasets WHERE name = ? AND version = ?"),
                    (name, version))
        return int(cur.fetchone()[0])


def register_model(name: str, version: str, *, tier: str, status: str, source: str,
                   owner: str, card: dict, sha256: Optional[str] = None) -> int:
    """Зарегистрировать модель в реестре (Postgres/sqlite). Идемпотентно по (name, version).

    Прогон G5 (registry_gate) и регистрация в MLflow Registry — на стороне оркестратора
    (вызывающего), здесь — только запись в реестр БД.
    """
    assert tier in {"LOW", "MED", "HIGH"}, tier
    assert source in {"ci_trained", "external"}, source
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("""INSERT INTO models (name, version, tier, status, source, sha256, owner, card)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (name, version) DO UPDATE SET
                        tier = excluded.tier, status = excluded.status, sha256 = excluded.sha256,
                        card = excluded.card"""),
            (name, version, tier, status, source, sha256, owner, _json_param(card)))
        cur.execute(_sql("SELECT id FROM models WHERE name = ? AND version = ?"),
                    (name, version))
        return int(cur.fetchone()[0])


def add_model_version(model_name: str, version: str, *, dataset_name: Optional[str],
                      dataset_version: Optional[str], dataset_sha256: Optional[str],
                      git_sha: Optional[str], run_id: Optional[str],
                      trained_in_ci: bool, sha256: Optional[str], status: str) -> int:
    """INSERT в model_versions (lineage). trained_in_ci проставляет CI, не клиент."""
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("""INSERT INTO model_versions
                    (model_name, version, dataset_name, dataset_version, dataset_sha256,
                     git_sha, run_id, trained_in_ci, sha256, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (model_name, version) DO UPDATE SET
                        dataset_name = excluded.dataset_name, dataset_version = excluded.dataset_version,
                        dataset_sha256 = excluded.dataset_sha256, git_sha = excluded.git_sha,
                        run_id = excluded.run_id, sha256 = excluded.sha256, status = excluded.status"""),
            (model_name, version, dataset_name, dataset_version, dataset_sha256, git_sha,
             run_id, 1 if trained_in_ci else 0, sha256, status))
        cur.execute(_sql("SELECT id FROM model_versions WHERE model_name = ? AND version = ?"),
                    (model_name, version))
        return int(cur.fetchone()[0])


def set_status(asset_type: str, name: str, version: str, status: str) -> None:
    """Сменить статус актива в реестре. log_event пишет вызывающий (оркестратор/API)."""
    table = {"dataset": "datasets", "model": "models"}.get(asset_type)
    if table is None:
        raise ValueError(f"unknown asset_type {asset_type!r}")
    with _tx(commit=True) as cur:
        cur.execute(
            _sql(f"UPDATE {table} SET status = ? WHERE name = ? AND version = ?"),
            (status, name, version))


def list_models() -> list[dict]:
    """Все модели реестра БД с их версией/Tier/статусом (для UI «Реестр», БД-ветка)."""
    with _tx() as cur:
        cur.execute("SELECT name, version, tier, status, source, owner, approved_by, created_at "
                    "FROM models ORDER BY name, version")
        return [{"name": r[0], "version": r[1], "tier": r[2], "status": r[3],
                 "source": r[4], "owner": r[5], "approved_by": r[6], "created_at": r[7]}
                for r in cur.fetchall()]


# --- находки / инциденты (авто из упавших гейтов) ----------------------------
def add_finding(gate: str, asset_type: str, asset: str, rule: str, severity: str,
                evidence: dict, *, run_no: int = 1, status: str = "open") -> int:
    """INSERT в findings (инцидент от гейта). severity ∈ {critical,high,medium,low}."""
    assert severity in {"critical", "high", "medium", "low"}, severity
    assert asset_type in {"dataset", "code", "model", "dependency", "runtime"}, asset_type
    assert status in {"open", "false_positive", "fixed"}, status
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("""INSERT INTO findings
                    (gate, asset_type, asset, rule, severity, evidence, status, run_no)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""),
            (gate, asset_type, asset, rule, severity, _json_param(evidence), status, run_no))
        cur.execute("SELECT last_insert_rowid()" if not _is_pg() else "SELECT lastval()")
        return int(cur.fetchone()[0])


def list_findings(*, status: Optional[str] = None, asset: Optional[str] = None,
                  limit: int = 200) -> list[dict]:
    """Инциденты (находки гейтов), новые сверху. Опц. фильтры по статусу/активу."""
    where, params = [], []
    if status:
        where.append("status = ?")
        params.append(status)
    if asset:
        where.append("asset = ?")
        params.append(asset)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with _tx() as cur:
        cur.execute(
            _sql("SELECT id, ts, gate, asset_type, asset, rule, severity, evidence, "
                 "status, marked_by, run_no FROM findings" + clause +
                 " ORDER BY id DESC LIMIT " + str(int(limit))),
            tuple(params))
        rows = cur.fetchall()
    return [{"id": int(r[0]), "ts": r[1], "gate": r[2], "asset_type": r[3], "asset": r[4],
             "rule": r[5], "severity": r[6], "evidence": _json_load(r[7]),
             "status": r[8], "marked_by": r[9], "run_no": int(r[10] or 1)} for r in rows]


def clear_findings_for_asset(asset: str) -> None:
    """Удалить открытые инциденты актива перед повторным security check (чтобы не плодить дубли)."""
    with _tx(commit=True) as cur:
        cur.execute(_sql("DELETE FROM findings WHERE asset = ? AND status = 'open'"), (asset,))


def mark_false_positive(finding_id: int, marked_by: str, reason: str) -> None:
    """Отметить находку как false_positive (только MLSecOps). log_event пишет вызывающий."""
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("UPDATE findings SET status = 'false_positive', marked_by = ? WHERE id = ?"),
            (marked_by, finding_id))


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
            (user_id, dataset_name, dataset_version, 1 if can_export else 0, granted_by),
        )


def has_dataset_access(user_id: int, dataset_name: str, dataset_version: str) -> bool:
    """Есть ли у пользователя запись доступа к датасету."""
    with _tx() as cur:
        cur.execute(
            _sql("SELECT 1 FROM dataset_access "
                 "WHERE user_id = ? AND dataset_name = ? AND dataset_version = ?"),
            (user_id, dataset_name, dataset_version))
        return cur.fetchone() is not None


# --- владение и ACL артефактов MLflow (приватность + контролируемый шаринг) ---
# Единица владения — эксперимент на разработчика; единица шаринга — ран (сессия
# разработки: data+код+модель в одном ноутбуке). Владелец проставляется СЕРВЕРНО
# (auth-прокси штампует X-Authenticated-User → owner). См. docs/18_MLFLOW.md.
def set_experiment_owner(experiment_id: str, owner: str) -> None:
    """Зафиксировать владельца эксперимента (первый писатель; идемпотентно, без перезаписи)."""
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("INSERT INTO experiment_owner (experiment_id, owner) VALUES (?, ?) "
                 "ON CONFLICT (experiment_id) DO NOTHING"),
            (experiment_id, owner))


def get_experiment_owner(experiment_id: str) -> Optional[str]:
    """Владелец эксперимента или None."""
    with _tx() as cur:
        cur.execute(_sql("SELECT owner FROM experiment_owner WHERE experiment_id = ?"),
                    (experiment_id,))
        row = cur.fetchone()
    return row[0] if row else None


def list_owned_experiments(owner: str) -> set[str]:
    """experiment_id всех экспериментов, которыми владеет пользователь."""
    with _tx() as cur:
        cur.execute(_sql("SELECT experiment_id FROM experiment_owner WHERE owner = ?"),
                    (owner,))
        return {r[0] for r in cur.fetchall()}


def upsert_artifact(run_id: str, experiment_id: str, owner: str,
                    session_name: Optional[str] = None) -> None:
    """Зарегистрировать ран (сессию) в ACL при первом появлении (владелец не перезаписывается).

    Идемпотентно: если запись есть — обновляем только session_name (если передан).
    """
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("""INSERT INTO artifact_acl (run_id, experiment_id, owner, session_name)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT (run_id) DO UPDATE SET
                        session_name = COALESCE(excluded.session_name, artifact_acl.session_name)"""),
            (run_id, experiment_id, owner, session_name))


def upsert_artifacts_bulk(rows: list[tuple]) -> None:
    """Пакетно зарегистрировать раны в ACL ОДНОЙ транзакцией (rows = [(run_id, exp_id, owner, name)]).

    Нужно для ленивой регистрации при листинге: иначе N×(connect+commit) на Windows
    легко перевалит за таймаут UI. Владелец существующих строк не перезаписывается.
    """
    if not rows:
        return
    with _tx(commit=True) as cur:
        cur.executemany(
            _sql("""INSERT INTO artifact_acl (run_id, experiment_id, owner, session_name)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT (run_id) DO UPDATE SET
                        session_name = COALESCE(excluded.session_name, artifact_acl.session_name)"""),
            rows)


def _acl_row_to_dict(r) -> dict:
    return {
        "run_id": r[0], "experiment_id": r[1], "owner": r[2], "session_name": r[3],
        "check_status": r[4], "check_detail": _json_load(r[5]),
        "tier": r[6], "stage": r[7] or "none", "approved_by": r[8], "deployed_by": r[9],
        "share_status": r[10], "share_level": r[11],
        "share_roles": _json_load(r[12]), "shared_by": r[13],
    }


_ACL_COLS = ("run_id, experiment_id, owner, session_name, check_status, check_detail, "
             "tier, stage, approved_by, deployed_by, "
             "share_status, share_level, share_roles, shared_by")


def get_artifact_acl(run_id: str) -> Optional[dict]:
    """ACL артефакта (рана) или None, если он ещё не зарегистрирован."""
    with _tx() as cur:
        cur.execute(_sql(f"SELECT {_ACL_COLS} FROM artifact_acl WHERE run_id = ?"), (run_id,))
        row = cur.fetchone()
    return _acl_row_to_dict(row) if row else None


def list_artifact_acls(run_ids: Optional[list[str]] = None) -> dict[str, dict]:
    """ACL по списку run_id (или все, если run_ids=None) → {run_id: acl}."""
    with _tx() as cur:
        if run_ids is None:
            cur.execute(_sql(f"SELECT {_ACL_COLS} FROM artifact_acl"))
        elif not run_ids:
            return {}
        else:
            ph = ",".join("?" * len(run_ids))
            cur.execute(_sql(f"SELECT {_ACL_COLS} FROM artifact_acl WHERE run_id IN ({ph})"),
                        tuple(run_ids))
        rows = cur.fetchall()
    return {r[0]: _acl_row_to_dict(r) for r in rows}


def list_shared_acls() -> list[dict]:
    """Все расшаренные артефакты (для вычисления видимых экспериментов на прокси)."""
    with _tx() as cur:
        cur.execute(_sql(f"SELECT {_ACL_COLS} FROM artifact_acl WHERE share_status = 'shared'"))
        return [_acl_row_to_dict(r) for r in cur.fetchall()]


def set_check_status(run_id: str, status: str, detail: Optional[dict] = None) -> None:
    """Записать результат security check артефакта (none|pending|passed|failed)."""
    assert status in {"none", "pending", "passed", "failed"}, status
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("UPDATE artifact_acl SET check_status = ?, check_detail = ?, "
                 "updated_at = CURRENT_TIMESTAMP WHERE run_id = ?"),
            (status, _json_param(detail), run_id))


def set_artifact_tier(run_id: str, tier: Optional[str]) -> None:
    """Проставить Tier артефакта (LOW|MED|HIGH); считается на security check."""
    if tier is not None:
        assert tier in {"LOW", "MED", "HIGH"}, tier
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("UPDATE artifact_acl SET tier = ?, updated_at = CURRENT_TIMESTAMP "
                 "WHERE run_id = ?"),
            (tier, run_id))


def set_artifact_stage(run_id: str, stage: str, *, approved_by: Optional[str] = None,
                       deployed_by: Optional[str] = None) -> None:
    """Сменить стадию жизненного цикла артефакта (выкатка/прод/откат).

    stage ∈ {none, pending_approve, approved, prod, previous, retired}.
    Реального CI-деплоя нет (плейсхолдер) — но движение по стадиям персистится и видно
    в реестре/на дашборде. log_event пишет вызывающий (API).
    """
    assert stage in {"none", "pending_approve", "approved", "prod", "previous", "retired"}, stage
    sets = ["stage = ?", "updated_at = CURRENT_TIMESTAMP"]
    params: list = [stage]
    if approved_by is not None:
        sets.insert(1, "approved_by = ?")
        params.append(approved_by)
    if deployed_by is not None:
        sets.insert(1, "deployed_by = ?")
        params.append(deployed_by)
    params.append(run_id)
    with _tx(commit=True) as cur:
        cur.execute(_sql(f"UPDATE artifact_acl SET {', '.join(sets)} WHERE run_id = ?"),
                    tuple(params))


def demote_prod_artifacts(experiment_id: str, except_run_id: str) -> list[str]:
    """Перевести все prod-артефакты эксперимента (кроме нового) в 'previous'. Вернуть их run_id.

    Используется при промоушене нового артефакта в прод: в проде эксперимента — один активный.
    """
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("SELECT run_id FROM artifact_acl WHERE experiment_id = ? AND stage = 'prod' "
                 "AND run_id != ?"),
            (experiment_id, except_run_id))
        demoted = [r[0] for r in cur.fetchall()]
        if demoted:
            cur.execute(
                _sql("UPDATE artifact_acl SET stage = 'previous', updated_at = CURRENT_TIMESTAMP "
                     "WHERE experiment_id = ? AND stage = 'prod' AND run_id != ?"),
                (experiment_id, except_run_id))
    return demoted


def share_artifact(run_id: str, *, level: Optional[int], roles: Optional[list[str]],
                   shared_by: str) -> None:
    """Расшарить артефакт: либо по клиренс-уровню (level), либо кастомным ролям (roles).

    Контроль «прошёл ли security check» — на стороне вызывающего (API).
    """
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("UPDATE artifact_acl SET share_status = 'shared', share_level = ?, "
                 "share_roles = ?, shared_by = ?, updated_at = CURRENT_TIMESTAMP "
                 "WHERE run_id = ?"),
            (level, _json_param(roles) if roles else None, shared_by, run_id))


def unshare_artifact(run_id: str) -> None:
    """Снять шаринг — артефакт снова приватный (виден только владельцу)."""
    with _tx(commit=True) as cur:
        cur.execute(
            _sql("UPDATE artifact_acl SET share_status = 'private', share_level = NULL, "
                 "share_roles = NULL, updated_at = CURRENT_TIMESTAMP WHERE run_id = ?"),
            (run_id,))


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

    # 6) ACL артефактов MLflow: владение → security check → шаринг → видимость.
    # Политику видимости дублируем локально (полная версия — core.identity.can_view_artifact),
    # чтобы демо запускалось и как `python core/db.py`, и как `python -m core.db`.
    _lvl = {"DS": 1, "DE": 1, "Product": 2, "MLSecOps": 3, "CEO": 4}

    def _can_view(acl, user, roles):
        if acl.get("owner") == user:
            return True
        if acl.get("share_status") != "shared":
            return False
        if acl.get("share_roles"):
            return any(r in acl["share_roles"] for r in roles)
        return max((_lvl.get(r, 0) for r in roles), default=0) >= (acl.get("share_level") or 0)

    set_experiment_owner("exp-1", "vasya")          # эксперимент vasya
    upsert_artifact("run-1", "exp-1", "vasya", "fraud-session")
    print(f"\n6) artifact_acl(run-1) = {get_artifact_acl('run-1')['share_status']}/"
          f"{get_artifact_acl('run-1')['check_status']} (приватный, не проверен)")
    print(f"   petya(DS) видит приватный run-1: "
          f"{_can_view(get_artifact_acl('run-1'), 'petya', ['DS'])} (ожидаем False)")
    set_check_status("run-1", "passed", {"passed": True, "placeholder": True})
    share_artifact("run-1", level=1, roles=None, shared_by="vasya")
    acl = get_artifact_acl("run-1")
    print(f"   после check+share(L{acl['share_level']}): petya(DS) видит = "
          f"{_can_view(acl, 'petya', ['DS'])} (ожидаем True);  "
          f"ceo видит = {_can_view(acl, 'ceo', ['CEO'])} (ожидаем True)")
    upsert_artifact("run-2", "exp-1", "vasya", "secret-session")
    set_check_status("run-2", "passed")
    share_artifact("run-2", level=None, roles=["Product"], shared_by="vasya")
    acl2 = get_artifact_acl("run-2")
    print(f"   кастомный шаринг run-2 ролям {acl2['share_roles']}: "
          f"DS видит = {_can_view(acl2, 'x', ['DS'])} (False), "
          f"Product видит = {_can_view(acl2, 'x', ['Product'])} (True)")
