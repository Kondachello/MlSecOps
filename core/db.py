"""
Доступ к БД + хелпер log_event() — сердце платформы.

ВСЕ сервисы (ingest, гейты, деплой, UI) пишут историю только через log_event().
Каждое событие связывается в hash-chain: row_hash = sha256(prev_hash + payload),
поэтому подделать/удалить запись из середины нельзя незаметно (угроза #24).

Использование:
    from platform.db import log_event, fetch_events
    log_event("alice", "DS", "dataset_uploaded", asset="train.csv",
              result="ok", details={"rows": 10000})
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from typing import Any

import psycopg2
import psycopg2.extras


def _conn_params() -> dict[str, Any]:
    return dict(
        host=os.getenv("PG_HOST", "localhost"),
        port=int(os.getenv("PG_PORT", "5432")),
        user=os.getenv("PG_USER", "mlsecops"),
        password=os.getenv("PG_PASSWORD", "mlsecops"),
        dbname=os.getenv("PG_DATABASE", "mlsecops"),
    )


@contextmanager
def get_conn():
    """Контекстный менеджер соединения с авто-commit/rollback."""
    conn = psycopg2.connect(**_conn_params())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _row_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    """Детерминированный хеш строки на основе предыдущего (звено цепочки)."""
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def log_event(
    actor: str,
    role: str,
    action: str,
    *,
    asset: str | None = None,
    result: str = "ok",
    details: dict[str, Any] | None = None,
) -> int:
    """Записать событие в историю. Возвращает id новой строки."""
    details = details or {}
    with get_conn() as conn:
        with conn.cursor() as cur:
            # берём хеш последней записи (звено цепочки)
            cur.execute("SELECT row_hash FROM events ORDER BY id DESC LIMIT 1;")
            row = cur.fetchone()
            prev_hash = row[0] if row else ""

            payload = {
                "actor": actor,
                "role": role,
                "action": action,
                "asset": asset,
                "result": result,
                "details": details,
                "prev_hash": prev_hash,
            }
            rhash = _row_hash(prev_hash, payload)

            cur.execute(
                """
                INSERT INTO events
                    (actor, role, action, asset, result, details, prev_hash, row_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (actor, role, action, asset, result,
                 json.dumps(details, ensure_ascii=False), prev_hash, rhash),
            )
            return cur.fetchone()[0]


def fetch_events(limit: int = 200) -> list[dict[str, Any]]:
    """Последние события (для UI)."""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, ts, actor, role, action, asset, result, details "
                "FROM events ORDER BY id DESC LIMIT %s;",
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]


def verify_chain() -> tuple[bool, int | None]:
    """
    Проверка целостности hash-chain (#24).
    Возвращает (ok, id_первой_битой_строки). Если ok=True — цепочка цела.
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, actor, role, action, asset, result, details, "
                "prev_hash, row_hash FROM events ORDER BY id ASC;"
            )
            prev = ""
            for r in cur.fetchall():
                payload = {
                    "actor": r["actor"], "role": r["role"], "action": r["action"],
                    "asset": r["asset"], "result": r["result"],
                    "details": r["details"], "prev_hash": prev,
                }
                if _row_hash(prev, payload) != r["row_hash"] or r["prev_hash"] != prev:
                    return False, r["id"]
                prev = r["row_hash"]
    return True, None
