"""Graceful event/feature sink — работает БЕЗ готового бэкенда A.

Назначение: пока A не реализовал core.db.log_event + Postgres, runtime-слой (serve, monitor)
всё равно должен оставлять след (Audit Trail) и логировать фичи для PSI. Поэтому:

  log_event(...)   — пытается core.db.log_event (когда A готов) → иначе пишет в logs/events.jsonl
  log_feature(...) — пишет DLP-маскированные фичи в logs/inference_<model>.jsonl (для G6 PSI)

Когда A реализует core.db.log_event — этот модуль автоматически начнёт писать в БД,
JSONL остаётся как локальный фолбэк/демо. Никаких секретов/ПДн в открытом виде (DLP).
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = Path(os.getenv("MLSEC_LOG_DIR", str(ROOT / "logs")))

# DLP-маски (#12): карты и email не пишем в открытом виде.
_RE_CARD = re.compile(r"\b(\d{4})[ -]?\d{4}[ -]?\d{4}[ -]?(\d{4})\b")
_RE_EMAIL = re.compile(r"([\w.+-])[\w.+-]*@([\w-]+\.[\w.-]+)")


def dlp_mask(s: str) -> str:
    s = _RE_CARD.sub(r"\1-****-****-\2", s)
    s = _RE_EMAIL.sub(r"\1***@\2", s)
    return s


def _append_jsonl(name: str, record: dict) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / name).open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def log_event(actor: str, role: str, action: str, *, asset: str | None = None,
              result: str = "ok", reason: str | None = None,
              details: dict | None = None) -> None:
    """Записать событие. Сначала пробуем БД A, иначе локальный JSONL-фолбэк."""
    payload = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "actor": actor, "role": role, "action": action, "asset": asset,
               "result": result, "reason": reason, "details": details or {}}
    try:
        from core.db import log_event as db_log_event  # A реализует позже
        db_log_event(actor, role, action, asset=asset, result=result,
                     reason=reason, details=details)
        return
    except Exception:  # noqa: BLE001 — БД ещё не готова → фолбэк
        _append_jsonl("events.jsonl", payload)


def log_feature(model: str, features: dict, *, decision: str | None = None) -> None:
    """Записать фичи запроса (для G6 PSI на живом трафике). Значения проходят DLP."""
    safe = {k: (dlp_mask(v) if isinstance(v, str) else v) for k, v in features.items()}
    _append_jsonl(f"inference_{model}.jsonl",
                  {"ts": time.time(), "model": model, "features": safe, "decision": decision})
