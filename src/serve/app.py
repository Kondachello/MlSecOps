"""G7 Runtime Gate — прод-инференс (FastAPI) с runtime-защитой.

Защиты (docs/13_RUNTIME_AND_MONITORING.md §13.2):
  - rate-limit (Redis) → 429        (#5 extraction, #6 DoS)
  - Pydantic-валидация → 422        (#6, #11 evasion)
  - лимит размера payload → 413
  - output reduction                (#5, #13 membership)
  - DLP в логах                     (#12)

Один сервис на модель (масштабируемость). Скелет: контракты есть, реализация TODO.
"""
from __future__ import annotations

import os
import re

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except Exception:  # graceful для py_compile
    FastAPI = None  # type: ignore

    class BaseModel:  # type: ignore
        pass

    def Field(*a, **k):  # type: ignore
        return None

RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "100"))
MAX_PAYLOAD_BYTES = int(os.getenv("MAX_PAYLOAD_BYTES", str(64 * 1024)))

# DLP-маски для логов
RE_CARD = re.compile(r"\b(\d{4})[ -]?\d{4}[ -]?\d{4}[ -]?(\d{4})\b")
RE_EMAIL = re.compile(r"([\w.+-])[\w.+-]*@([\w-]+\.[\w.-]+)")


class ScoreRequest(BaseModel):  # type: ignore[misc]
    """Строгая схема входа (пример для табличного скоринга). Нарушение → 422."""
    amount: float = Field(gt=0)                       # #11 evasion: amount>0
    age: int = Field(ge=0, le=120)                    # 0..120
    text: str = Field(default="", max_length=500)     # #6 DoS: лимит длины


def dlp_mask(s: str) -> str:
    """Маскировать ПДн перед записью в лог (#12)."""
    s = RE_CARD.sub(r"\1-****-****-\2", s)
    s = RE_EMAIL.sub(r"\1***@\2", s)
    return s


def reduce_output(proba: float) -> dict:
    """Output reduction (#5/#13): отдаём решение/округление, НЕ сырые вероятности."""
    return {"decision": "approve" if proba >= 0.5 else "decline"}


def rate_limited(api_key: str) -> bool:
    """Redis-счётчик по ключу/IP: >RATE_LIMIT_PER_MIN/min → True (→429). TODO: INCR+EXPIRE."""
    raise NotImplementedError("TODO: Redis rate-limit")


app = FastAPI(title="MLSecOps Inference (G7)") if FastAPI else None

if app:
    @app.middleware("http")
    async def guard(request: Request, call_next):
        # 1. лимит размера payload → 413; 2. rate-limit → 429 (TODO).
        # 3. DLP применяется при логировании запроса/ответа.
        return await call_next(request)  # TODO: реализовать проверки

    @app.post("/predict")
    def predict(req: ScoreRequest):
        """Инференс. TODO: загрузка модели (проверенной/подписанной), reduce_output, DLP-лог."""
        # proba = model.predict_proba(...)  # TODO
        return JSONResponse(reduce_output(0.0))

    @app.get("/health")
    def health():
        return {"status": "ok"}
