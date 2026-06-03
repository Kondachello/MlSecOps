"""G7 Runtime Gate — прод-инференс (FastAPI) с runtime-защитой. Эталон (модель №1).

Защиты (docs/13_RUNTIME_AND_MONITORING.md §13.2):
  - rate-limit (Redis, graceful in-memory fallback) → 429   (#5 extraction, #6 DoS)
  - Pydantic-валидация → 422                                 (#6, #11 evasion)
  - лимит размера payload → 413
  - output reduction                                         (#5, #13 membership)
  - DLP в логах                                              (#12)

КРИТИЧНО: фичи — ТОЛЬКО через src.common.features (парность с train, #19).
Модели №2/№3 (C): по сервису на модель, тот же middleware-слой защит.
"""
from __future__ import annotations

import os
import re
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.common.features import featurize_row  # noqa: E402
from src.common.audit import log_event, log_feature  # noqa: E402

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except Exception:  # graceful для py_compile без пакетов
    FastAPI = None  # type: ignore

    class BaseModel:  # type: ignore
        pass

    def Field(*a, **k):  # type: ignore
        return None

RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "100"))
MAX_PAYLOAD_BYTES = int(os.getenv("MAX_PAYLOAD_BYTES", str(64 * 1024)))
MAX_INFLIGHT = int(os.getenv("MAX_INFLIGHT", "32"))        # DOS-01 load-shedding → 503
COST_BUDGET = int(os.getenv("COST_BUDGET", "20000"))       # DOW-01 бюджет «стоимости»/мин → 429
OOD_AMOUNT_MAX = float(os.getenv("OOD_AMOUNT_MAX", "100000"))  # RT-02 порог аномалии входа
MODEL_PATH = os.getenv("MODEL_PATH", str(ROOT / "artifacts" / "credit_scoring.onnx"))

# DOS-01: глобальный лимит одновременных запросов (load-shedding). Сверх лимита → 503.
_inflight = threading.BoundedSemaphore(MAX_INFLIGHT)

# DOW-01: бюджет «стоимости» на ключ за минуту (исчерпан → 429).
_cost: dict[str, list] = {}


def cost_exceeded(key: str, cost: int) -> bool:
    now = time.time()
    items = [(t, c) for t, c in _cost.get(key, []) if now - t < 60]
    items.append((now, cost))
    _cost[key] = items
    return sum(c for _, c in items) > COST_BUDGET


def ood_check(amount: float, age: int) -> tuple[bool, str]:
    """RT-02: грубый OOD/adversarial-детект по диапазонам/соотношению. suspect=True → Finding."""
    if amount > OOD_AMOUNT_MAX:
        return True, f"amount={amount} вне обучающего диапазона (> {OOD_AMOUNT_MAX:g})"
    if age <= 0 or age >= 110:
        return True, f"age={age} аномален"
    if age > 0 and amount / age > OOD_AMOUNT_MAX / 10:
        return True, "аномальное соотношение amount/age"
    return False, ""

# --- DLP-маски для логов (#12) ---
RE_CARD = re.compile(r"\b(\d{4})[ -]?\d{4}[ -]?\d{4}[ -]?(\d{4})\b")
RE_EMAIL = re.compile(r"([\w.+-])[\w.+-]*@([\w-]+\.[\w.-]+)")


def dlp_mask(s: str) -> str:
    s = RE_CARD.sub(r"\1-****-****-\2", s)
    s = RE_EMAIL.sub(r"\1***@\2", s)
    return s


# --- Rate-limit: Redis, с graceful in-memory fallback ---
class _RateLimiter:
    def __init__(self) -> None:
        self._redis = None
        self._mem: dict[str, list[float]] = {}
        try:
            import redis  # noqa: F401

            self._redis = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
            self._redis.ping()
        except Exception:  # noqa: BLE001
            self._redis = None  # деградация в in-memory (для локального демо)

    def hit(self, key: str) -> bool:
        """True = лимит превышен (нужно отдать 429)."""
        if self._redis is not None:
            bucket = f"rl:{key}:{int(time.time() // 60)}"
            n = self._redis.incr(bucket)
            if n == 1:
                self._redis.expire(bucket, 60)
            return int(n) > RATE_LIMIT_PER_MIN
        # in-memory скользящее окно 60с
        now = time.time()
        hits = [t for t in self._mem.get(key, []) if now - t < 60]
        hits.append(now)
        self._mem[key] = hits
        return len(hits) > RATE_LIMIT_PER_MIN


_limiter = _RateLimiter()


# --- модель (ONNX) ---
class _Model:
    def __init__(self, path: str) -> None:
        self._sess = None
        try:
            import onnxruntime as ort

            if Path(path).exists():
                self._sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        except Exception:  # noqa: BLE001
            self._sess = None

    def proba(self, feats: list[float]) -> float:
        if self._sess is None:
            return 0.0  # модель не загружена (демо без артефакта)
        import numpy as np

        inp = {self._sess.get_inputs()[0].name: np.array([feats], dtype=np.float32)}
        out = self._sess.run(None, inp)
        # ONNX от sklearn обычно отдаёт [label, proba]; берём P(class=1), иначе 0.0
        try:
            return float(out[1][0][1])
        except Exception:  # noqa: BLE001
            return float(out[0][0])


_model = _Model(MODEL_PATH)


def reduce_output(proba: float) -> dict:
    """Output reduction (#5/#13): решение, НЕ сырые вероятности."""
    return {"decision": "approve" if proba >= 0.5 else "decline"}


class ScoreRequest(BaseModel):  # type: ignore[misc]
    """Строгая схема входа (#6 DoS, #11 evasion). Нарушение → 422."""
    amount: float = Field(gt=0)
    age: int = Field(ge=0, le=120)
    text: str = Field(default="", max_length=500)


app = FastAPI(title="MLSecOps Inference (G7)") if FastAPI else None

if app:
    @app.middleware("http")
    async def guard(request: Request, call_next):
        # 1) лимит размера payload → 413
        cl = request.headers.get("content-length")
        if cl and int(cl) > MAX_PAYLOAD_BYTES:
            return JSONResponse({"detail": "payload too large"}, status_code=413)
        key = request.headers.get("x-api-key") or (request.client.host if request.client else "anon")
        # 2) RT-01 rate-limit → 429
        if _limiter.hit(key):
            return JSONResponse({"detail": "Too Many Requests"}, status_code=429)
        # 3) DOW-01 cost/token-quota → 429
        if cost_exceeded(key, cost=int(cl or 1)):
            return JSONResponse({"detail": "Cost budget exceeded"}, status_code=429)
        # 4) DOS-01 load-shedding → 503 (сверх MAX_INFLIGHT одновременных — отбрасываем, ядро живо)
        if not _inflight.acquire(blocking=False):
            return JSONResponse({"detail": "Service overloaded, retry later"}, status_code=503)
        try:
            return await call_next(request)
        finally:
            _inflight.release()

    @app.post("/predict")
    def predict(req: ScoreRequest):
        feats = featurize_row(req.amount, req.age)   # парность с train (#19)
        # RT-02 OOD/adversarial-детект: подозрительный вход → suspect + Finding (не блокируем)
        suspect, why = ood_check(req.amount, req.age)
        if suspect:
            log_event("serve", "system", "ood_suspect", asset="credit_scoring",
                      result="pending", details={"control": "RT-02", "reason": why})
        proba = _model.proba(feats)
        out = reduce_output(proba)
        out["ood_suspect"] = suspect
        # DLP перед логированием (#12) + лог фич для G6 PSI на живом трафике
        print(dlp_mask(f"[infer] amount={req.amount} age={req.age} text={req.text!r}"))
        log_feature("credit_scoring", {"amount": req.amount, "age": req.age},
                    decision=out.get("decision"))
        return JSONResponse(out)

    @app.get("/health")
    def health():
        return {"status": "ok", "model_loaded": _model._sess is not None}
