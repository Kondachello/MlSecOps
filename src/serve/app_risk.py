"""G7 Runtime — инференс transaction risk (модель №3).

Принимает: {"amount": float, "age": int}
Возвращает: {"decision": "low_risk"|"high_risk"}  (output reduction, #5/#13)
Использует featurize_risk_row для 6 фич (#19 — парность с train_risk.py).

Запуск: uvicorn src.serve.app_risk:app --port 8082
"""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.common.features import featurize_risk_row  # noqa: E402 — парность с train (#19)
from src.common.audit import log_feature  # noqa: E402

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except Exception:
    FastAPI = None  # type: ignore

    class BaseModel:  # type: ignore
        pass

    def Field(*a, **k):  # type: ignore
        return None

RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "100"))
MAX_PAYLOAD_BYTES = int(os.getenv("MAX_PAYLOAD_BYTES", str(64 * 1024)))
MODEL_PATH = os.getenv("RISK_MODEL_PATH", str(ROOT / "artifacts" / "transaction_risk.onnx"))

RE_CARD = re.compile(r"\b(\d{4})[ -]?\d{4}[ -]?\d{4}[ -]?(\d{4})\b")


def dlp_mask(s: str) -> str:
    return RE_CARD.sub(r"\1-****-****-\2", s)


class _RateLimiter:
    def __init__(self) -> None:
        self._redis = None
        self._mem: dict[str, list[float]] = {}
        try:
            import redis
            self._redis = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
            self._redis.ping()
        except Exception:  # noqa: BLE001
            self._redis = None

    def hit(self, key: str) -> bool:
        if self._redis is not None:
            bucket = f"rl:{key}:{int(time.time() // 60)}"
            n = self._redis.incr(bucket)
            if n == 1:
                self._redis.expire(bucket, 60)
            return int(n) > RATE_LIMIT_PER_MIN
        now = time.time()
        hits = [t for t in self._mem.get(key, []) if now - t < 60]
        hits.append(now)
        self._mem[key] = hits
        return len(hits) > RATE_LIMIT_PER_MIN


class _RiskModel:
    def __init__(self, path: str) -> None:
        self._sess = None
        try:
            import onnxruntime as ort
            if Path(path).exists():
                self._sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        except Exception:  # noqa: BLE001
            self._sess = None

    def predict_proba(self, feats: list[float]) -> float:
        if self._sess is None:
            return 0.0
        import numpy as np
        inp = {self._sess.get_inputs()[0].name: np.array([feats], dtype=np.float32)}
        out = self._sess.run(None, inp)
        try:
            return float(out[1][0][1])
        except Exception:  # noqa: BLE001
            return float(out[0][0])


_limiter = _RateLimiter()
_model = _RiskModel(MODEL_PATH)


def reduce_output(proba: float) -> dict:
    """Output reduction (#5/#13): метка, НЕ сырая вероятность."""
    return {"decision": "high_risk" if proba >= 0.5 else "low_risk"}


class RiskRequest(BaseModel):  # type: ignore[misc]
    amount: float = Field(gt=0)
    age: int = Field(ge=0, le=120)


app = FastAPI(title="MLSecOps Transaction Risk (G7, model #3)") if FastAPI else None

if app:
    @app.middleware("http")
    async def guard(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and int(cl) > MAX_PAYLOAD_BYTES:
            return JSONResponse({"detail": "payload too large"}, status_code=413)
        key = request.headers.get("x-api-key") or (request.client.host if request.client else "anon")
        if _limiter.hit(key):
            return JSONResponse({"detail": "Too Many Requests"}, status_code=429)
        return await call_next(request)

    @app.post("/predict")
    def predict(req: RiskRequest):
        feats = featurize_risk_row(req.amount, req.age)  # 6 фич, парность с train (#19)
        proba = _model.predict_proba(feats)
        out = reduce_output(proba)
        print(dlp_mask(f"[risk-infer] amount={req.amount} age={req.age}"))
        log_feature("transaction_risk", {"amount": req.amount, "age": req.age},
                    decision=out.get("decision"))
        return JSONResponse(out)

    @app.get("/health")
    def health():
        return {"status": "ok", "model": "transaction_risk",
                "model_loaded": _model._sess is not None}
