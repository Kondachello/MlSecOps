"""G7 Runtime — инференс текстового классификатора (модель №2).

Принимает: {"text": "..."}
Возвращает: {"decision": "spam"|"ok"}  (output reduction, #5/#13)
Все G7-защиты: rate-limit→429, Pydantic→422, payload→413, DLP-логи (#12).

Запуск: uvicorn src.serve.app_text:app --port 8081
"""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.common.features import featurize_text  # noqa: E402 — парность с train (#19)
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
MODEL_PATH = os.getenv("TEXT_MODEL_PATH", str(ROOT / "artifacts" / "text_classifier.onnx"))

RE_EMAIL = re.compile(r"([\w.+-])[\w.+-]*@([\w-]+\.[\w.-]+)")


def dlp_mask(s: str) -> str:
    return RE_EMAIL.sub(r"\1***@\2", s)


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


class _TextModel:
    def __init__(self, path: str) -> None:
        self._sess = None
        self._input_name = "text_input"
        try:
            import onnxruntime as ort
            if Path(path).exists():
                self._sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
                self._input_name = self._sess.get_inputs()[0].name
        except Exception:  # noqa: BLE001
            self._sess = None

    def predict(self, text: str) -> str:
        """Вернуть 'spam' или 'ok'. Output reduction (#5/#13)."""
        if self._sess is None:
            return "ok"
        import numpy as np
        inp = {self._input_name: np.array([[text]])}
        try:
            out = self._sess.run(None, inp)
            label = int(out[0][0])
        except Exception:  # noqa: BLE001
            label = 0
        return "spam" if label == 1 else "ok"


_limiter = _RateLimiter()
_model = _TextModel(MODEL_PATH)


class TextRequest(BaseModel):  # type: ignore[misc]
    text: str = Field(min_length=1, max_length=1000)


app = FastAPI(title="MLSecOps Text Classifier (G7, model #2)") if FastAPI else None

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

    @app.post("/classify")
    def classify(req: TextRequest):
        norm = featurize_text(req.text)   # парность с train (#19)
        decision = _model.predict(norm)
        print(dlp_mask(f"[text-infer] text={req.text!r:.80} → {decision}"))
        log_feature("text_classifier", {"text_len": len(norm)}, decision=decision)
        return JSONResponse({"decision": decision})

    @app.get("/health")
    def health():
        return {"status": "ok", "model": "text_classifier",
                "model_loaded": _model._sess is not None}
