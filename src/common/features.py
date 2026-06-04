"""Единая фичеинженерия — ОДИН источник правды для train.py и serve/app.py.

Закрывает #19 (Training-Serving Skew): и обучение, и инференс ОБЯЗАНЫ звать
эти функции. Если кто-то форкнет логику фич на serve — упадёт tests/test_consistency.py.

Модели:
  №1 — credit_scoring (tabular: amount, age)     → featurize_row / featurize_df / featurize_rows
  №2 — text_classifier (TF-IDF, text input)      → featurize_text / featurize_texts
  №3 — transaction_risk (tabular, 4 фичи)        → featurize_risk_row / featurize_risk_df

Контракт:
  вход каждой featurize_* чётко задокументирован.
  FEATURE_NAMES фиксирован (train и serve совпадают побитово).
"""
from __future__ import annotations

import re
from typing import Sequence

# ── Модель №1: tabular credit/fraud scoring ──────────────────────────────── #

FEATURE_NAMES: list[str] = ["amount", "age", "amount_per_age"]


def featurize_row(amount: float, age: int) -> list[float]:
    """Превратить один пример в вектор фич. Детерминирована, без внешнего состояния."""
    amount = float(amount)
    age = int(age)
    amount_per_age = amount / age if age > 0 else 0.0
    return [amount, float(age), amount_per_age]


def featurize_rows(rows: Sequence[dict]) -> list[list[float]]:
    """Батч: список dict с ключами amount/age → матрица фич."""
    return [featurize_row(r["amount"], r["age"]) for r in rows]


def featurize_df(df):
    """pandas.DataFrame (колонки amount, age) → numpy-матрица фич (n, 3)."""
    import numpy as np

    return np.array([featurize_row(a, b) for a, b in zip(df["amount"], df["age"])],
                    dtype=np.float32)


# ── Модель №2: text classifier (спам/не-спам) ─────────────────────────────── #
# TF-IDF строится один раз при обучении и сохраняется вместе с моделью.
# На serve: onnxruntime принимает сырой text → pipeline внутри ONNX.
# featurize_text нужна только в train.py; serve напрямую передаёт text в ONNX.

TEXT_FEATURE_NAMES: list[str] = ["text_raw"]  # ONNX-pipeline делает TF-IDF сам


def featurize_text(text: str) -> str:
    """Нормализация текста (нижний регистр, strip). Детерминирована."""
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)  # нормализация пробелов
    return text


def featurize_texts(texts: Sequence[str]) -> list[str]:
    """Батч текстов → нормализованные строки."""
    return [featurize_text(t) for t in texts]


# ── Модель №3: transaction risk (расширенный табличный) ───────────────────── #

RISK_FEATURE_NAMES: list[str] = [
    "amount", "age", "amount_per_age",
    "amount_log1p",   # log(1+amount): сжимает выбросы
    "is_large",       # amount > 10000 → риск крупных сумм
    "is_young",       # age < 25 → поведенческий риск
]


def featurize_risk_row(amount: float, age: int) -> list[float]:
    """Расширенные фичи для transaction risk (модель №3). Включает фичи №1."""
    import math

    amount = float(amount)
    age = int(age)
    amount_per_age = amount / age if age > 0 else 0.0
    amount_log1p = math.log1p(max(amount, 0.0))
    is_large = 1.0 if amount > 10_000 else 0.0
    is_young = 1.0 if age < 25 else 0.0
    return [amount, float(age), amount_per_age, amount_log1p, is_large, is_young]


def featurize_risk_rows(rows: Sequence[dict]) -> list[list[float]]:
    return [featurize_risk_row(r["amount"], r["age"]) for r in rows]


def featurize_risk_df(df):
    """pandas.DataFrame → numpy-матрица расширенных фич (n, 6)."""
    import numpy as np

    return np.array([featurize_risk_row(a, b) for a, b in zip(df["amount"], df["age"])],
                    dtype=np.float32)
