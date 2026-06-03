"""#19 Training-Serving Skew — тест парности фичей train ↔ serve.

Принцип: и обучение, и инференс ОБЯЗАНЫ считать фичи через src.common.features.
Тест ловит расхождение, если кто-то форкнул логику фич на стороне serve.

Запуск (как в .github/workflows/train.yml):
  pytest tests/test_consistency.py -v --model-path artifacts/credit_scoring.onnx

Базовая проверка (parity фичей) работает БЕЗ модели и без onnxruntime — поэтому CI зелёный
даже до того, как C доделает модели. Проверка предсказаний — только если артефакт+onnxruntime есть.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.common.features import (  # noqa: E402
    FEATURE_NAMES,
    RISK_FEATURE_NAMES,
    featurize_risk_row,
    featurize_row,
    featurize_text,
)

# ── Эталонные строки для проверки ──────────────────────────────────────────── #
SAMPLES = [
    {"amount": 100.0, "age": 30},
    {"amount": 5000.5, "age": 65},
    {"amount": 1.0, "age": 18},
    {"amount": 99999.0, "age": 0},   # граничный: age=0 (деление защищено)
]

TEXT_SAMPLES = [
    "You WON a free iPhone!",
    "Meeting at 10am tomorrow",
    " buy  cheap   pills  NOW ",   # нормализация пробелов
    "",                            # граничный: пустая строка
]


# ── Модель №1: tabular credit/fraud scoring ─────────────────────────────── #

def _serve_featurize(row: dict) -> list[float]:
    """Путь serve: serve ОБЯЗАН звать ту же featurize_row (см. src/serve/app.py)."""
    from src.serve.app import featurize_row as serve_featurize_row
    return serve_featurize_row(row["amount"], row["age"])


def _train_featurize(row: dict) -> list[float]:
    """Путь train: train ОБЯЗАН звать ту же featurize_row (см. src/train/train.py)."""
    return featurize_row(row["amount"], row["age"])


@pytest.mark.parametrize("row", SAMPLES)
def test_feature_parity(row):
    """train-путь и serve-путь дают ИДЕНТИЧНЫЕ фичи (иначе training-serving skew)."""
    assert _train_featurize(row) == _serve_featurize(row), (
        f"Расхождение фич train↔serve на {row} — это #19 skew. "
        f"serve обязан использовать src.common.features.featurize_row")


def test_serve_uses_common_source():
    """serve не должен переопределять featurize — он импортирует общий источник."""
    import src.common.features as common
    import src.serve.app as serve
    assert serve.featurize_row is common.featurize_row, (
        "serve.app.featurize_row должен быть тем же объектом, что common.features.featurize_row")


def test_feature_names_order():
    """FEATURE_NAMES фиксирован; изменение порядка — это #19 skew."""
    assert FEATURE_NAMES == ["amount", "age", "amount_per_age"], (
        "Порядок фичей FEATURE_NAMES изменился — обновите модели и serve!")


def test_feature_age_zero_safe():
    """age=0 не вызывает ZeroDivisionError (деление защищено)."""
    result = featurize_row(100.0, 0)
    assert result[2] == 0.0, "amount_per_age при age=0 должен быть 0.0"


def test_model_predictions_stable(request):
    """Если артефакт + onnxruntime доступны — предсказание детерминировано на повторе."""
    model_path = request.config.getoption("--model-path")
    if not model_path or not Path(model_path).exists():
        pytest.skip("--model-path не задан или артефакт отсутствует (модель ещё не обучена)")
    try:
        import numpy as np
        import onnxruntime as ort
    except Exception:
        pytest.skip("onnxruntime не установлен")

    sess = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
    feats = np.array([_train_featurize(SAMPLES[0])], dtype=np.float32)
    name = sess.get_inputs()[0].name
    out1 = sess.run(None, {name: feats})
    out2 = sess.run(None, {name: feats})
    assert str(out1) == str(out2), "Предсказание недетерминировано на одинаковом входе"


# ── Модель №2: text classifier ─────────────────────────────────────────── #

def test_text_serve_uses_common_source():
    """serve/app_text использует featurize_text из common.features."""
    import src.common.features as common
    import src.serve.app_text as serve_text
    assert serve_text.featurize_text is common.featurize_text, (
        "serve.app_text.featurize_text должен быть тем же объектом, что common.features.featurize_text")


@pytest.mark.parametrize("text", TEXT_SAMPLES)
def test_text_feature_deterministic(text):
    """featurize_text детерминирована (одинаковый вход → одинаковый выход)."""
    r1 = featurize_text(text)
    r2 = featurize_text(text)
    assert r1 == r2, f"featurize_text не детерминирована на {text!r}"


def test_text_feature_normalizes():
    """Нормализация текста: нижний регистр + схлопывание пробелов."""
    assert featurize_text("  Hello   WORLD  ") == "hello world"


# ── Модель №3: transaction risk ────────────────────────────────────────── #

def test_risk_serve_uses_common_source():
    """serve/app_risk использует featurize_risk_row из common.features."""
    import src.common.features as common
    import src.serve.app_risk as serve_risk
    assert serve_risk.featurize_risk_row is common.featurize_risk_row, (
        "serve.app_risk.featurize_risk_row должен быть тем же объектом, что common.features.featurize_risk_row")


def test_risk_feature_names_count():
    """RISK_FEATURE_NAMES содержит ровно 6 фич."""
    assert len(RISK_FEATURE_NAMES) == 6, f"Ожидалось 6 фич, получено {len(RISK_FEATURE_NAMES)}"


@pytest.mark.parametrize("row", SAMPLES)
def test_risk_feature_parity(row):
    """featurize_risk_row детерминирована и содержит 6 фич."""
    result = featurize_risk_row(row["amount"], row["age"])
    assert len(result) == 6, f"Ожидалось 6 фич, получено {len(result)}"
    assert isinstance(result[0], float)


def test_risk_age_zero_safe():
    """age=0 безопасен для risk-фич."""
    result = featurize_risk_row(100.0, 0)
    assert result[2] == 0.0  # amount_per_age
    assert result[4] == 0.0  # is_large (100 < 10000)
    assert result[5] == 1.0  # is_young (0 < 25)
