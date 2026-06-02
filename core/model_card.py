"""core/model_card.py — паспорт модели (G0 Onboarding). pydantic-валидация.

См. docs/07_SECURITY_GATES.md (G0) и docs/06_IDENTITY_AND_AUTH.md §6.5 (авто-Tier).
Tier по умолчанию HIGH (fail-safe). Метки source/trained_in_ci проставляет сервер/CI.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

try:
    from pydantic import BaseModel, Field
except Exception:  # graceful: pydantic может отсутствовать в среде гейта
    BaseModel = object  # type: ignore

    def Field(*a, **k):  # type: ignore
        return None


class Tier(str, Enum):
    LOW = "LOW"
    MED = "MED"
    HIGH = "HIGH"


class Source(str, Enum):
    CI_TRAINED = "ci_trained"
    EXTERNAL = "external"


class ModelCard(BaseModel):  # type: ignore[misc]
    """Минимальный паспорт. Обязательные поля проверяет validate_card()."""
    name: str
    version: str
    owner: str
    tier: Tier = Tier.HIGH            # дефолт — fail-safe
    source: Source
    purpose: str                      # назначение модели
    data_source: str                  # источник данных
    # lineage (для G5) — проставляется CI/бэкендом:
    dataset_version: Optional[str] = None
    git_sha: Optional[str] = None
    run_id: Optional[str] = None
    sha256: Optional[str] = None
    trained_in_ci: bool = False       # проставляет CI, НЕ клиент


def auto_tier(*, source: str, pii_found: bool, trained_in_ci: bool,
              data_criticality: str = "low") -> str:
    """Детерминированные авто-правила Tier (docs/06 §6.5). Fail-safe в сторону строгости."""
    if source == Source.EXTERNAL.value:
        return Tier.HIGH.value
    if pii_found:
        return Tier.HIGH.value
    if not trained_in_ci:
        return Tier.HIGH.value
    if data_criticality == "high":
        return Tier.HIGH.value
    return Tier.MED.value if data_criticality == "med" else Tier.LOW.value


def validate_card(card: dict) -> list[dict]:
    """Вернуть список результатов в формате гейта (PASS/FAIL/SKIP) для G0/G5.

    Проверяет обязательные поля. TODO: расширить JSON-schema/pydantic-валидацией.
    """
    required = ["name", "version", "owner", "tier", "source", "purpose", "data_source"]
    results = []
    for field in required:
        ok = bool(card.get(field))
        results.append({
            "check": f"field:{field}",
            "status": "PASS" if ok else "FAIL",
            "detail": "present" if ok else "missing required field",
            "evidence": {"field": field, "value": card.get(field)},
        })
    return results
