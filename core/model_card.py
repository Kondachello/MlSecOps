"""
model_card.py — паспорт модели (G0 Onboarding) + валидация (pydantic).

Обязательные поля заполняются осмысленно (не "TODO"), tier из перечисления.
Любые дополнительные поля кладутся в extra (интерактивно добавляются в UI).
"""
from __future__ import annotations

from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

PLACEHOLDERS = {"", "todo", "tbd", "-", "n/a", "none"}


class ModelCard(BaseModel):
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    tier: Literal["LOW", "MED", "HIGH"] = "HIGH"  # fail-safe: по умолчанию HIGH
    owner: str = Field(min_length=1)
    data_source: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    framework: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("owner", "data_source", "purpose")
    @classmethod
    def _not_placeholder(cls, v: str) -> str:
        if v.strip().lower() in PLACEHOLDERS:
            raise ValueError("поле должно быть заполнено осмысленно")
        return v

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.model_dump(exclude_none=True),
                              allow_unicode=True, sort_keys=False)


def validate_card(data: dict) -> tuple[bool, list[str], ModelCard | None]:
    """Прогон G0-валидации. Возвращает (ok, список_ошибок, card|None)."""
    try:
        card = ModelCard(**data)
        return True, [], card
    except Exception as e:  # pydantic.ValidationError и пр.
        msgs: list[str] = []
        if hasattr(e, "errors"):
            for err in e.errors():
                loc = ".".join(str(x) for x in err.get("loc", []))
                msgs.append(f"{loc or 'поле'}: {err.get('msg')}")
        else:
            msgs = [str(e)]
        return False, msgs, None
