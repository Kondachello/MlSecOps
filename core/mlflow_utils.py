"""core/mlflow_utils.py — доступ к MLflow (за auth-прокси) и связка с реестром.

См. docs/11_BACKEND_API.md §11.5, docs/06_IDENTITY_AND_AUTH.md.
MLflow НЕ публикуется наружу — ходим только через прокси; tracking_uri = адрес прокси.
Скелет.
"""
from __future__ import annotations

import os
from typing import Optional

MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", "http://authproxy:4180/mlflow")


def _client():
    """MlflowClient(tracking_uri=MLFLOW_TRACKING_URI). TODO."""
    raise NotImplementedError("TODO: from mlflow.tracking import MlflowClient")


def list_models() -> list[dict]:
    """Список моделей/экспериментов для выпадашки UI. TODO: search_runs/experiments."""
    raise NotImplementedError("TODO")


def list_runs(model: str) -> list[dict]:
    """Список ранов модели с ИБ-тегами и хэшем датасета (run.inputs.dataset_inputs). TODO."""
    raise NotImplementedError("TODO")


def get_run_metadata(run_id: str) -> dict:
    """Метаданные рана: security.* теги, dataset hash, git_sha, метрики. TODO."""
    raise NotImplementedError("TODO")


def download_artifacts(run_id: str, path: str, dst: str) -> str:
    """Скачать артефакт рана в dst (для G2/G4 на верификации внешних весов). TODO."""
    raise NotImplementedError("TODO")


def register_model_version(name: str, source_uri: str, *, tags: Optional[dict] = None) -> str:
    """Зарегистрировать версию в MLflow Model Registry; вернуть mlflow_version. TODO."""
    raise NotImplementedError("TODO")


def set_alias(name: str, version: str, alias: str) -> None:
    """Сменить alias (candidate/staging/production/previous). Делает бэкенд/деплой, не человек. TODO."""
    assert alias in {"candidate", "staging", "production", "previous"}, alias
    raise NotImplementedError("TODO")
