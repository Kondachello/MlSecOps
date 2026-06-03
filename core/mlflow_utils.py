"""core/mlflow_utils.py — доступ к MLflow (за auth-прокси) и связка с реестром.

См. docs/11_BACKEND_API.md §11.5, docs/06_IDENTITY_AND_AUTH.md.
MLflow НЕ публикуется наружу — ходим только через прокси; tracking_uri = адрес прокси.
Скелет.
"""
from __future__ import annotations

import os
from typing import Optional

# Бэкенд ходит в MLflow server-side НАПРЯМУЮ (он доверенный), минуя собственный /mlflow-прокси.
# Для дев это локальный mlflow server; в проде — внутренний адрес MLflow за прокси.
MLFLOW_UPSTREAM_URL = os.getenv("MLFLOW_UPSTREAM_URL",
                                os.getenv("MLFLOW_TRACKING_URI", "http://127.0.0.1:5000"))


def _client():
    """MlflowClient на внутренний MLflow (server-side, без нашего auth-прокси)."""
    from mlflow.tracking import MlflowClient
    return MlflowClient(tracking_uri=MLFLOW_UPSTREAM_URL)


def list_recent_runs(limit: int = 50) -> list[dict]:
    """Последние раны по всем экспериментам — для UI «MLflow раны».

    Возвращает плоские dict'ы: run_id, experiment, run_name, user, status,
    start_time, метрики и параметры. Если MLflow недоступен — пустой список.
    """
    try:
        c = _client()
        exps = c.search_experiments()
        by_id = {e.experiment_id: e.name for e in exps}
        if not by_id:
            return []
        runs = c.search_runs(experiment_ids=list(by_id.keys()),
                             max_results=limit, order_by=["start_time DESC"])
    except Exception:
        return []
    out = []
    for r in runs:
        tags = r.data.tags or {}
        out.append({
            "run_id": r.info.run_id,
            "experiment": by_id.get(r.info.experiment_id, r.info.experiment_id),
            "run_name": tags.get("mlflow.runName", ""),
            # личность: серверный штамп прокси (если проставлен) либо mlflow.user
            "user": tags.get("mlflow.user", r.info.user_id or ""),
            "status": r.info.status,
            "start_time": r.info.start_time,
            "metrics": dict(r.data.metrics),
            "params": dict(r.data.params),
        })
    return out


def list_models() -> list[dict]:
    """Зарегистрированные модели из MLflow Model Registry (для выпадашек)."""
    try:
        c = _client()
        return [{"name": m.name,
                 "latest_versions": [v.version for v in (m.latest_versions or [])]}
                for m in c.search_registered_models()]
    except Exception:
        return []


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
