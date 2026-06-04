"""core/mlflow_utils.py — доступ к MLflow (за auth-прокси) и связка с реестром.

См. docs/11_BACKEND_API.md §11.5, docs/06_IDENTITY_AND_AUTH.md.
MLflow НЕ публикуется наружу — ходим только через прокси; tracking_uri = адрес прокси.
Скелет.
"""
from __future__ import annotations

import os
from typing import Optional

# FAIL-FAST: если MLflow недоступен, его REST-клиент по умолчанию ретраит ~2 минуты
# (грабли HANDOFF, урок №3) — и наши ручки (/artifacts) висят до таймаута UI. Ставим
# короткие таймаут/ретраи ДО первого импорта mlflow, чтобы при лежащем MLflow быстро
# отдать пусто, а не блокировать запрос. Перебить можно через окружение.
os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT", "5")
os.environ.setdefault("MLFLOW_HTTP_REQUEST_MAX_RETRIES", "1")

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
    out = [_run_to_dict(r, by_id) for r in runs]
    return out


# Серверный тег владельца, который проставляет auth-прокси на runs/create.
OWNER_TAG = "mlsecops.owner"


def _run_to_dict(r, by_id: Optional[dict] = None) -> dict:
    """Плоский dict рана для UI/бэкенда (с experiment_id и неподделываемым owner-тегом)."""
    tags = r.data.tags or {}
    exp_id = r.info.experiment_id
    return {
        "run_id": r.info.run_id,
        "experiment_id": exp_id,
        "experiment": (by_id or {}).get(exp_id, exp_id),
        "run_name": tags.get("mlflow.runName", ""),
        # владелец: серверный штамп прокси (mlsecops.owner) — неподделываем; fallback на mlflow.user
        "owner": tags.get(OWNER_TAG) or tags.get("mlflow.user") or (r.info.user_id or ""),
        "user": tags.get("mlflow.user", r.info.user_id or ""),
        "status": r.info.status,
        "start_time": r.info.start_time,
        "metrics": dict(r.data.metrics),
        "params": dict(r.data.params),
    }


def get_run(run_id: str) -> Optional[dict]:
    """Метаданные одного рана (плоский dict) или None, если ран/MLflow недоступен."""
    try:
        c = _client()
        r = c.get_run(run_id)
        exp = c.get_experiment(r.info.experiment_id)
        return _run_to_dict(r, {r.info.experiment_id: exp.name})
    except Exception:
        return None


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
    """Раны конкретной модели/эксперимента (по имени). Пустой список, если MLflow недоступен.

    `model` трактуется как имя эксперимента (в нашей модели эксперимент = «аккаунт/проект»
    разработчика). Возвращает плоские dict'ы, как list_recent_runs.
    """
    try:
        c = _client()
        exp = c.get_experiment_by_name(model)
        if exp is None:
            return []
        by_id = {exp.experiment_id: exp.name}
        runs = c.search_runs(experiment_ids=[exp.experiment_id],
                             order_by=["start_time DESC"])
    except Exception:  # noqa: BLE001
        return []
    return [_run_to_dict(r, by_id) for r in runs]


def get_run_metadata(run_id: str) -> dict:
    """Метаданные рана: security.* теги, dataset hash, git_sha, метрики, lineage входов.

    Расширяет get_run() тегами безопасности и информацией о датасет-входах рана.
    {} если ран/MLflow недоступен.
    """
    base = get_run(run_id) or {}
    if not base:
        return {}
    try:
        c = _client()
        r = c.get_run(run_id)
        tags = r.data.tags or {}
        base["security_tags"] = {k: v for k, v in tags.items() if k.startswith("security.")}
        base["git_sha"] = tags.get("mlflow.source.git.commit") or tags.get("security.git_sha")
        inputs = getattr(r, "inputs", None)
        ds = []
        for di in (getattr(inputs, "dataset_inputs", None) or []):
            d = getattr(di, "dataset", None)
            if d is not None:
                ds.append({"name": getattr(d, "name", None), "digest": getattr(d, "digest", None)})
        base["dataset_inputs"] = ds
        base["dataset_sha256"] = ds[0]["digest"] if ds else tags.get("security.dataset_sha256")
    except Exception:  # noqa: BLE001
        pass
    return base


def download_artifacts(run_id: str, path: str, dst: str) -> str:
    """Скачать артефакт рана в dst (для G2/G4 на верификации внешних весов).

    Тонкая обёртка над MlflowClient.download_artifacts. Бросает RuntimeError, если MLflow недоступен.
    """
    try:
        c = _client()
        return c.download_artifacts(run_id, path, dst)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"download_artifacts failed (run={run_id}, path={path}): {e}") from e


def register_model_version(name: str, source_uri: str, *, tags: Optional[dict] = None) -> str:
    """Зарегистрировать версию в MLflow Model Registry; вернуть mlflow_version.

    Создаёт registered model при отсутствии (идемпотентно), затем create_model_version.
    Бросает RuntimeError, если MLflow недоступен.
    """
    try:
        c = _client()
        try:
            c.create_registered_model(name)
        except Exception:  # noqa: BLE001  — модель уже существует
            pass
        run_id = None
        if source_uri.startswith("runs:/"):
            run_id = source_uri.split("/", 2)[1] if len(source_uri.split("/")) > 1 else None
        mv = c.create_model_version(name=name, source=source_uri, run_id=run_id, tags=tags or {})
        return str(mv.version)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"register_model_version failed (name={name}): {e}") from e


def set_alias(name: str, version: str, alias: str) -> None:
    """Сменить alias (candidate/staging/production/previous). Делает бэкенд/деплой, не человек.

    Тонкая обёртка над MlflowClient.set_registered_model_alias. RuntimeError при недоступности.
    """
    assert alias in {"candidate", "staging", "production", "previous"}, alias
    try:
        c = _client()
        c.set_registered_model_alias(name, alias, version)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"set_alias failed (name={name}, alias={alias}): {e}") from e
