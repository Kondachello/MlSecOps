"""core/mlflow_utils.py — доступ к MLflow (за auth-прокси) и связка с реестром.

См. docs/11_BACKEND_API.md §11.5, docs/06_IDENTITY_AND_AUTH.md.
MLflow НЕ публикуется наружу — ходим только через прокси; tracking_uri = адрес прокси.
Скелет.
"""
from __future__ import annotations

import logging
import os
from typing import Optional
from urllib.parse import urlsplit

log = logging.getLogger("mlsecops.mlflow")

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

# КРИТИЧНО (частая причина «пустого реестра»): MLflow-клиент ходит через requests, который
# уважает системные прокси (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY). На корпоративных машинах
# (особенно Windows) запрос к ЛОКАЛЬНОМУ/внутреннему MLflow тогда уходит во внешний прокси и
# падает → list_recent_runs() ловит исключение и молча отдаёт [] → реестр пуст без причины.
# Внутренний MLflow доверенный — добавляем его хост в NO_PROXY, чтобы клиент шёл напрямую.
def _ensure_no_proxy_for_upstream() -> None:
    host = (urlsplit(MLFLOW_UPSTREAM_URL).hostname or "127.0.0.1")
    extra = {host, "127.0.0.1", "localhost", "::1"}
    for var in ("NO_PROXY", "no_proxy"):
        cur = {h.strip() for h in os.environ.get(var, "").split(",") if h.strip()}
        os.environ[var] = ",".join(sorted(cur | extra))


_ensure_no_proxy_for_upstream()

# Последняя ошибка соединения с MLflow (для диагностики «почему реестр пуст») — см. mlflow_status().
_LAST_ERROR: Optional[str] = None


def _client():
    """MlflowClient на внутренний MLflow (server-side, без нашего auth-прокси)."""
    from mlflow.tracking import MlflowClient
    return MlflowClient(tracking_uri=MLFLOW_UPSTREAM_URL)


def mlflow_status() -> dict:
    """Диагностика доступности MLflow для UI: {ok, upstream, error, experiments, runs}.

    Используется реестром/дашбордом, чтобы при пустом списке показать ПРИЧИНУ (MLflow недоступен,
    адрес, текст ошибки), а не молчаливое «реестр пуст».
    """
    try:
        c = _client()
        exps = c.search_experiments()
        n_runs = 0
        if exps:
            n_runs = len(c.search_runs(experiment_ids=[e.experiment_id for e in exps],
                                       max_results=1000))
        return {"ok": True, "upstream": MLFLOW_UPSTREAM_URL, "error": None,
                "experiments": len(exps), "runs": n_runs}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "upstream": MLFLOW_UPSTREAM_URL, "error": f"{type(e).__name__}: {e}",
                "experiments": 0, "runs": 0}


def list_recent_runs(limit: int = 50) -> list[dict]:
    """Последние раны по всем экспериментам — для UI «MLflow раны».

    Возвращает плоские dict'ы: run_id, experiment, run_name, user, status,
    start_time, метрики и параметры. Если MLflow недоступен — пустой список.
    """
    global _LAST_ERROR
    try:
        c = _client()
        exps = c.search_experiments()
        by_id = {e.experiment_id: e.name for e in exps}
        if not by_id:
            _LAST_ERROR = None
            return []
        runs = c.search_runs(experiment_ids=list(by_id.keys()),
                             max_results=limit, order_by=["start_time DESC"])
    except Exception as e:  # noqa: BLE001
        # НЕ глотаем тихо: логируем причину — иначе «пустой реестр» неотлаживаем (см. mlflow_status).
        _LAST_ERROR = f"{type(e).__name__}: {e}"
        log.warning("list_recent_runs: MLflow недоступен (%s) — отдаю []: %s",
                    MLFLOW_UPSTREAM_URL, _LAST_ERROR)
        return []
    _LAST_ERROR = None
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
        # Теги рана без внутренних mlflow.* (security.*/research.*/mlsecops.owner) —
        # используются для авто-Tier (security_check) и фильтра по тегам в реестре.
        "tags": {k: v for k, v in tags.items() if not k.startswith("mlflow.")},
    }


def get_run(run_id: str) -> Optional[dict]:
    """Метаданные одного рана (плоский dict) или None, если ран/MLflow недоступен."""
    try:
        c = _client()
        r = c.get_run(run_id)
        exp = c.get_experiment(r.info.experiment_id)
        return _run_to_dict(r, {r.info.experiment_id: exp.name})
    except Exception as e:  # noqa: BLE001
        log.warning("get_run(%s): %s", run_id, e)
        return None


def list_models() -> list[dict]:
    """Зарегистрированные модели из MLflow Model Registry (для выпадашек/реестра моделей).

    Версии берём через search_model_versions (надёжно в MLflow 2.x и 3.x; latest_versions
    в новых версиях может быть пустым/устаревшим). Ошибки логируем, не глотаем тихо.
    """
    try:
        c = _client()
        out = []
        for m in c.search_registered_models():
            try:
                vers = sorted((int(mv.version) for mv in c.search_model_versions(f"name='{m.name}'")),
                              reverse=True)
            except Exception:  # noqa: BLE001 — fallback на latest_versions
                vers = [int(v.version) for v in (getattr(m, "latest_versions", None) or [])]
            out.append({"name": m.name, "latest_versions": [str(v) for v in vers],
                        "n_versions": len(vers)})
        return out
    except Exception as e:  # noqa: BLE001
        log.warning("list_models: MLflow Registry недоступен: %s", e)
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


def create_manual_run(owner: str, name: str, *, file_path: Optional[str] = None,
                      description: str = "", metrics: Optional[dict] = None,
                      experiment: Optional[str] = None) -> dict:
    """Создать ран ВРУЧНУЮ (загрузка отдельного артефакта без связи с экспериментом-исследованием).

    Кладёт ран в личный «ручной» эксперимент владельца (по умолчанию f"{owner}_manual"),
    штампует серверный тег владельца (mlsecops.owner), при наличии — логирует загруженный файл
    как артефакт и метрики. Возвращает {run_id, experiment_id, experiment}. RuntimeError если MLflow недоступен.
    """
    try:
        import mlflow
        c = _client()
        exp_name = experiment or f"{owner}_manual"
        exp = c.get_experiment_by_name(exp_name)
        exp_id = exp.experiment_id if exp else c.create_experiment(exp_name)
        run = c.create_run(experiment_id=exp_id, run_name=name,
                           tags={OWNER_TAG: owner, "mlflow.user": owner,
                                 "mlflow.runName": name, "manual_upload": "true",
                                 "model.description": description or "загружено вручную"})
        rid = run.info.run_id
        for k, v in (metrics or {}).items():
            try:
                c.log_metric(rid, k, float(v))
            except Exception:  # noqa: BLE001
                pass
        if file_path:
            c.log_artifact(rid, file_path)
        c.set_terminated(rid, "FINISHED")
        return {"run_id": rid, "experiment_id": exp_id, "experiment": exp_name}
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"create_manual_run failed: {e}") from e


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
