"""src/api/mlflow_proxy.py — auth-прокси перед MLflow (docs/06, docs/18).

MLflow OSS не умеет пер-юзер RBAC, поэтому наружу не публикуется. Единственный вход —
этот прокси: он валидирует наш JWT (Authorization: Bearer) и СЕРВЕРНО проставляет
личность (X-Authenticated-User), которую клиент задать не может. Затем запрос
проксируется во внутренний MLflow-сервер.

Поверх этого прокси реализована ПРИВАТНОСТЬ + КОНТРОЛИРУЕМЫЙ ШАРИНГ артефактов:
  1. На runs/create и experiments/create прокси штампует неподделываемого ВЛАДЕЛЬЦА
     (тег mlsecops.owner = личность из токена) и фиксирует владение в нашей БД.
  2. На runs/search, runs/get, experiments/search, experiments/get прокси ФИЛЬТРУЕТ
     ответ MLflow: пользователь видит только свои артефакты + расшаренные ему
     (по клиренсу роли или по кастомному списку ролей). См. core.identity.can_view_artifact.

Так каждый разработчик работает в своём «аккаунте» (эксперименте) изолированно, а шаринг
между разработчиками происходит контролируемо (только после security check, см. бэкенд).

DS в ноутбуке делает:
    os.environ["MLFLOW_TRACKING_URI"]   = "http://<backend>/mlflow"
    os.environ["MLFLOW_TRACKING_TOKEN"] = "<JWT от /auth/token>"
MLflow-клиент шлёт токен в заголовке Authorization, прокси его проверяет.
"""
from __future__ import annotations

import json
import os
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from core import db, identity
from core.mlflow_utils import OWNER_TAG

MLFLOW_UPSTREAM_URL = os.getenv("MLFLOW_UPSTREAM_URL", "http://127.0.0.1:5000")

# Заголовки, которые НЕ форвардим апстриму (hop-by-hop + наша авторизация).
_DROP_HEADERS = {
    "host", "content-length", "authorization", "connection", "keep-alive",
    "transfer-encoding", "upgrade", "proxy-authorization", "te", "trailers",
}
# Дополнительно дропаем при ПЕРЕЗАПИСИ тела (иначе клиент получит рассинхрон длины/кодировки).
_DROP_ON_REWRITE = _DROP_HEADERS | {"content-encoding"}

router = APIRouter()


def _action(path: str) -> str:
    """Нормализовать путь MLflow → action, напр. 'api/2.0/mlflow/runs/search' → 'runs/search'."""
    return path.split("mlflow/", 1)[-1].strip("/") if "mlflow/" in path else path.strip("/")


def _owner_of_run(run: dict) -> str:
    """Владелец рана из тегов: серверный mlsecops.owner → fallback mlflow.user → user_id."""
    tags = (run.get("data") or {}).get("tags") or []
    by_key = {t.get("key"): t.get("value") for t in tags if isinstance(t, dict)}
    return by_key.get(OWNER_TAG) or by_key.get("mlflow.user") or (run.get("info") or {}).get("user_id", "")


def _synth_acl(run: dict, db_acls: dict) -> dict:
    """ACL рана: из БД (если зарегистрирован) либо синтетический приватный (owner из тегов)."""
    rid = (run.get("info") or {}).get("run_id", "")
    acl = db_acls.get(rid)
    if acl:
        return acl
    return {"owner": _owner_of_run(run), "share_status": "private"}


def _filter_runs(data: dict, user: str, roles) -> dict:
    """Оставить в ответе runs/search только видимые пользователю раны."""
    runs = data.get("runs")
    if not isinstance(runs, list):
        return data
    rids = [(r.get("info") or {}).get("run_id", "") for r in runs]
    db_acls = db.list_artifact_acls([r for r in rids if r])
    data["runs"] = [r for r in runs
                    if identity.can_view_artifact(_synth_acl(r, db_acls), user, roles)]
    return data


def _filter_experiments(data: dict, user: str, roles) -> dict:
    """Оставить в ответе experiments/search только видимые пользователю эксперименты.

    Видим, если: эксперимент не отслеживается (legacy/Default — не прячем), либо им
    владеет пользователь, либо в нём есть расшаренный пользователю ран.
    """
    exps = data.get("experiments")
    if not isinstance(exps, list):
        return data
    visible_shared = {a["experiment_id"] for a in db.list_shared_acls()
                      if identity.can_view_artifact(a, user, roles)}
    kept = []
    for e in exps:
        eid = e.get("experiment_id", "")
        owner = db.get_experiment_owner(eid)
        if owner is None or owner == user or eid in visible_shared:
            kept.append(e)
    data["experiments"] = kept
    return data


def _record_create(action: str, user: str, content: bytes, req_body: bytes) -> None:
    """Зафиксировать владение после runs/create / experiments/create (best-effort)."""
    try:
        resp = json.loads(content or b"{}")
    except Exception:
        return
    if action == "runs/create":
        info = (resp.get("run") or {}).get("info") or {}
        rid, eid = info.get("run_id"), info.get("experiment_id")
        if rid and eid:
            db.set_experiment_owner(eid, user)
            name = None
            try:
                name = (json.loads(req_body or b"{}") or {}).get("run_name")
            except Exception:
                pass
            db.upsert_artifact(rid, eid, user, session_name=name)
    elif action == "experiments/create":
        eid = resp.get("experiment_id")
        if eid:
            db.set_experiment_owner(eid, user)


def _stamp_owner_in_body(body: bytes, user: str) -> bytes:
    """Вписать неподделываемый тег владельца в тело runs/create (заменив клиентский, если был)."""
    try:
        payload = json.loads(body or b"{}")
    except Exception:
        return body
    tags = [t for t in (payload.get("tags") or [])
            if isinstance(t, dict) and t.get("key") != OWNER_TAG]
    tags.append({"key": OWNER_TAG, "value": user})
    payload["tags"] = tags
    return json.dumps(payload).encode("utf-8")


@router.api_route("/mlflow/{path:path}",
                  methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
async def mlflow_proxy(path: str, request: Request):
    """Проксировать запрос в MLflow: проверить JWT, штамповать личность/владельца, фильтровать видимость."""
    # 1) Доступ к MLflow — только аутентифицированным (наш JWT).
    try:
        user = identity.current_user(request)
    except identity.AuthError as e:
        raise HTTPException(401, f"MLflow proxy: {e}")

    action = _action(path)
    roles = identity.get_roles(user)

    # 2) Собрать апстрим-запрос: тело + отфильтрованные заголовки + серверный штамп личности.
    body = await request.body()
    if action == "runs/create":
        body = _stamp_owner_in_body(body, user)  # неподделываемый владелец рана
    fwd_headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in _DROP_HEADERS}
    # HTTP-заголовки только latin-1 → не-ASCII логин (напр. кириллицу) URL-кодируем.
    fwd_headers["X-Authenticated-User"] = quote(user, safe="")  # неподделываемая личность

    url = f"{MLFLOW_UPSTREAM_URL}/{path}"
    try:
        # trust_env=False: внутренний MLflow доверенный и обычно локальный — НЕ пускаем этот
        # запрос через системный/корпоративный прокси (HTTP_PROXY/ALL_PROXY). Иначе на части
        # машин (особенно Windows) проксирование ломает связь с MLflow → артефакты «теряются».
        async with httpx.AsyncClient(timeout=120, trust_env=False) as client:
            upstream = await client.request(
                request.method, url, content=body,
                params=request.query_params, headers=fwd_headers,
            )
    except httpx.ConnectError:
        raise HTTPException(502, f"MLflow upstream недоступен ({MLFLOW_UPSTREAM_URL})")

    # 3) Зафиксировать владение на создании рана/эксперимента.
    if upstream.status_code == 200 and action in ("runs/create", "experiments/create"):
        _record_create(action, user, upstream.content, body)

    # 4) Отфильтровать видимость на чтении (search/get) — пользователь видит только своё+расшаренное.
    if upstream.status_code == 200 and action in (
            "runs/search", "experiments/search", "experiments/list", "runs/get", "experiments/get"):
        rewritten = _apply_visibility(action, upstream.content, user, roles)
        if rewritten is not None:
            status, content = rewritten
            resp_headers = {k: v for k, v in upstream.headers.items()
                            if k.lower() not in _DROP_ON_REWRITE}
            return Response(content=content, status_code=status, headers=resp_headers,
                            media_type="application/json")

    # 5) Вернуть ответ MLflow как есть (без hop-by-hop заголовков).
    resp_headers = {k: v for k, v in upstream.headers.items()
                    if k.lower() not in _DROP_HEADERS}
    return Response(content=upstream.content, status_code=upstream.status_code,
                    headers=resp_headers)


_FORBIDDEN = json.dumps(
    {"error_code": "PERMISSION_DENIED",
     "message": "Артефакт приватный или не расшарен вам (MLSecOps visibility)."}).encode("utf-8")


def _apply_visibility(action: str, content: bytes, user: str, roles):
    """Учесть видимость. Вернуть (status, bytes) для подмены ответа, либо None (passthrough)."""
    try:
        data = json.loads(content or b"{}")
    except Exception:
        return None  # не JSON — отдаём как есть
    if action == "runs/search":
        return 200, json.dumps(_filter_runs(data, user, roles)).encode("utf-8")
    if action in ("experiments/search", "experiments/list"):
        return 200, json.dumps(_filter_experiments(data, user, roles)).encode("utf-8")
    if action == "runs/get":
        run = data.get("run") or {}
        acl = _synth_acl(run, db.list_artifact_acls([(run.get("info") or {}).get("run_id", "")]))
        if not identity.can_view_artifact(acl, user, roles):
            return 403, _FORBIDDEN
        return None
    if action == "experiments/get":
        eid = (data.get("experiment") or {}).get("experiment_id", "")
        owner = db.get_experiment_owner(eid)
        if owner is not None and owner != user:
            visible = {a["experiment_id"] for a in db.list_shared_acls()
                       if identity.can_view_artifact(a, user, roles)}
            if eid not in visible:
                return 403, _FORBIDDEN
        return None
    return None
