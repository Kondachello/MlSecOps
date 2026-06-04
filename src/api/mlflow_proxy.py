"""src/api/mlflow_proxy.py — auth-прокси перед MLflow (docs/06, docs/18).

MLflow OSS не умеет пер-юзер RBAC, поэтому наружу не публикуется. Единственный вход —
этот прокси: он валидирует наш JWT (Authorization: Bearer) и СЕРВЕРНО проставляет
личность (X-Authenticated-User), которую клиент задать не может. Затем запрос
проксируется во внутренний MLflow-сервер.

DS в ноутбуке делает:
    os.environ["MLFLOW_TRACKING_URI"]   = "http://<backend>/mlflow"
    os.environ["MLFLOW_TRACKING_TOKEN"] = "<JWT от /auth/token>"
MLflow-клиент шлёт токен в заголовке Authorization, прокси его проверяет.
"""
from __future__ import annotations

import os
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from core import identity

MLFLOW_UPSTREAM_URL = os.getenv("MLFLOW_UPSTREAM_URL", "http://127.0.0.1:5000")

# Заголовки, которые НЕ форвардим апстриму (hop-by-hop + наша авторизация).
_DROP_HEADERS = {
    "host", "content-length", "authorization", "connection", "keep-alive",
    "transfer-encoding", "upgrade", "proxy-authorization", "te", "trailers",
}

router = APIRouter()


@router.api_route("/mlflow/{path:path}",
                  methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
async def mlflow_proxy(path: str, request: Request):
    """Проксировать запрос в MLflow после проверки JWT и штампа личности."""
    # 1) Доступ к MLflow — только аутентифицированным (наш JWT).
    try:
        user = identity.current_user(request)
    except identity.AuthError as e:
        raise HTTPException(401, f"MLflow proxy: {e}")

    # 2) Собрать апстрим-запрос: тело + отфильтрованные заголовки + серверный штамп.
    body = await request.body()
    fwd_headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in _DROP_HEADERS}
    # HTTP-заголовки только latin-1 → не-ASCII логин (напр. кириллицу) URL-кодируем.
    fwd_headers["X-Authenticated-User"] = quote(user, safe="")  # неподделываемая личность

    url = f"{MLFLOW_UPSTREAM_URL}/{path}"
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            upstream = await client.request(
                request.method, url, content=body,
                params=request.query_params, headers=fwd_headers,
            )
    except httpx.ConnectError:
        raise HTTPException(502, f"MLflow upstream недоступен ({MLFLOW_UPSTREAM_URL})")

    # 3) Вернуть ответ MLflow как есть (без hop-by-hop заголовков).
    resp_headers = {k: v for k, v in upstream.headers.items()
                    if k.lower() not in _DROP_HEADERS}
    return Response(content=upstream.content, status_code=upstream.status_code,
                    headers=resp_headers)
