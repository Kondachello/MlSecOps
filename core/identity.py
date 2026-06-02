"""core/identity.py — идентичность и RBAC.

Личность приходит из auth-прокси заголовком X-Authenticated-User (СЕРВЕРНЫЙ штамп).
Клиент её задать НЕ может. См. docs/06_IDENTITY_AND_AUTH.md.

В боевом режиме роль берётся ТОЛЬКО из аутентификации. Demo-переключатель ролей
доступен лишь при APP_DEBUG=true (иначе обход RBAC).
"""
from __future__ import annotations

import os
from typing import Optional

AUTH_HEADER = os.getenv("AUTH_PROXY_HEADER", "X-Authenticated-User")
APP_DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"

ROLES = {"DS", "DE", "MLSecOps", "Product", "CEO"}


class AuthError(Exception):
    """403 — действие без прав. Вызывающий обязан записать event(access_denied)."""


def current_user(request) -> str:
    """Извлечь проверенную личность из заголовка прокси. TODO: чтение request.headers[AUTH_HEADER].

    НИКОГДА не доверять телу запроса/клиентским полям для определения личности.
    """
    raise NotImplementedError("TODO: вернуть request.headers[AUTH_HEADER]")


def get_roles(username: str) -> set[str]:
    """Роли пользователя из таблицы roles (core.db). TODO."""
    raise NotImplementedError("TODO")


def require_role(request, role: str) -> str:
    """Проверить, что у текущего пользователя есть роль. Иначе AuthError (→403 + событие).

    Возвращает username. TODO: current_user + get_roles + проверка.
    """
    assert role in ROLES, role
    raise NotImplementedError("TODO")


def effective_role(request) -> str:
    """Роль для UI. В боевом режиме — из аутентификации.

    Demo-переключатель ('режим разработчика'/'режим MLSecOps') учитывается ТОЛЬКО при APP_DEBUG.
    """
    if APP_DEBUG:
        # TODO: учесть выбранный в UI demo-режим (за DEBUG-флагом)
        pass
    raise NotImplementedError("TODO")
