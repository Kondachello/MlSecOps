"""core/identity.py — личность из auth-прокси и RBAC."""
from __future__ import annotations

import os
from typing import Optional

AUTH_HEADER = os.getenv("AUTH_PROXY_HEADER", "X-Authenticated-User")
APP_DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"
DEBUG_USER = os.getenv("BOOTSTRAP_ADMIN_USER", "msecops")

ROLES = {"DS", "DE", "MLSecOps", "Product", "CEO"}


class AuthError(Exception):
    """403 — нет прав."""


def current_user(request) -> str:
    """Личность из заголовка прокси. В APP_DEBUG — fallback на BOOTSTRAP_ADMIN_USER."""
    headers = getattr(request, "headers", {}) or {}
    user = headers.get(AUTH_HEADER) or headers.get(AUTH_HEADER.lower())
    if user:
        return str(user)
    if APP_DEBUG:
        return DEBUG_USER
    raise AuthError(f"missing auth header {AUTH_HEADER}")


def require_role(request, role: str) -> str:
    assert role in ROLES, role
    user = current_user(request)
    from core.db import get_roles

    if role not in get_roles(user):
        if APP_DEBUG and role == "MLSecOps":
            return user
        raise AuthError(f"user {user} lacks role {role}")
    return user


def effective_role(request) -> str:
    user = current_user(request)
    from core.db import get_roles

    roles = get_roles(user)
    if "MLSecOps" in roles:
        return "MLSecOps"
    if "DS" in roles:
        return "DS"
    if roles:
        return sorted(roles)[0]
    return "DS" if APP_DEBUG else "Product"
