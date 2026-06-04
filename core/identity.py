"""core/identity.py — идентичность, пароли, JWT, RBAC.

См. docs/06_IDENTITY_AND_AUTH.md, docs/18_MLFLOW.md.

МОДЕЛЬ ДЛЯ ДЕМО (локальный JWT-issuer в бэкенде):
- Регистрация/логин → бэкенд выдаёт короткоживущий JWT (sub=username, roles=[...]).
- Тот же JWT действителен и для нашего API, и (через auth-прокси) для MLflow.
- Бэкенд, получая запрос, достаёт личность из JWT (Authorization: Bearer ...).

ИСТОЧНИК ЛИЧНОСТИ (current_user), по приоритету:
1. Доверенный заголовок auth-прокси X-Authenticated-User — ТОЛЬКО если включён
   TRUST_PROXY_HEADER=true (т.е. бэкенд реально стоит за прокси, который штампует
   личность серверно и не пропускает этот заголовок от клиента). По умолчанию ВЫКЛ —
   иначе любой клиент мог бы выдать себя за другого, прислав заголовок.
2. JWT из Authorization: Bearer <token> — наш локальный issuer.

В боевом режиме роль берётся ТОЛЬКО из аутентификации. Demo-переключатель ролей
доступен лишь при APP_DEBUG=true (иначе обход RBAC).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt

from core import db

AUTH_HEADER = os.getenv("AUTH_PROXY_HEADER", "X-Authenticated-User")
TRUST_PROXY_HEADER = os.getenv("TRUST_PROXY_HEADER", "false").lower() == "true"
APP_DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"

JWT_SECRET = os.getenv("JWT_SECRET", "dev-insecure-change-me")
JWT_ALGORITHM = "HS256"
TOKEN_TTL_HOURS = int(os.getenv("TOKEN_TTL_HOURS", "8"))

ROLES = {"DS", "DE", "MLSecOps", "Product", "CEO"}


class AuthError(Exception):
    """401/403 — нет валидной личности или прав. Вызывающий пишет event(access_denied)."""


# --- пароли (bcrypt) ---------------------------------------------------------
def hash_password(password: str) -> str:
    """bcrypt-хэш пароля. bcrypt ограничен 72 байтами — режем явно (стандартная практика)."""
    pw = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: Optional[str]) -> bool:
    """Проверить пароль против сохранённого хэша. None-хэш → False (SSO-юзер без пароля)."""
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:72], password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --- JWT ---------------------------------------------------------------------
def create_token(username: str, roles: list[str], *, ttl_hours: Optional[int] = None) -> str:
    """Выдать подписанный JWT (sub=username, roles, exp). Используется при логине."""
    ttl = TOKEN_TTL_HOURS if ttl_hours is None else ttl_hours
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "roles": sorted(roles),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=ttl)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Проверить подпись/срок и вернуть payload. AuthError при невалидном/истёкшем токене."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        raise AuthError(f"invalid token: {e}") from e


# --- аутентификация по логину/паролю ----------------------------------------
def authenticate(username: str, password: str) -> dict:
    """Проверить логин+пароль по БД. Вернуть {username, roles} или AuthError.

    Используется эндпоинтом /auth/login для выдачи токена.
    """
    user = db.get_user(username)
    if not user or not verify_password(password, user.get("password_hash")):
        raise AuthError("invalid username or password")
    return {"username": username, "roles": sorted(db.get_roles(username))}


# --- извлечение личности из запроса ------------------------------------------
def _header(request, name: str) -> Optional[str]:
    """Достать заголовок (Starlette Headers — регистронезависимы; dict — как есть)."""
    try:
        return request.headers.get(name)
    except AttributeError:
        return None


def current_user(request) -> str:
    """Вернуть проверенную личность (username). AuthError, если её нет.

    НИКОГДА не доверяем телу запроса/клиентским полям. См. приоритет в docstring модуля.
    """
    if TRUST_PROXY_HEADER:
        proxied = _header(request, AUTH_HEADER)
        if proxied:
            return proxied

    authz = _header(request, "Authorization") or ""
    if authz.lower().startswith("bearer "):
        token = authz[7:].strip()
        return decode_token(token)["sub"]

    raise AuthError("no authenticated identity (need Bearer token)")


def token_roles(request) -> set[str]:
    """Роли из JWT запроса (если есть) — без обращения к БД. Пусто, если токена нет."""
    authz = _header(request, "Authorization") or ""
    if authz.lower().startswith("bearer "):
        try:
            return set(decode_token(authz[7:].strip()).get("roles", []))
        except AuthError:
            return set()
    return set()


def get_roles(username: str) -> set[str]:
    """Актуальные роли пользователя из БД (источник правды по ролям)."""
    return db.get_roles(username)


def require_role(request, role: str) -> str:
    """Проверить, что у текущего пользователя есть роль. Иначе AuthError (→403 + событие).

    Возвращает username. Роли берём из БД (а не из токена) — на случай отзыва роли.
    """
    assert role in ROLES, role
    username = current_user(request)
    if role not in get_roles(username):
        raise AuthError(f"user '{username}' lacks role '{role}'")
    return username


def effective_role(request) -> str:
    """Роль для UI. В боевом режиме — из аутентификации (первая роль пользователя).

    Demo-переключатель ('режим разработчика'/'режим MLSecOps') учитывается ТОЛЬКО при
    APP_DEBUG (передаётся UI через заголовок X-Demo-Role).
    """
    if APP_DEBUG:
        demo = _header(request, "X-Demo-Role")
        if demo in ROLES:
            return demo
    username = current_user(request)
    roles = sorted(get_roles(username))
    return roles[0] if roles else ""


# --- демо/самопроверка -------------------------------------------------------
if __name__ == "__main__":
    # Сценарий: хэш пароля → регистрация в БД → логин (выдача JWT) → валидация →
    # current_user из заголовка Bearer → require_role (есть/нет) → истёкший токен.
    import tempfile
    from pathlib import Path

    db.SQLITE_PATH = str(Path(tempfile.gettempdir()) / "mlsec_identity_demo.db")
    if Path(db.SQLITE_PATH).exists():
        Path(db.SQLITE_PATH).unlink()
    db.init_db()

    class FakeRequest:
        def __init__(self, headers: dict):
            self.headers = headers

    # 1) Пароль: хэш + проверка
    h = hash_password("hunter2")
    print(f"1) hash_password('hunter2') = {h[:25]}...")
    print(f"   verify ok   = {verify_password('hunter2', h)}")
    print(f"   verify wrong= {verify_password('nope', h)}")

    # 2) Регистрация пользователя в БД (как сделает /auth/register) + роль DS
    uid = db.register_user("ivanov", "ivanov@example.com", password_hash=h)
    db.assign_role(uid, "DS")
    print(f"\n2) зарегистрирован 'ivanov' (id={uid}), роль DS")

    # 3) Логин: проверка пароля → выдача JWT
    info = authenticate("ivanov", "hunter2")
    token = create_token(info["username"], info["roles"])
    print(f"\n3) authenticate('ivanov','hunter2') = {info}")
    print(f"   JWT = {token[:40]}...")
    try:
        authenticate("ivanov", "WRONG")
    except AuthError as e:
        print(f"   authenticate с неверным паролем -> AuthError: {e}")

    # 4) Запрос с Bearer-токеном → current_user / require_role
    req = FakeRequest({"Authorization": f"Bearer {token}"})
    print(f"\n4) current_user(req) = '{current_user(req)}'")
    print(f"   require_role(req,'DS')      = '{require_role(req, 'DS')}'  (ОК)")
    try:
        require_role(req, "MLSecOps")
    except AuthError as e:
        print(f"   require_role(req,'MLSecOps') -> AuthError: {e}  (ОК, прав нет)")

    # 5) Истёкший токен отвергается
    expired = create_token("ivanov", ["DS"], ttl_hours=-1)
    try:
        decode_token(expired)
    except AuthError as e:
        print(f"\n5) истёкший токен -> AuthError: {e}  (ОК)")

    # 6) Запрос без токена
    try:
        current_user(FakeRequest({}))
    except AuthError as e:
        print(f"6) запрос без токена -> AuthError: {e}  (ОК)")
