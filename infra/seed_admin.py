"""seed_admin.py — bootstrap первого MLSecOps (debug-сид для разработки/демо).

См. docs/06_IDENTITY_AND_AUTH.md §6.6. Берёт логин/почту/пароль из окружения
(BOOTSTRAP_ADMIN_*). Создаёт пользователя и назначает роль MLSecOps. Идемпотентно.
Никаких секретов в коде — только из .env/окружения.

Запуск (локально, sqlite-дев):
    python -m infra.seed_admin
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# repo root в path, чтобы импортировать core при запуске как скрипт
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import db, identity  # noqa: E402


def main() -> None:
    user = os.getenv("BOOTSTRAP_ADMIN_USER", "msecops")
    email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "msecops@example.com")
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "admin-pass")

    db.init_db()  # sqlite-дев: создать схему (в Postgres — no-op)

    existing = db.get_user(user)
    uid = db.register_user(user, email, password_hash=identity.hash_password(password))
    # Если юзер уже был, но без пароля — проставим (идемпотентный bootstrap)
    if existing and not existing.get("password_hash"):
        db.set_password(user, identity.hash_password(password))
    db.assign_role(uid, "MLSecOps")
    db.log_event("system", "MLSecOps", "bootstrap_admin", asset=user, result="ok",
                 reason="seed первого админа")

    action = "уже существовал" if existing else "создан"
    print(f"MLSecOps-админ {action}: {user} <{email}> (роль MLSecOps назначена)")
    if not os.getenv("BOOTSTRAP_ADMIN_PASSWORD"):
        print(f"  пароль по умолчанию (debug): {password!r} — задай BOOTSTRAP_ADMIN_PASSWORD в .env")


if __name__ == "__main__":
    main()
