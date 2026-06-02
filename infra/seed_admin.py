"""seed_admin.py — bootstrap первого MLSecOps (debug-сид для разработки/демо).

См. docs/06_IDENTITY_AND_AUTH.md §6.6. Берёт логин/почту из окружения (BOOTSTRAP_ADMIN_*).
Создаёт пользователя и назначает роль MLSecOps. Идемпотентно. Никаких секретов в коде.
"""
from __future__ import annotations

import os


def main() -> None:
    user = os.getenv("BOOTSTRAP_ADMIN_USER", "msecops")
    email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "msecops@example.com")
    # from core.db import register_user, assign_role
    # uid = register_user(user, email)         # идемпотентно (UNIQUE username)
    # assign_role(uid, "MLSecOps")
    # log_event("system", "MLSecOps", "bootstrap_admin", asset=user, result="ok")
    print(f"TODO: создать админа {user} <{email}> и роль MLSecOps")


if __name__ == "__main__":
    main()
