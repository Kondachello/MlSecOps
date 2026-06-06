"""infra/seed_ci_user.py — сервисный аккаунт `ci` для GitHub Actions runner.

Создаёт юзера `ci` с ролью MLSecOps (минимально нужная для POST /api/v1/pipeline_runs).
Идемпотентен. Пароль — из env CI_USER_PASSWORD (дефолт `ci-pass-change-me`).

ВАЖНО: пароль должен совпадать с GitHub Actions Secret `MLSEC_CI_PASS`
(см. .github/workflows/gates.yml). Никогда не коммить реальный пароль в репо.

Запуск:
  python -m infra.seed_ci_user
  # или внутри backend-контейнера:
  docker exec -e CI_USER_PASSWORD=xxx infra-backend-1 python -m infra.seed_ci_user
"""
from __future__ import annotations

import os
import sys

from core import db, identity

CI_USERNAME = os.getenv("CI_USERNAME", "ci")
CI_PASSWORD = os.getenv("CI_USER_PASSWORD", "ci-pass-change-me")
CI_EMAIL = os.getenv("CI_EMAIL", "ci@mlsecops.local")


def main() -> int:
    db.init_db()
    existing = db.get_user(CI_USERNAME)
    if existing:
        uid = existing["id"]
        # обновим пароль на актуальный (на случай ротации секрета)
        db.set_password(uid, identity.hash_password(CI_PASSWORD))
        print(f"CI-юзер уже существовал: {CI_USERNAME} (id={uid}) — пароль обновлён.")
    else:
        uid = db.register_user(CI_USERNAME, CI_EMAIL,
                                password_hash=identity.hash_password(CI_PASSWORD))
        print(f"Создан CI-юзер: {CI_USERNAME} (id={uid}).")
    if "MLSecOps" not in identity.get_roles(CI_USERNAME):
        db.assign_role(uid, "MLSecOps")
        print(f"Назначена роль MLSecOps.")
    db.log_event(CI_USERNAME, "MLSecOps", "user_created", asset=CI_USERNAME,
                 result="ok", reason="CI service account seeded")
    print(f"\nДальше:\n"
          f"  1) В GitHub Actions Secrets положи `MLSEC_CI_PASS` = {CI_PASSWORD!r}.\n"
          f"  2) Опционально `MLSEC_BACKEND_URL` (по умолчанию http://backend:8200).\n"
          f"  3) Подними ci-runner: docker compose --profile ci -f infra/docker-compose.yml up -d ci-runner")
    return 0


if __name__ == "__main__":
    sys.exit(main())
