"""Bootstrap первого MLSecOps (идемпотентно)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core import db, identity
from core.db import assign_role, log_event, ping, register_user, set_password


def main() -> None:
    user = os.getenv("BOOTSTRAP_ADMIN_USER", "msecops")
    email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "msecops@example.com")
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "admin-pass")
    if not ping():
        print(f"seed_admin: Postgres недоступен — пропуск ({user})", file=sys.stderr)
        sys.exit(1)
    pw_hash = identity.hash_password(password)
    existing = db.get_user(user)
    if existing:
        uid = int(existing["id"])
        if not existing.get("password_hash"):
            set_password(user, pw_hash)
    else:
        uid = register_user(user, email, password_hash=pw_hash)
    assign_role(uid, "MLSecOps")
    log_event("system", "MLSecOps", "bootstrap_admin", asset=user, result="ok")
    print(f"seed_admin: OK user={user} id={uid} role=MLSecOps")


if __name__ == "__main__":
    main()
