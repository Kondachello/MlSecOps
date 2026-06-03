"""Bootstrap первого MLSecOps (идемпотентно)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.db import assign_role, log_event, ping, register_user


def main() -> None:
    user = os.getenv("BOOTSTRAP_ADMIN_USER", "msecops")
    email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "msecops@example.com")
    if not ping():
        print(f"seed_admin: Postgres недоступен — пропуск ({user})", file=sys.stderr)
        sys.exit(1)
    uid = register_user(user, email)
    assign_role(uid, "MLSecOps")
    log_event("system", "MLSecOps", "bootstrap_admin", asset=user, result="ok")
    print(f"seed_admin: OK user={user} id={uid} role=MLSecOps")


if __name__ == "__main__":
    main()
