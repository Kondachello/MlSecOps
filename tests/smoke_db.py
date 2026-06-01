"""
Smoke-тест контура БД для CI: применяет init.sql, пишет события через log_event,
читает их и проверяет целостность hash-chain. Падает с кодом 1, если что-то не так.
Запуск локально:  PG_HOST=localhost python tests/smoke_db.py
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from core.db import get_conn, log_event, fetch_events, verify_chain  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def apply_schema() -> None:
    sql = (ROOT / "infra" / "init.sql").read_text(encoding="utf-8")
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(sql)
    print("[ok] схема применена (init.sql)")


def main() -> int:
    apply_schema()

    id1 = log_event("ci", "MLSecOps", "smoke_start", asset="ci-pipeline", result="ok",
                    details={"stage": "smoke"})
    id2 = log_event("ci", "MLSecOps", "smoke_check", asset="ci-pipeline", result="ok",
                    details={"prev": id1})
    print(f"[ok] записаны события #{id1}, #{id2}")

    events = fetch_events(limit=10)
    assert len(events) >= 2, "ожидали минимум 2 события"
    print(f"[ok] прочитано событий: {len(events)}")

    ok, bad_id = verify_chain()
    assert ok, f"hash-chain нарушена на событии #{bad_id}"
    print("[ok] hash-chain цел — Audit Trail работает")

    print("\nSMOKE PASSED ✅")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        print(f"\nSMOKE FAILED ❌  {type(e).__name__}: {e}")
        sys.exit(1)
