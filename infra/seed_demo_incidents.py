"""seed_demo_incidents.py — демо-инциденты: пара артефактов, НЕ прошедших проверку.

Заводит в БД два примера сработок гейтов (Data Poisoning и утёкший секрет), чтобы на вкладке
«Инциденты» было видно, что сработки отображаются (severity, гейт, evidence, статус). Идемпотентно.

Инциденты видны роли MLSecOps (она видит все); владелец демо-артефактов — `ds-demo`.
Запуск:  python -m infra.seed_demo_incidents
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import db  # noqa: E402

DEMO = [
    {"run_id": "demo-poisoned-001", "exp": "demo", "owner": "ds-demo", "name": "fraud_poisoned_v1",
     "gate": "G1", "rule": "class_balance", "sev": "high",
     "detail": "Дисбаланс классов 49.6% (порог 30%) — подозрение на Data Poisoning",
     "evidence": {"detail": "Дисбаланс классов 49.6% (порог 30%) — Data Poisoning",
                  "threats": ["#1"], "minority_rate": 0.496}},
    {"run_id": "demo-secret-002", "exp": "demo", "owner": "ds-demo", "name": "leaky_model_v1",
     "gate": "G2", "rule": "secrets", "sev": "critical",
     "detail": "gitleaks: API_KEY в train.py:13",
     "evidence": {"detail": "gitleaks: generic-api-key в train.py:13",
                  "threats": ["#10"], "file": "train.py", "line": 13}},
]


def main() -> None:
    db.init_db()
    for d in DEMO:
        db.upsert_artifact(d["run_id"], d["exp"], d["owner"], session_name=d["name"])
        # Пометить как проваленную проверку + сохранить «цепочку» с упавшим гейтом (как реальный check).
        detail = {"passed": False, "run_id": d["run_id"], "placeholder": True, "gates": [
            {"id": d["gate"], "name": d["gate"], "status": "FAIL", "severity": d["sev"],
             "threats": d["evidence"].get("threats", []), "detail": d["detail"],
             "logs": [f"[{d['gate']}] {d['detail']}", f"[{d['gate']}] result = FAIL"]}]}
        db.set_check_status(d["run_id"], "failed", detail)
        db.clear_findings_for_asset(d["run_id"])  # идемпотентность: не плодить дубли
        fid = db.add_finding(gate=d["gate"], asset_type="model", asset=d["run_id"],
                             rule=d["rule"], severity=d["sev"], evidence=d["evidence"])
        db.log_event("system", "MLSecOps", "demo_incident_seeded", asset=d["run_id"],
                     result="blocked", reason="демо-инцидент (seed)", details={"finding": fid})
        print(f"seeded: {d['run_id']} {d['gate']}/{d['rule']} ({d['sev']}) -> finding #{fid}")
    print("Готово. Открой вкладку «Инциденты» в UI (под ролью MLSecOps).")


if __name__ == "__main__":
    main()
