"""
ingest_dataset.py — онбординг датасета через Data Gate (G1).

Сквозной срез (Шаг 4):
  1) регистрирует датасет в реестре (Postgres), считает SHA-256;
  2) пишет событие dataset_uploaded;
  3) прогоняет G1 (src/gates/data_gate.py);
  4) на каждую FAIL-проверку пишет finding (причина блока для UI);
  5) PASS  → status=available, событие result=ok;
     FAIL  → status=quarantine, событие gate_blocked result=blocked.

Запуск:
    python src/ingest_dataset.py data/datasets/train_clean.csv --name scoring_train --version v1
    python src/ingest_dataset.py data/datasets/train_poisoned.csv --name scoring_train --version v2

Требует поднятый Postgres (docker compose ... up postgres) и PG_* в окружении.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from core.db import (  # noqa: E402
    register_dataset, set_dataset_status, add_finding, log_event,
)
from core import storage  # noqa: E402
from src.gates.data_gate import gate_check, build_report  # noqa: E402


def _upload(path: Path, bucket: str, name: str, version: str, digest: str) -> str | None:
    """Загрузить артефакт в MinIO (graceful: вернёт None, если MinIO недоступен)."""
    if not storage.available():
        print("  ⚠️  MinIO недоступен — пропускаю выгрузку (location = локальный путь)")
        return None
    key = f"{name}/{version}/{digest[:12]}_{path.name}"
    uri = storage.upload_file(path, bucket, key)
    print(f"  ☁️  выгружено в {uri}")
    return uri

SEVERITY = {
    "no_pii": "high",
    "class_balance": "high",
    "schema_match": "medium",
    "readable_csv": "high",
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Онбординг датасета через G1")
    ap.add_argument("path", type=Path)
    ap.add_argument("--name", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--actor", default="alice")
    ap.add_argument("--role", default="DS")
    ap.add_argument("--target", default="target")
    ap.add_argument("--expected-cols", default="amount,age,target")
    ap.add_argument("--max-class-share", type=float, default=0.9)
    args = ap.parse_args()

    if not args.path.exists():
        print(f"❌ Файл не найден: {args.path}")
        return 1

    asset = f"{args.name}:{args.version}"
    digest = sha256_of(args.path)

    # 1-2. Регистрация + событие загрузки
    register_dataset(args.name, args.version, sha256=digest,
                     location=str(args.path), created_by=args.actor)
    log_event(args.actor, args.role, "dataset_uploaded", asset=asset, result="ok",
              details={"sha256": digest[:12], "file": args.path.name})
    print(f"📦 Датасет зарегистрирован: {asset} (sha256={digest[:12]}…)")

    # 3. Прогон G1
    expected = [c.strip() for c in args.expected_cols.split(",")] if args.expected_cols else None
    results = gate_check(args.path, target=args.target,
                         expected_cols=expected, max_class_share=args.max_class_share)
    report = build_report(args.path, results)

    for r in results:
        icon = "✅" if r["status"] == "PASS" else "❌"
        print(f"  {icon} [{r['status']}] {r['check']} → {r['detail']}")

    # 4. Находки по упавшим проверкам
    for r in results:
        if r["status"] == "FAIL":
            add_finding(
                "G1", "dataset", asset,
                severity=SEVERITY.get(r["check"], "medium"),
                rule=r["check"],
                evidence={"detail": r["detail"], "report": report},
            )

    # 5. Итог: выгрузка в нужный bucket + статус + событие
    if report["passed"]:
        uri = _upload(args.path, storage.DATASETS_BUCKET, args.name, args.version, digest)
        register_dataset(args.name, args.version, sha256=digest,
                         location=uri or str(args.path), created_by=args.actor)
        set_dataset_status(args.name, args.version, "available")
        log_event("data_gate", "MLSecOps", "gate_passed", asset=asset, result="ok",
                  details={"gate": "G1", "location": uri})
        print(f"\n✅ G1 PASSED — {asset} доступен (status=available)\n")
        return 0
    else:
        # Вредоносный/отравленный артефакт НЕ удаляем — версионируем в quarantine
        # как улику для последующей атрибуции злоумышленника.
        uri = _upload(args.path, storage.QUARANTINE_BUCKET, args.name, args.version, digest)
        register_dataset(args.name, args.version, sha256=digest,
                         location=uri or str(args.path), created_by=args.actor)
        set_dataset_status(args.name, args.version, "quarantine")
        log_event("data_gate", "MLSecOps", "gate_blocked", asset=asset, result="blocked",
                  details={"gate": "G1", "failed": report["failed_checks"],
                           "quarantine_location": uri, "uploaded_by": args.actor})
        print(f"\n❌ G1 FAILED — {asset} помещён в КАРАНТИН (улика сохранена). Причины: "
              f"{', '.join(report['failed_checks'])}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
