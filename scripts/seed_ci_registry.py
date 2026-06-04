"""Наполнить реестр датасетами для CI preflight (train_m1_clean@v1). Идемпотентно."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core import db


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    db.init_db()
    if not db.ping():
        print("seed_ci_registry: DB unavailable", file=sys.stderr)
        sys.exit(1)
    datasets = [
        ("train_m1_clean", "v1", "data/train_m1_clean.csv", "corp_storage", "available"),
        ("synthetic_text", "v1", "data/synthetic_text.csv", "verified_id", "available"),
    ]
    for name, ver, rel, src, status in datasets:
        p = _ROOT / rel
        sha = _sha(p) if p.is_file() else "0" * 64
        db.register_dataset(name, ver, sha, src, status, "datasets", "ci-seed@mlsecops")
        db.mark_dataset_verified(name, ver, sha)
        print(f"  dataset {name}@{ver} -> {status}")
    print("seed_ci_registry: OK")


if __name__ == "__main__":
    main()
