#!/usr/bin/env python3
"""Register CI-trained model in Gatekeeper registry (POST /api/v1/ci/register-model)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None  # type: ignore


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", default="artifacts/model.safetensors")
    ap.add_argument("--model-name", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--dataset-name", default="")
    ap.add_argument("--dataset-version", default="")
    ap.add_argument("--git-sha", default="")
    ap.add_argument("--run-id", default="")
    ap.add_argument("--tier", default="MED")
    ap.add_argument("--card-path", default="demo/model_card_complete.json")
    args = ap.parse_args()

    url = os.getenv("GATEKEEPER_URL", "").rstrip("/")
    if not url:
        print("register: GATEKEEPER_URL not set — skip")
        return

    art = Path(args.artifact)
    if not art.is_file():
        print(f"register: artifact missing {art}", file=sys.stderr)
        sys.exit(1)

    card = json.loads(Path(args.card_path).read_text(encoding="utf-8"))
    payload = {
        "model_name": args.model_name,
        "version": args.version,
        "sha256": sha256_file(art),
        "tier": args.tier,
        "source": "ci_trained",
        "status": "pending_hitl" if args.tier.upper() == "HIGH" else "approved",
        "dataset_name": args.dataset_name,
        "dataset_version": args.dataset_version,
        "git_sha": args.git_sha,
        "run_id": args.run_id,
        "card": card,
    }

    if not requests:
        print("register: requests not installed", file=sys.stderr)
        sys.exit(1)

    headers = {"Content-Type": "application/json"}
    token = os.getenv("CI_INGEST_TOKEN", "")
    if token:
        headers["X-CI-Ingest-Token"] = token

    resp = requests.post(
        f"{url}/api/v1/ci/register-model",
        headers=headers,
        json=payload,
        timeout=30,
    )
    if resp.status_code >= 400:
        print(resp.text, file=sys.stderr)
        sys.exit(1)
    print(json.dumps(resp.json(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
