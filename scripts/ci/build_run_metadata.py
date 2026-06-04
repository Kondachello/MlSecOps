#!/usr/bin/env python3
"""Attach GitHub Actions run metadata to a workflow summary JSON file."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", required=True, help="path to *-summary.json")
    args = ap.parse_args()
    path = Path(args.summary)
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    data["run_metadata"] = {
        "github_run_id": os.getenv("GITHUB_RUN_ID", ""),
        "github_run_number": os.getenv("GITHUB_RUN_NUMBER", ""),
        "github_workflow": os.getenv("GITHUB_WORKFLOW", ""),
        "github_sha": os.getenv("GITHUB_SHA", ""),
        "github_ref": os.getenv("GITHUB_REF", ""),
        "github_repository": os.getenv("GITHUB_REPOSITORY", ""),
        "github_actor": os.getenv("GITHUB_ACTOR", ""),
        "github_event_name": os.getenv("GITHUB_EVENT_NAME", ""),
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
