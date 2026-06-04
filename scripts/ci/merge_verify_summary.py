#!/usr/bin/env python3
"""Merge gate-*.json into verify-summary.json for UI / Gatekeeper polling."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flow", default="A")
    ap.add_argument("--workflow", default="verify")
    ap.add_argument("--out", default="verify-summary.json")
    ap.add_argument("reports", nargs="+", help="gate JSON files")
    args = ap.parse_args()

    gates: list[dict] = []
    passed = True
    for p in args.reports:
        path = Path(p)
        if not path.exists():
            continue
        report = json.loads(path.read_text(encoding="utf-8"))
        gates.append(report)
        if not report.get("passed", False):
            passed = False

    summary = {
        "workflow": args.workflow,
        "flow": args.flow,
        "passed": passed,
        "gates": gates,
        "failed_gates": [g["gate"] for g in gates if not g.get("passed")],
        "github_run_id": os.getenv("GITHUB_RUN_ID", ""),
    }
    Path(args.out).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
