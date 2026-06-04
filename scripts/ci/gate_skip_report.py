#!/usr/bin/env python3
"""Emit a PASS gate JSON report when a stage is skipped (e.g. dataset fast-path)."""
from __future__ import annotations

import argparse
import json
import sys


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", required=True, help="G1, G2, …")
    ap.add_argument("--asset", required=True)
    ap.add_argument("--reason", required=True)
    ap.add_argument("-o", "--out", help="write JSON to file (default stdout)")
    args = ap.parse_args()

    report = {
        "gate": args.gate,
        "asset": args.asset,
        "passed": True,
        "checks": [
            {
                "check": "skipped",
                "status": "PASS",
                "detail": args.reason,
                "evidence": {"skip": True},
            }
        ],
        "failed_checks": [],
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text)


if __name__ == "__main__":
    main()
