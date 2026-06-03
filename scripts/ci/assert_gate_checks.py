#!/usr/bin/env python3
"""Проверить JSON гейта: обязательные checks не SKIP (и опц. не FAIL)."""
from __future__ import annotations

import argparse
import json
import sys


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--require", nargs="+", required=True, help="имена check (secrets, sast, …)")
    ap.add_argument("--no-fail", action="store_true", help="FAIL тоже запрещён")
    ap.add_argument("report_file", nargs="?", help="JSON-файл; иначе stdin")
    args = ap.parse_args()

    if args.report_file:
        report = json.loads(open(args.report_file, encoding="utf-8").read())
    else:
        report = json.load(sys.stdin)

    by_name = {c["check"]: c for c in report.get("checks", [])}
    errors: list[str] = []
    for name in args.require:
        c = by_name.get(name)
        if not c:
            errors.append(f"missing check: {name}")
            continue
        if c["status"] == "SKIP":
            errors.append(f"{name}: SKIP — {c.get('detail', '')}")
        if args.no_fail and c["status"] == "FAIL":
            errors.append(f"{name}: FAIL — {c.get('detail', '')}")

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        sys.exit(1)
    print("ok:", ", ".join(args.require))


if __name__ == "__main__":
    main()
