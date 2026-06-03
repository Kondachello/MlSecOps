"""Печать краткого итога JSON-отчёта гейта. Exit 1, если passed=false.

  python src/gates/data_gate/data_gate.py --path data/x.csv --json | python scripts/ci/parse_report.py
  python scripts/ci/parse_report.py report.json
"""
from __future__ import annotations

import json
import sys


def main() -> None:
    if len(sys.argv) > 1:
        text = open(sys.argv[1], encoding="utf-8").read()
    else:
        text = sys.stdin.read()

    report = json.loads(text)
    gate = report.get("gate", "?")
    passed = report.get("passed", False)
    print(f"{gate}: passed={passed}")

    for check in report.get("checks", []):
        if check.get("status") == "FAIL":
            print(f"  - {check.get('check')}: {check.get('detail')}")

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
