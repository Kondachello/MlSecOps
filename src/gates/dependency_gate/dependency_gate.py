"""G3 Supply Gate — цепочка поставки: allow-list имён, пиннинг, доверенный источник.

Закрывает #9 (typosquatting), #3 (источник). См. docs/07_SECURITY_GATES.md (G3).
Граница с G2: CVE/SCA зависимостей — в G2; имена/пиннинг/источник — здесь.

Запуск: docker run --rm -v "$CODE:/in:ro" mlsec-gate-dependency --path /in --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

GATE = "G3"

# Белый список доверенных пакетов (демо; в реале — вести централизованно).
ALLOWLIST = {
    "numpy", "pandas", "scikit-learn", "scipy", "torch", "tensorflow", "xgboost",
    "catboost", "lightgbm", "onnx", "onnxruntime", "transformers", "safetensors",
    "fastapi", "uvicorn", "pydantic", "mlflow", "redis", "boto3", "requests",
    "pyarrow", "streamlit", "pytest", "psycopg", "python-dotenv",
    "evidently", "modelscan", "picklescan", "presidio-analyzer",
    "gitleaks", "pip-audit", "bandit", "trivy",
}
# Частые опечатки-двойники (для наглядного демо).
KNOWN_TYPOSQUATS = {"pytirch", "tenserflew", "tensorflw", "numyp", "pandsa", "scikit_learn"}

RE_REQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*([=<>!~]=?)?\s*([0-9A-Za-z.\-]+)?")


def _parse(req_text: str) -> list[tuple[str, str | None]]:
    out = []
    for line in req_text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = RE_REQ.match(line)
        if m:
            out.append((m.group(1).lower(), m.group(3)))
    return out


def gate_check(path: str) -> list[dict]:
    req = Path(path) / "requirements.txt" if Path(path).is_dir() else Path(path)
    if not req.exists():
        return [{"check": "requirements_present", "status": "SKIP",
                 "detail": "нет requirements.txt", "evidence": {}}]

    pkgs = _parse(req.read_text(encoding="utf-8"))
    results: list[dict] = []

    # 1. Typosquatting / allow-list имён
    bad_names = [(n, v) for n, v in pkgs if n in KNOWN_TYPOSQUATS or n not in ALLOWLIST]
    typos = [n for n, _ in pkgs if n in KNOWN_TYPOSQUATS]
    results.append({"check": "name_allowlist",
                    "status": "FAIL" if bad_names else "PASS",
                    "detail": f"вне allow-list/опечатки: {[n for n, _ in bad_names]}"
                              if bad_names else "все имена доверенные",
                    "evidence": {"unknown": [n for n, _ in bad_names], "typosquats": typos}})

    # 2. Пиннинг версий
    unpinned = [n for n, v in pkgs if not v]
    results.append({"check": "version_pinning",
                    "status": "FAIL" if unpinned else "PASS",
                    "detail": f"незапиненные: {unpinned}" if unpinned else "все версии запинены",
                    "evidence": {"unpinned": unpinned}})

    # 3. Доверенный источник (HF namespace / индекс PyPI) — TODO: проверять --index-url / namespace
    results.append({"check": "trusted_source", "status": "SKIP",
                    "detail": "TODO: проверка индекса/namespace источника", "evidence": {}})
    return results


def build_report(target: str, results: list[dict]) -> dict:
    failed = [r["check"] for r in results if r["status"] == "FAIL"]
    return {"gate": GATE, "asset": target, "passed": not failed,
            "checks": results, "failed_checks": failed}


def main() -> None:
    ap = argparse.ArgumentParser(description="G3 Supply/Dependency Gate")
    ap.add_argument("--path", required=True, help="папка с requirements.txt или путь к файлу")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    results = gate_check(args.path)
    report = build_report(args.path, results)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
