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
ALLOWLIST: set[str] = {
    "numpy", "pandas", "scikit-learn", "sklearn", "scipy", "torch", "torchvision",
    "tensorflow", "keras", "xgboost", "catboost", "lightgbm",
    "onnx", "onnxruntime", "onnxruntime-gpu",
    "transformers", "safetensors", "tokenizers", "datasets", "huggingface-hub",
    "fastapi", "flask", "uvicorn", "pydantic", "pydantic-settings", "starlette",
    "mlflow", "redis", "boto3", "botocore", "requests", "httpx", "aiohttp",
    "pyarrow", "pyarrow-stubs",
    "streamlit", "pytest", "pytest-asyncio", "psycopg", "psycopg2-binary",
    "python-dotenv", "python-multipart", "sqlalchemy", "alembic",
    "evidently", "modelscan", "picklescan", "presidio-analyzer",
    "gitleaks", "pip-audit", "bandit", "trivy", "cosign",
    "cryptography", "pyjwt", "passlib", "bcrypt",
    "pillow", "matplotlib", "seaborn", "plotly",
    "tqdm", "rich", "click", "typer",
}

# Известные опечатки-двойники (для наглядного демо).
KNOWN_TYPOSQUATS: set[str] = {
    "pytirch", "tenserflew", "tensorflw", "numyp", "pandsa", "scikit_learn",
    "sckikit-learn", "pytoch", "tensorfow", "mlfolw", "fasapi",
}

# Доверенные индексы (PyPI и его зеркала)
TRUSTED_INDICES: set[str] = {
    "https://pypi.org/simple",
    "https://pypi.org/simple/",
    "https://files.pythonhosted.org",
    "https://pypi.org",
}

# Доверенные HF-пространства имён (для --find-links из HF)
TRUSTED_HF_PREFIXES = ("https://huggingface.co/", "https://hf.co/")

RE_REQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*([=<>!~]=?)?\s*([0-9A-Za-z.*\-+]+)?")


def _parse_requirements(req_text: str) -> tuple[list[tuple[str, str | None]], list[str]]:
    """Вернуть (пакеты, custom_indices). Пропускать опции и комментарии."""
    pkgs: list[tuple[str, str | None]] = []
    custom_indices: list[str] = []
    for raw_line in req_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        # Строки с индексами
        if line.startswith(("--index-url", "--extra-index-url", "-i ", "--find-links", "-f ")):
            parts = line.split(None, 1)
            url = parts[1].strip() if len(parts) > 1 else ""
            if url:
                custom_indices.append(url)
            continue
        # Пропустить остальные опции (--hash, -r, --require-hashes, etc.)
        if line.startswith("-"):
            continue
        m = RE_REQ.match(line)
        if m:
            pkgs.append((m.group(1).lower(), m.group(3)))
    return pkgs, custom_indices


def _normalize_name(name: str) -> str:
    """PEP 503 нормализация: нижний регистр, _ и - → -."""
    return re.sub(r"[-_.]+", "-", name.lower())


def gate_check(path: str) -> list[dict]:
    req_path = Path(path) / "requirements.txt" if Path(path).is_dir() else Path(path)
    if not req_path.exists():
        return [{"check": "requirements_present", "status": "SKIP", "severity": "low",
                 "detail": f"нет requirements.txt по пути {req_path}", "evidence": {}}]

    text = req_path.read_text(encoding="utf-8")
    pkgs, custom_indices = _parse_requirements(text)
    results: list[dict] = []

    # 1. Typosquatting / allow-list
    typosquats: list[str] = []
    unknown: list[str] = []
    for name, _ver in pkgs:
        norm = _normalize_name(name)
        if norm in KNOWN_TYPOSQUATS:
            typosquats.append(name)
        elif norm not in {_normalize_name(a) for a in ALLOWLIST}:
            unknown.append(name)
    bad_names = typosquats + unknown
    results.append({"check": "name_allowlist",
                    "status": "FAIL" if bad_names else "PASS",
                    "severity": "critical",
                    "detail": (f"вне allow-list/опечатки: {bad_names}" if bad_names
                               else "все имена доверенные"),
                    "evidence": {"typosquats": typosquats, "unknown": unknown}})

    # 2. Пиннинг версий (==конкретная_версия или с хешами)
    unpinned: list[str] = []
    for name, ver in pkgs:
        if not ver or "*" in (ver or ""):
            unpinned.append(name)
    results.append({"check": "version_pinning",
                    "status": "FAIL" if unpinned else "PASS",
                    "severity": "medium",
                    "detail": (f"незапиненные: {unpinned}" if unpinned
                               else "все версии запинены"),
                    "evidence": {"unpinned": unpinned}})

    # 3. Доверенный источник (--index-url / --extra-index-url / --find-links)
    untrusted_indices: list[str] = []
    for url in custom_indices:
        url_norm = url.rstrip("/")
        is_trusted = (
            any(url_norm.startswith(t.rstrip("/")) for t in TRUSTED_INDICES)
            or any(url_norm.startswith(p) for p in TRUSTED_HF_PREFIXES)
        )
        if not is_trusted:
            untrusted_indices.append(url)
    results.append({"check": "trusted_source",
                    "status": "FAIL" if untrusted_indices else "PASS",
                    "severity": "high",
                    "detail": (f"недоверенные индексы: {untrusted_indices}" if untrusted_indices
                               else "индексы не заданы или из доверенных"),
                    "evidence": {"custom_indices": custom_indices,
                                 "untrusted": untrusted_indices}})

    return results


def build_report(target: str, results: list[dict]) -> dict:
    failed = [r["check"] for r in results if r["status"] == "FAIL"]
    sev_summary: dict[str, list[str]] = {}
    for r in results:
        if r["status"] == "FAIL":
            sev = r.get("severity", "medium")
            sev_summary.setdefault(sev, []).append(r["check"])
    return {"gate": GATE, "asset": target, "passed": not failed,
            "checks": results, "failed_checks": failed, "severity_summary": sev_summary}


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
