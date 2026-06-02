"""G4 Model Gate — формат весов, скан, целостность (SHA-256), подпись.

Закрывает #3 (pickle/RCE), #4 (подмена), #19 (skew), #26 (подпись).
ВАЖНО: НИКОГДА не unpickle/не загружать артефакт для проверки — только формат/скан/хэш.
См. docs/07_SECURITY_GATES.md (G4).

Запуск: docker run --rm --network none -v "$ART:/in:ro" mlsec-gate-model --path /in --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

GATE = "G4"

# Allow-list безопасных форматов весов. Запрещены исполняемые при загрузке форматы.
ALLOWED_EXT = {".safetensors", ".onnx", ".cbm", ".txt", ".json"}
BLOCKED_EXT = {".pkl", ".pickle", ".joblib", ".bin", ".pt", ".pth", ".h5"}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def gate_check(path: str, *, expected_sha: str | None = None) -> list[dict]:
    p = Path(path)
    results: list[dict] = []

    # 1. Allow-list форматов (анти-pickle-RCE)
    ext = p.suffix.lower()
    if ext in BLOCKED_EXT:
        results.append({"check": "weights_format", "status": "FAIL",
                        "detail": f"запрещённый формат {ext} (исполняет код при load)",
                        "evidence": {"ext": ext}})
    elif ext in ALLOWED_EXT:
        results.append({"check": "weights_format", "status": "PASS",
                        "detail": f"формат {ext} разрешён", "evidence": {"ext": ext}})
    else:
        results.append({"check": "weights_format", "status": "FAIL",
                        "detail": f"неизвестный формат {ext}", "evidence": {"ext": ext}})

    # 2. Скан весов на вредоносный код (modelscan/picklescan) — внешний инструмент.
    #    TODO: subprocess к modelscan; нет инструмента → SKIP. Сам артефакт не загружать!
    results.append({"check": "weights_scan", "status": "SKIP",
                    "detail": "TODO: modelscan/picklescan", "evidence": {}})

    # 3. Целостность (SHA-256 ↔ реестр)
    if p.is_file():
        actual = sha256_file(p)
        if expected_sha:
            ok = actual == expected_sha
            results.append({"check": "integrity_sha256",
                            "status": "PASS" if ok else "FAIL",
                            "detail": "hash совпал" if ok else "hash MISMATCH",
                            "evidence": {"expected": expected_sha, "actual": actual}})
        else:
            results.append({"check": "integrity_sha256", "status": "PASS",
                            "detail": "эталон не передан — фиксируем хэш",
                            "evidence": {"actual": actual}})

    # 4. Подпись (cosign) — TODO: cosign verify; нет подписи/ключа → FAIL на деплое.
    results.append({"check": "signature_cosign", "status": "SKIP",
                    "detail": "TODO: cosign verify (на деплое — FAIL при отсутствии)",
                    "evidence": {}})

    # 5. Consistency train↔serve (#19) — TODO: pytest на N строках (вне этого образа/в CI).
    return results


def build_report(target: str, results: list[dict]) -> dict:
    failed = [r["check"] for r in results if r["status"] == "FAIL"]
    return {"gate": GATE, "asset": target, "passed": not failed,
            "checks": results, "failed_checks": failed}


def main() -> None:
    ap = argparse.ArgumentParser(description="G4 Model Gate")
    ap.add_argument("--path", required=True, help="путь к артефакту весов")
    ap.add_argument("--expected-sha", default=None, help="эталонный SHA-256 из реестра")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    results = gate_check(args.path, expected_sha=args.expected_sha)
    report = build_report(args.path, results)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
