"""G4 Model Gate — формат весов, скан на вредоносный код, целостность SHA-256, подпись.

Закрывает #3 (pickle/RCE), #4 (подмена), #19 (skew), #26 (подпись).
ВАЖНО: НИКОГДА не unpickle/не загружать артефакт — только формат/скан/хэш.
Graceful SKIP при отсутствии инструмента (netscan, cosign).
Гейт сам в БД не пишет.

Запуск: docker run --rm --network none -v "$ART:/in:ro" mlsec-gate-model --path /in --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess  # nosec B404 — внешние доверенные инструменты, без shell
import sys
from pathlib import Path

GATE = "G4"

# Allow-list безопасных форматов. Запрещены форматы, исполняющие код при загрузке.
ALLOWED_EXT: set[str] = {".safetensors", ".onnx", ".cbm", ".txt", ".json", ".pb", ".tflite"}
BLOCKED_EXT: set[str] = {".pkl", ".pickle", ".joblib", ".bin", ".pt", ".pth", ".h5", ".npy", ".npz"}


def _run(cmd: list[str]) -> tuple[int, str]:
    """Запустить инструмент без shell. Нет бинарника → rc=127."""
    if shutil.which(cmd[0]) is None:
        return 127, f"{cmd[0]} not installed"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # nosec B603
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_format(path: str) -> dict:
    """Allow-list форматов (анти-pickle-RCE). Файл или директория."""
    p = Path(path)
    if p.is_dir():
        # Рекурсивно проверяем все файлы в директории
        bad_files = [str(f) for f in p.rglob("*") if f.is_file()
                     and f.suffix.lower() in BLOCKED_EXT]
        if bad_files:
            return {"check": "weights_format", "status": "FAIL", "severity": "critical",
                    "detail": f"запрещённые форматы в директории: {bad_files[:5]}",
                    "evidence": {"blocked_files": bad_files[:10]}}
        # Проверяем наличие хотя бы одного разрешённого файла весов
        allowed_files = [str(f) for f in p.rglob("*") if f.is_file()
                         and f.suffix.lower() in ALLOWED_EXT]
        if not allowed_files:
            return {"check": "weights_format", "status": "FAIL", "severity": "critical",
                    "detail": "директория не содержит файлов с разрешёнными расширениями",
                    "evidence": {"allowed_ext": sorted(ALLOWED_EXT)}}
        return {"check": "weights_format", "status": "PASS", "severity": "critical",
                "detail": f"форматы разрешены ({len(allowed_files)} файлов)",
                "evidence": {"allowed_files": allowed_files[:5]}}

    ext = p.suffix.lower()
    if ext in BLOCKED_EXT:
        return {"check": "weights_format", "status": "FAIL", "severity": "critical",
                "detail": f"запрещённый формат {ext} — исполняет произвольный код при load()",
                "evidence": {"ext": ext, "blocked_ext": sorted(BLOCKED_EXT)}}
    if ext in ALLOWED_EXT:
        return {"check": "weights_format", "status": "PASS", "severity": "critical",
                "detail": f"формат {ext} разрешён", "evidence": {"ext": ext}}
    return {"check": "weights_format", "status": "FAIL", "severity": "critical",
            "detail": f"неизвестный формат {ext} — fail-safe блок",
            "evidence": {"ext": ext, "allowed_ext": sorted(ALLOWED_EXT)}}


def _parse_modelscan(out: str) -> tuple[bool, list[dict]]:
    """Parse modelscan JSON. FAIL при CRITICAL/HIGH issues."""
    try:
        data = json.loads(out) if out.strip() else {}
    except (json.JSONDecodeError, ValueError):
        return False, []
    sevs = data.get("total_issues_by_severity", {})
    dangerous = sevs.get("CRITICAL", 0) + sevs.get("HIGH", 0)
    all_issues = data.get("all_issues", [])
    findings = [
        {"source": i.get("source", {}).get("name", "?") if isinstance(i.get("source"), dict) else str(i.get("source", "?")),
         "severity": i.get("severity", "?"),
         "description": (i.get("description") or "")[:200]}
        for i in all_issues
    ]
    return dangerous > 0 or bool(findings), findings


def check_scan(path: str) -> dict:
    """Сканирование весов на вредоносный код (modelscan → picklescan → SKIP)."""
    rc, out = _run(["modelscan", "-p", path, "--json"])
    if rc != 127:
        found, findings = _parse_modelscan(out)
        return {"check": "weights_scan",
                "status": "FAIL" if found else "PASS",
                "severity": "critical",
                "detail": (f"modelscan: найдено {len(findings)} проблем(ы)" if found
                           else "modelscan: вредоносный код не найден"),
                "evidence": {"scanner": "modelscan", "findings": findings}}

    # Fallback: picklescan (только для .pkl/.pickle)
    p = Path(path)
    ext = p.suffix.lower() if p.is_file() else ""
    if ext in (".pkl", ".pickle"):
        rc2, out2 = _run(["picklescan", "-p", path])
        if rc2 != 127:
            found2 = rc2 != 0
            return {"check": "weights_scan",
                    "status": "FAIL" if found2 else "PASS",
                    "severity": "critical",
                    "detail": ("picklescan: вредоносные opcode найдены" if found2
                               else "picklescan: ok"),
                    "evidence": {"scanner": "picklescan", "output": out2[:300]}}

    return {"check": "weights_scan", "status": "SKIP", "severity": "critical",
            "detail": "modelscan/picklescan не установлены — установить в Dockerfile",
            "evidence": {}}


def check_integrity(path: str, *, expected_sha: str | None = None) -> dict:
    """SHA-256 целостность: мismatch → деплой отменён (#4)."""
    p = Path(path)
    if not p.is_file():
        # Директория: считаем SHA по всем файлам (конкатенация)
        h = hashlib.sha256()
        for f in sorted(p.rglob("*")):
            if f.is_file():
                with f.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
        actual = h.hexdigest()
    else:
        actual = sha256_file(p)

    if expected_sha:
        ok = actual == expected_sha
        return {"check": "integrity_sha256",
                "status": "PASS" if ok else "FAIL",
                "severity": "critical",
                "detail": "SHA-256 совпадает" if ok else "SHA-256 MISMATCH — артефакт подменён!",
                "evidence": {"expected": expected_sha, "actual": actual}}
    return {"check": "integrity_sha256", "status": "PASS", "severity": "critical",
            "detail": "эталон не передан — фиксируем хэш",
            "evidence": {"actual": actual}}


def check_signature(path: str, *, cosign_key: str | None = None,
                    require_signature: bool = False) -> dict:
    """cosign verify-blob. Нет ключа/подписи → SKIP (или FAIL если require_signature=True)."""
    if not cosign_key:
        status = "FAIL" if require_signature else "SKIP"
        return {"check": "signature_cosign", "status": status, "severity": "high",
                "detail": ("ключ cosign не передан — обязательна подпись на деплое"
                           if require_signature else "ключ cosign не передан — SKIP"),
                "evidence": {}}

    sig_path = path + ".sig"
    if not Path(sig_path).exists():
        status = "FAIL" if require_signature else "SKIP"
        return {"check": "signature_cosign", "status": status, "severity": "high",
                "detail": (f"файл подписи {sig_path} не найден"
                           + (" — FAIL на деплое" if require_signature else "")),
                "evidence": {"expected_sig": sig_path}}

    rc, out = _run(["cosign", "verify-blob", "--key", cosign_key,
                    "--signature", sig_path, path])
    if rc == 127:
        status = "FAIL" if require_signature else "SKIP"
        return {"check": "signature_cosign", "status": status, "severity": "high",
                "detail": "cosign не установлен" + (" — FAIL на деплое" if require_signature else ""),
                "evidence": {}}
    ok = rc == 0
    return {"check": "signature_cosign",
            "status": "PASS" if ok else "FAIL",
            "severity": "high",
            "detail": "подпись cosign валидна" if ok else f"подпись НЕВАЛИДНА: {out[:200]}",
            "evidence": {"key": cosign_key, "sig": sig_path, "cosign_output": out[:500]}}


def check_consistency(consistency_script: str | None = None) -> dict:
    """Consistency train↔serve (#19): запускает pytest-скрипт или SKIP.
    Вынесено в CI за пределы образа; гейт сигнализирует результат."""
    if not consistency_script:
        return {"check": "consistency_train_serve", "status": "SKIP", "severity": "high",
                "detail": "consistency-скрипт не передан (--consistency-script). "
                           "Запустите pytest-тест в CI отдельным шагом.",
                "evidence": {}}
    rc, out = _run(["pytest", consistency_script, "-v", "--tb=short", "-q"])
    if rc == 127:
        return {"check": "consistency_train_serve", "status": "SKIP", "severity": "high",
                "detail": "pytest не установлен", "evidence": {}}
    return {"check": "consistency_train_serve",
            "status": "PASS" if rc == 0 else "FAIL",
            "severity": "high",
            "detail": "предсказания train=serve" if rc == 0 else f"РАСХОЖДЕНИЕ train↔serve: {out[:300]}",
            "evidence": {"script": consistency_script, "output": out[:500]}}


def gate_check(path: str, *, expected_sha: str | None = None,
               cosign_key: str | None = None, require_signature: bool = False,
               consistency_script: str | None = None) -> list[dict]:
    results = [
        check_format(path),
        check_scan(path),
        check_integrity(path, expected_sha=expected_sha),
        check_signature(path, cosign_key=cosign_key, require_signature=require_signature),
        check_consistency(consistency_script),
    ]
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
    ap = argparse.ArgumentParser(description="G4 Model Gate")
    ap.add_argument("--path", required=True, help="путь к артефакту весов или директории")
    ap.add_argument("--expected-sha", default=None, help="эталонный SHA-256 из реестра")
    ap.add_argument("--cosign-key", default=None, help="путь к публичному ключу cosign")
    ap.add_argument("--require-signature", action="store_true",
                    help="FAIL если подпись отсутствует (обязательно на деплое)")
    ap.add_argument("--consistency-script", default=None,
                    help="pytest-скрипт для проверки train↔serve consistency")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="SKIP трактовать как FAIL (нет modelscan/cosign → блок для критичных)")
    args = ap.parse_args()

    results = gate_check(
        args.path,
        expected_sha=args.expected_sha,
        cosign_key=args.cosign_key,
        require_signature=args.require_signature,
        consistency_script=args.consistency_script,
    )
    if args.fail_closed:
        for r in results:
            if r.get("status") == "SKIP":
                r["status"] = "FAIL"
                r["detail"] = "fail-closed: " + r.get("detail", "")
    report = build_report(args.path, results)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
