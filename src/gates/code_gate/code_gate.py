"""G2 Code Gate — секреты + SAST + CVE зависимостей. Стадии: ci | deploy (deploy + trivy).

Закрывает #8 (CVE), #10 (секреты). См. docs/07_SECURITY_GATES.md (G2).
Инструменты вызываются как внешние бинарники; нет инструмента → SKIP (graceful), не падаем.
Гейт сам в БД не пишет. Скелет: обвязка готова, разбор вывода инструментов — TODO.

Запуск: docker run --rm -v "$CODE:/in:ro" mlsec-gate-code --path /in --stage ci --json
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess  # nosec B404 — вызываем доверенные сканеры по фикс. аргументам, без shell
import sys

GATE = "G2"


def _run(cmd: list[str]) -> tuple[int, str]:
    """Запустить сканер без shell. Возвращает (rc, output). Нет бинарника → rc=127."""
    if shutil.which(cmd[0]) is None:
        return 127, f"{cmd[0]} not installed"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # nosec B603
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def check_secrets(path: str) -> dict:
    rc, out = _run(["gitleaks", "detect", "--source", path, "--no-banner",
                    "--report-format", "json"])
    if rc == 127:
        return {"check": "secrets", "status": "SKIP", "detail": out, "evidence": {}}
    # gitleaks: rc!=0 → найдены секреты. TODO: распарсить JSON-отчёт в evidence.
    found = rc != 0
    return {"check": "secrets", "status": "FAIL" if found else "PASS",
            "detail": "секреты найдены" if found else "секретов нет", "evidence": {}}


def check_sast(path: str) -> dict:
    rc, out = _run(["bandit", "-r", path, "-f", "json", "-q"])
    if rc == 127:
        return {"check": "sast", "status": "SKIP", "detail": out, "evidence": {}}
    # TODO: парсить bandit JSON, FAIL только при HIGH-severity issues.
    return {"check": "sast", "status": "FAIL" if rc != 0 else "PASS",
            "detail": "bandit issues" if rc != 0 else "ok", "evidence": {}}


def check_cve(path: str) -> dict:
    req = f"{path}/requirements.txt"
    rc, out = _run(["pip-audit", "-r", req, "-f", "json"])
    if rc == 127:
        return {"check": "cve_deps", "status": "SKIP", "detail": out, "evidence": {}}
    # TODO: парсить, FAIL при CRITICAL/HIGH.
    return {"check": "cve_deps", "status": "FAIL" if rc != 0 else "PASS",
            "detail": "уязвимые зависимости" if rc != 0 else "ok", "evidence": {}}


def check_image_trivy(image: str) -> dict:
    rc, out = _run(["trivy", "image", "--severity", "CRITICAL,HIGH", "--exit-code", "1", image])
    if rc == 127:
        return {"check": "trivy_image", "status": "SKIP", "detail": out, "evidence": {}}
    return {"check": "trivy_image", "status": "FAIL" if rc != 0 else "PASS",
            "detail": "критичные CVE в образе" if rc != 0 else "ok", "evidence": {}}


def gate_check(path: str, *, stage: str = "ci", image: str | None = None) -> list[dict]:
    results = [check_secrets(path), check_sast(path), check_cve(path)]
    if stage == "deploy" and image:  # trivy запускается РОВНО ОДИН раз — на деплое
        results.append(check_image_trivy(image))
    return results


def build_report(target: str, results: list[dict]) -> dict:
    failed = [r["check"] for r in results if r["status"] == "FAIL"]
    return {"gate": GATE, "asset": target, "passed": not failed,
            "checks": results, "failed_checks": failed}


def main() -> None:
    ap = argparse.ArgumentParser(description="G2 Code Gate")
    ap.add_argument("--path", required=True)
    ap.add_argument("--stage", choices=["ci", "deploy"], default="ci")
    ap.add_argument("--image", default=None, help="docker-образ для trivy (только stage=deploy)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    results = gate_check(args.path, stage=args.stage, image=args.image)
    report = build_report(args.path, results)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
