"""G2 Code Gate — секреты + SAST + CVE зависимостей + CVE образа (deploy).

Закрывает #8 (CVE), #10 (секреты). См. docs/07_SECURITY_GATES.md (G2).
Инструменты: gitleaks, bandit, pip-audit; trivy только на стадии deploy.
Гейт сам в БД не пишет; graceful SKIP при отсутствии инструмента.

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
    """Запустить сканер без shell. Нет бинарника → rc=127."""
    if shutil.which(cmd[0]) is None:
        return 127, f"{cmd[0]} not installed"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # nosec B603
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def _extract_json(out: str) -> object:
    """Извлечь первый JSON-объект/массив из строки.

    Находит самое раннее вхождение '{' или '[' (начало JSON), игнорируя
    предшествующий не-JSON текст (например, warnings из stderr).
    """
    brace = out.find("{")
    bracket = out.find("[")
    if brace == -1 and bracket == -1:
        return None
    if brace == -1:
        start = bracket
    elif bracket == -1:
        start = brace
    else:
        start = min(brace, bracket)
    try:
        obj, _ = json.JSONDecoder().raw_decode(out, start)
        return obj
    except (ValueError, json.JSONDecodeError):
        return None


def _parse_gitleaks(out: str) -> list[dict]:
    """Parse gitleaks JSON → список {rule, file, line, match}."""
    try:
        data = _extract_json(out)
        if data is None or out.strip() in ("null", ""):
            return []
        if not isinstance(data, list):
            return []
        return [
            {"rule": f.get("RuleID", "?"),
             "file": f.get("File", "?"),
             "line": f.get("StartLine", 0),
             "match": (f.get("Match") or "")[:80]}
            for f in data
        ]
    except (AttributeError, TypeError):
        return []


def check_secrets(path: str) -> dict:
    """gitleaks — любой detect → FAIL (critical)."""
    rc, out = _run(["gitleaks", "detect", "--source", path, "--no-banner",
                    "--report-format", "json", "--no-git"])
    if rc == 127:
        return {"check": "secrets", "status": "SKIP", "severity": "critical",
                "detail": "gitleaks не установлен", "evidence": {}}
    findings = _parse_gitleaks(out)
    found = rc != 0 or bool(findings)
    return {"check": "secrets",
            "status": "FAIL" if found else "PASS",
            "severity": "critical",
            "detail": f"найдено секретов: {len(findings)}" if found else "секретов нет",
            "evidence": {"findings": findings, "raw_exit": rc}}


def _parse_bandit(out: str) -> list[dict]:
    """Parse bandit JSON → HIGH-severity issues only."""
    try:
        data = _extract_json(out)
        if data is None:
            return []
        results = data.get("results", []) if isinstance(data, dict) else []
        return [
            {"test": r.get("test_name", "?"),
             "test_id": r.get("test_id", "?"),
             "file": r.get("filename", "?"),
             "line": r.get("line_number", 0),
             "severity": r.get("issue_severity", "?"),
             "confidence": r.get("issue_confidence", "?"),
             "text": (r.get("issue_text") or "")[:100]}
            for r in results
            if r.get("issue_severity") == "HIGH"
        ]
    except (json.JSONDecodeError, AttributeError):
        return []


def check_sast(path: str) -> dict:
    """bandit — FAIL только при HIGH-severity issues."""
    rc, out = _run(["bandit", "-r", path, "-f", "json", "-q"])
    if rc == 127:
        return {"check": "sast", "status": "SKIP", "severity": "high",
                "detail": "bandit не установлен", "evidence": {}}
    issues = _parse_bandit(out)
    found = bool(issues)
    return {"check": "sast",
            "status": "FAIL" if found else "PASS",
            "severity": "high",
            "detail": f"HIGH-issues: {len(issues)}" if found else "HIGH-issues не найдено",
            "evidence": {"high_issues": issues}}


def _parse_pip_audit(out: str) -> list[dict]:
    """Parse pip-audit JSON → список уязвимостей."""
    raw = _extract_json(out)
    if raw is None:
        return []
    # pip-audit v2 обёрнут в {"dependencies": [...]}, v1 — просто список
    if isinstance(raw, dict):
        deps = raw.get("dependencies", [])
    elif isinstance(raw, list):
        deps = raw
    else:
        return []
    vulns = []
    for dep in deps:
        for v in dep.get("vulns", []):
            vulns.append({
                "package": dep.get("name", "?"),
                "version": dep.get("version", "?"),
                "id": v.get("id", "?"),
                "aliases": v.get("aliases", []),
                "fix_versions": v.get("fix_versions", []),
            })
    return vulns


def _resolve_requirements_file(path: str) -> str | None:
    """Файл зависимостей: явный .txt, рядом с path, либо корень репо (CI: --path src)."""
    import os

    if path.endswith(".txt") and os.path.isfile(path):
        return path
    local = os.path.join(path, "requirements.txt")
    if os.path.isfile(local):
        return local
    for candidate in ("requirements.txt", os.path.join(os.getcwd(), "requirements.txt")):
        if os.path.isfile(candidate):
            return candidate
    return None


def check_cve(path: str) -> dict:
    """pip-audit — FAIL при любых известных CVE."""
    req = _resolve_requirements_file(path)
    if not req:
        return {"check": "cve_deps", "status": "SKIP", "severity": "critical",
                "detail": f"requirements.txt не найден для {path}", "evidence": {}}
    rc, out = _run(["pip-audit", "-r", req, "-f", "json"])
    if rc == 127:
        return {"check": "cve_deps", "status": "SKIP", "severity": "critical",
                "detail": "pip-audit не установлен", "evidence": {}}
    vulns = _parse_pip_audit(out)
    found = bool(vulns)
    return {"check": "cve_deps",
            "status": "FAIL" if found else "PASS",
            "severity": "critical",
            "detail": f"уязвимых пакетов: {len(vulns)}" if found else "уязвимостей нет",
            "evidence": {"vulns": vulns}}


def _parse_trivy(out: str) -> list[dict]:
    """Parse trivy JSON → CRITICAL/HIGH CVE list."""
    data = _extract_json(out)
    if data is None:
        return []
    cves = []
    for r in (data.get("Results") or []):
        for v in (r.get("Vulnerabilities") or []):
            if v.get("Severity") in ("CRITICAL", "HIGH"):
                cves.append({
                    "cve": v.get("VulnerabilityID", "?"),
                    "pkg": v.get("PkgName", "?"),
                    "installed": v.get("InstalledVersion", "?"),
                    "fixed": v.get("FixedVersion", "?"),
                    "severity": v.get("Severity", "?"),
                    "title": (v.get("Title") or "")[:120],
                })
    return cves


def check_image_trivy(image: str) -> dict:
    """trivy image — запускается РОВНО ОДИН РАЗ на стадии deploy."""
    rc, out = _run(["trivy", "image", "--severity", "CRITICAL,HIGH",
                    "--format", "json", "--exit-code", "1", image])
    if rc == 127:
        return {"check": "trivy_image", "status": "SKIP", "severity": "critical",
                "detail": "trivy не установлен", "evidence": {}}
    cves = _parse_trivy(out)
    found = bool(cves)
    return {"check": "trivy_image",
            "status": "FAIL" if found else "PASS",
            "severity": "critical",
            "detail": f"критичных CVE в образе: {len(cves)}" if found else "CVE не найдено",
            "evidence": {"cves": cves}}


def check_semgrep(path: str) -> dict:
    """ML-aware SAST через semgrep (дополняет bandit). Нет бинарника → SKIP."""
    rc, out = _run(["semgrep", "--config", "auto", "--json", "--quiet",
                    "--severity", "ERROR", path])
    if rc == 127:
        return {"check": "semgrep", "status": "SKIP", "severity": "high",
                "detail": "semgrep не установлен", "evidence": {}}
    n = 0
    try:
        n = len(json.loads(out).get("results", []))
    except Exception:  # noqa: BLE001
        n = 1 if rc != 0 else 0
    return {"check": "semgrep", "status": "FAIL" if n else "PASS", "severity": "high",
            "detail": f"semgrep findings: {n}" if n else "ok", "evidence": {"count": n}}


def gate_check(path: str, *, stage: str = "ci", image: str | None = None) -> list[dict]:
    results = [check_secrets(path), check_sast(path), check_semgrep(path), check_cve(path)]
    if stage == "deploy" and image:  # trivy запускается РОВНО ОДИН раз — на деплое
        results.append(check_image_trivy(image))
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
    ap = argparse.ArgumentParser(description="G2 Code Gate")
    ap.add_argument("--path", required=True)
    ap.add_argument("--stage", choices=["ci", "deploy"], default="ci")
    ap.add_argument("--image", default=None, help="docker-образ для trivy (только stage=deploy)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="SKIP трактовать как FAIL (нет сканера → блок для критичных активов)")
    args = ap.parse_args()

    results = gate_check(args.path, stage=args.stage, image=args.image)
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
