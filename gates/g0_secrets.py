"""gates/g0_secrets.py — G0: секреты в артефактах рана.

Прогон gitleaks через subprocess, если бинарь есть (production-grade путь).
Если gitleaks недоступен — fallback на regex по AWS/OpenAI/Anthropic/JWT/private-key/generic
patterns (из fortress/scripts/ci/gate_code.py, расширенный набор).

Скан скачанных артефактов рана: model.pkl, code.py, requirements.txt, configs и т.п.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from gates.base import GateContext, GateResult, log_line, register_gate

# Регекспы для fallback-режима (когда нет gitleaks CLI).
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    ("openai_key", re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    ("anthropic_key", re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack_token", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("generic_password", re.compile(
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]")),
]
SCAN_EXTS = {".py", ".env", ".yaml", ".yml", ".sh", ".json", ".ini", ".toml",
             ".cfg", ".conf", ".txt", ".md", ".pkl"}
SKIP_PATH_PARTS = (".venv", "node_modules", "__pycache__", ".git", ".example")


def _run_gitleaks(target: Path, gid: str, gname: str, logs: list[str]) -> tuple[str, list[dict]]:
    """Запустить gitleaks; вернуть ('found'/'clean', findings[])."""
    out_json = target.parent / f"_gitleaks_{target.name}.json"
    cmd = ["gitleaks", "detect", "--source", str(target), "--no-git",
           "--redact", "--report-format", "json", "--report-path", str(out_json)]
    logs.append(log_line(gid, gname, f"$ {' '.join(cmd)}"))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        logs.append(log_line(gid, gname, "gitleaks timeout (>120s)"))
        return "error", []
    # gitleaks: rc=0 чистый, rc=1 нашёл секреты, остальные — ошибка
    if r.returncode == 0:
        return "clean", []
    if r.returncode == 1 and out_json.exists():
        try:
            data = json.loads(out_json.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            data = []
        return "found", data or []
    logs.append(log_line(gid, gname, f"gitleaks rc={r.returncode} stderr={r.stderr[:200]}"))
    return "error", []


def _fallback_scan(target: Path, gid: str, gname: str,
                   logs: list[str]) -> list[dict]:
    """Regex-fallback. Возвращает список сработок [{file, pattern, line}]."""
    hits: list[dict] = []
    for p in target.rglob("*") if target.is_dir() else [target]:
        if not p.is_file():
            continue
        if any(s in str(p) for s in SKIP_PATH_PARTS):
            continue
        if p.suffix.lower() not in SCAN_EXTS:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        for name, pat in PATTERNS:
            m = pat.search(text)
            if m:
                line_no = text.count("\n", 0, m.start()) + 1
                hits.append({"file": str(p.relative_to(target) if target.is_dir() else p.name),
                             "pattern": name, "line": line_no})
                if len(hits) >= 20:
                    return hits
    return hits


@register_gate("G0", name="Secrets", order=20,
               description="Секреты в артефактах (gitleaks → regex fallback)",
               severity="critical", threats=["#8", "#10"])
def run(ctx: GateContext) -> GateResult:
    gid, gname = "G0", "Secrets"
    logs = [log_line(gid, gname, f"scan: {ctx.work_dir}")]

    if not ctx.work_dir or not ctx.work_dir.exists() or not any(ctx.work_dir.iterdir()):
        logs.append(log_line(gid, gname, "SKIP: артефакты рана не скачаны / пусто"))
        return GateResult(id=gid, name=gname, status="SKIP",
                          detail="Артефактов нет — нечего сканировать.", logs=logs,
                          evidence={"reason": "empty_workdir"})

    use_gitleaks = shutil.which("gitleaks") is not None and \
        os.getenv("G0_FORCE_FALLBACK", "").lower() not in ("1", "true", "yes")

    if use_gitleaks:
        logs.append(log_line(gid, gname, "tool: gitleaks (production-grade)"))
        status, findings = _run_gitleaks(ctx.work_dir, gid, gname, logs)
        if status == "clean":
            logs.append(log_line(gid, gname, "PASS: секреты не найдены"))
            return GateResult(id=gid, name=gname, status="PASS",
                              detail="Секретов не обнаружено (gitleaks).",
                              logs=logs, evidence={"scanner": "gitleaks", "findings": 0})
        if status == "found":
            n = len(findings)
            for f in findings[:3]:
                logs.append(log_line(gid, gname,
                            f"  hit: {f.get('RuleID', '?')} in {f.get('File', '?')}:{f.get('StartLine', '?')}"))
            return GateResult(id=gid, name=gname, status="FAIL", severity="critical",
                              detail=f"Найдены {n} секретов (gitleaks).",
                              logs=logs, evidence={"scanner": "gitleaks",
                                                   "findings": findings[:10],
                                                   "n_findings": n})
        # error → деградируем в fallback
        logs.append(log_line(gid, gname, "gitleaks ошибка — переключаюсь на regex-fallback"))

    logs.append(log_line(gid, gname, "tool: regex-fallback (gitleaks недоступен)"))
    hits = _fallback_scan(ctx.work_dir, gid, gname, logs)
    if not hits:
        logs.append(log_line(gid, gname, f"PASS: regex-fallback, паттернов: {len(PATTERNS)}"))
        return GateResult(id=gid, name=gname, status="PASS",
                          detail=f"Секретов не найдено (regex, {len(PATTERNS)} паттернов).",
                          logs=logs, evidence={"scanner": "regex_fallback",
                                               "patterns": len(PATTERNS), "findings": 0})
    for h in hits[:3]:
        logs.append(log_line(gid, gname, f"  hit: {h['pattern']} in {h['file']}:{h['line']}"))
    return GateResult(id=gid, name=gname, status="FAIL", severity="critical",
                      detail=f"Найдены {len(hits)} потенциальных секретов (regex).",
                      logs=logs, evidence={"scanner": "regex_fallback",
                                           "findings": hits[:10], "n_findings": len(hits)})
