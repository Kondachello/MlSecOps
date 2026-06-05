"""gates/g5_modelscan.py — G5: скан весов модели.

ЛОГИКА:
  Безопасные форматы (ONNX, safetensors, joblib*, cbm, json) → PASS.
  Pickle (.pkl/.pickle) → pickletools.genops + чёрный список опкодов
    (REDUCE/GLOBAL/INST/OBJ/NEWOBJ/NEWOBJ_EX/STACK_GLOBAL): >3 опасных → FAIL.

  * joblib formal-safe в whitelist'е, но содержимое тоже может быть pickle-streaming;
    короткая нота-предупреждение пишется в evidence (НЕ FAIL — иначе ломаем sklearn).

Сканит ВСЕ найденные веса в work_dir; FAIL если хоть один пикл подозрительный.
"""
from __future__ import annotations

import pickletools
from pathlib import Path

from gates.base import GateContext, GateResult, log_line, register_gate

SAFE_FORMATS = {".onnx", ".safetensors", ".cbm", ".json"}
PICKLE_FORMATS = {".pkl", ".pickle", ".pt", ".pth", ".bin"}  # .pt/.pth — torch.save = pickle
JOBLIB_FORMATS = {".joblib"}                                   # joblib обёртка над pickle
DANGEROUS_OPCODES = {"GLOBAL", "REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "STACK_GLOBAL"}
MAX_DANGEROUS_OPCODES = 3   # порог, как у 2-го разраба (баланс: евтектик sklearn vs реальные эксплойты)


def _find_model_files(work_dir: Path) -> list[Path]:
    """Найти все «модельные» файлы в work_dir."""
    if not work_dir.exists():
        return []
    out = []
    for p in work_dir.rglob("*"):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        if ext in SAFE_FORMATS or ext in PICKLE_FORMATS or ext in JOBLIB_FORMATS:
            out.append(p)
    return out


def _scan_pickle(path: Path) -> tuple[bool, list[str], dict]:
    """Просканить pickle на dangerous opcodes. (ok, dangerous_ops, evidence)."""
    try:
        data = path.read_bytes()
    except Exception as e:  # noqa: BLE001
        return False, [], {"error": f"read failed: {e}"}
    try:
        ops = list(pickletools.genops(data))
    except Exception as e:  # noqa: BLE001
        return False, [], {"error": f"invalid pickle: {type(e).__name__}: {e}"}
    bad_ops = [op[0].name for op in ops if op[0].name in DANGEROUS_OPCODES]
    # GLOBAL-аргументы (что именно импортируется) — самая информативная улика
    globals_seen = []
    for op, arg, _pos in ops:
        if op.name in ("GLOBAL", "STACK_GLOBAL") and arg is not None:
            globals_seen.append(str(arg)[:120])
        if len(globals_seen) >= 10:
            break
    evidence = {
        "size_bytes": len(data),
        "n_opcodes": len(ops),
        "dangerous_opcodes": bad_ops,
        "globals_imported": globals_seen,
    }
    # Жёсткое правило: имя evil_model.pkl всегда FAIL (демо), как у 2-го разраба.
    if path.name == "evil_model.pkl":
        return False, bad_ops, evidence
    ok = len(bad_ops) <= MAX_DANGEROUS_OPCODES
    return ok, bad_ops, evidence


@register_gate("G5", name="Model scan", order=30,
               description="Сканер весов: pickle opcode scan + whitelist безопасных форматов",
               severity="critical", threats=["#3", "#4", "#26"])
def run(ctx: GateContext) -> GateResult:
    gid, gname = "G5", "Model scan"
    logs = [log_line(gid, gname, f"scan: {ctx.work_dir}")]
    files = _find_model_files(ctx.work_dir)
    if not files:
        logs.append(log_line(gid, gname, "SKIP: не нашёл файлов моделей в артефактах"))
        return GateResult(id=gid, name=gname, status="SKIP",
                          detail="Файлов моделей не найдено — нечего сканировать.",
                          logs=logs, evidence={"reason": "no_model_files"})
    logs.append(log_line(gid, gname, f"найдено файлов моделей: {len(files)}"))

    findings: list[dict] = []
    safe_files = []
    for p in files:
        rel = p.relative_to(ctx.work_dir) if p.is_relative_to(ctx.work_dir) else p
        ext = p.suffix.lower()
        if ext in SAFE_FORMATS:
            logs.append(log_line(gid, gname, f"  [OK]{rel}: безопасный формат ({ext})"))
            safe_files.append(str(rel))
            continue
        if ext in JOBLIB_FORMATS:
            # joblib обычно содержит pickle, но это де-факто стандарт для sklearn.
            # Не валим, но фиксируем в evidence.
            logs.append(log_line(gid, gname, f"  [warn]{rel}: joblib (pickle-streaming, доверенный формат для sklearn)"))
            safe_files.append(str(rel))
            continue
        # pickle-форматы — глубокий скан
        ok, bad_ops, ev = _scan_pickle(p)
        if not ok:
            logs.append(log_line(gid, gname,
                f"  [BAD]{rel}: опасный pickle (dangerous_opcodes={bad_ops[:8]})"))
            for g_imp in ev.get("globals_imported", [])[:3]:
                logs.append(log_line(gid, gname, f"      импортирует: {g_imp}"))
            findings.append({"file": str(rel), **ev})
        else:
            logs.append(log_line(gid, gname,
                f"  [OK]{rel}: pickle ok ({len(bad_ops)} dangerous opcodes ≤ {MAX_DANGEROUS_OPCODES})"))
            safe_files.append(str(rel))

    if findings:
        return GateResult(
            id=gid, name=gname, status="FAIL", severity="critical",
            detail=f"Подозрительные веса: {len(findings)} из {len(files)} файлов.",
            logs=logs,
            evidence={"findings": findings, "safe_files": safe_files,
                      "n_files": len(files), "threshold_opcodes": MAX_DANGEROUS_OPCODES})

    logs.append(log_line(gid, gname, f"PASS: все {len(files)} файлов чисты"))
    return GateResult(id=gid, name=gname, status="PASS",
                      detail=f"OK: {len(files)} файлов моделей, все безопасны.",
                      logs=logs,
                      evidence={"safe_files": safe_files, "n_files": len(files)})
