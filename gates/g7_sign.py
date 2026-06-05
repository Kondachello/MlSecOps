"""gates/g7_sign.py — G7: integrity / подпись артефакта (SHA256 manifest).

ЛОГИКА:
  1. Найти артефакт модели (предпочтительно ONNX/safetensors; иначе самый крупный из весов).
  2. Посчитать SHA256.
  3. Сложить manifest.json + <model>.sig в work_dir (для последующей верификации).

ЛОГИКА FAIL:
  - Нет файла модели → SKIP (не FAIL: на ранах без модели гейт неприменим).
  - Прочитать не удалось → FAIL.

NB: реальная криптоподпись (Sigstore / Ed25519 из fortress/attestation.py) — следующий
эшелон. Сейчас manifest+sha — это минимум integrity, который мы можем верифицировать
позже на promote.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from gates.base import GateContext, GateResult, log_line, register_gate

PREFERRED_EXTS = (".onnx", ".safetensors")
ANY_MODEL_EXTS = (".onnx", ".safetensors", ".joblib", ".pkl", ".pt", ".pth", ".cbm", ".bin")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_main_artifact(work_dir: Path) -> Path | None:
    """Главный артефакт для подписи: .onnx/.safetensors → любой *.{joblib,pkl,...}."""
    if not work_dir.exists():
        return None
    # 1) предпочтительные форматы
    for ext in PREFERRED_EXTS:
        files = sorted(work_dir.rglob(f"*{ext}"))
        if files:
            return files[0]
    # 2) любой модельный файл (самый большой)
    candidates = []
    for ext in ANY_MODEL_EXTS:
        candidates.extend(work_dir.rglob(f"*{ext}"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


@register_gate("G7", name="Artifact sign", order=40,
               description="SHA256 manifest + .sig артефакта (для верификации на promote)",
               severity="medium", threats=["#3", "#4", "#26"])
def run(ctx: GateContext) -> GateResult:
    gid, gname = "G7", "Artifact sign"
    logs = [log_line(gid, gname, f"scan: {ctx.work_dir}")]

    artifact = _find_main_artifact(ctx.work_dir)
    if artifact is None:
        logs.append(log_line(gid, gname, "SKIP: нет файла модели для подписи"))
        return GateResult(id=gid, name=gname, status="SKIP",
                          detail="Файла модели не найдено — подписывать нечего.",
                          logs=logs, evidence={"reason": "no_artifact"})

    rel = artifact.relative_to(ctx.work_dir) if artifact.is_relative_to(ctx.work_dir) else artifact
    logs.append(log_line(gid, gname, f"артефакт: {rel} ({artifact.stat().st_size} bytes)"))

    try:
        digest = _sha256(artifact)
    except Exception as e:  # noqa: BLE001
        logs.append(log_line(gid, gname, f"FAIL: чтение артефакта: {e}"))
        return GateResult(id=gid, name=gname, status="FAIL",
                          detail=f"Не смог прочитать артефакт: {e}",
                          logs=logs, evidence={"error": str(e)})

    logs.append(log_line(gid, gname, f"sha256: {digest}"))

    sig_path = artifact.with_suffix(artifact.suffix + ".sig")
    manifest_path = artifact.parent / "manifest.json"
    manifest = {
        "algorithm": "sha256",
        "digest": digest,
        "file": artifact.name,
        "size_bytes": artifact.stat().st_size,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "run_id": ctx.run_id,
        "note": "minimal-integrity manifest (Ed25519/Sigstore — следующий эшелон)",
    }
    try:
        sig_path.write_text(digest + "\n", encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        logs.append(log_line(gid, gname, f"FAIL: запись manifest/sig: {e}"))
        return GateResult(id=gid, name=gname, status="FAIL",
                          detail=f"Не смог записать manifest: {e}",
                          logs=logs, evidence={"error": str(e)})

    # самопроверка: перечитать и сверить
    if json.loads(manifest_path.read_text(encoding="utf-8"))["digest"] != digest:
        logs.append(log_line(gid, gname, "FAIL: digest mismatch после чтения manifest"))
        return GateResult(id=gid, name=gname, status="FAIL",
                          detail="manifest digest mismatch", logs=logs,
                          evidence={"digest": digest})

    logs.append(log_line(gid, gname, f"PASS: manifest={manifest_path.name} sig={sig_path.name}"))
    return GateResult(
        id=gid, name=gname, status="PASS",
        detail=f"OK: SHA256 {digest[:16]}… (manifest + .sig созданы).",
        logs=logs,
        evidence={"digest": digest, "file": str(rel), "size_bytes": manifest["size_bytes"],
                  "manifest_path": str(manifest_path.relative_to(ctx.work_dir)
                                        if manifest_path.is_relative_to(ctx.work_dir)
                                        else manifest_path)})
