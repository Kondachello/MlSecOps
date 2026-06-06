"""gates/runner.py — оркестратор security-гейтов.

Скачивает артефакты MLflow-рана во временную папку, запускает выбранные гейты
по порядку, печатает построчные логи в stdout и в конце выводит финальный
JSON-блок с агрегатом (для бэкенда).

ЗАПУСК (CLI):
  python -m gates.runner --run-id RUN_ID                # вся цепочка
  python -m gates.runner --run-id RUN_ID --only G5      # один гейт
  python -m gates.runner --run-id RUN_ID --from G5      # с G5 до конца цепочки

КОНТРАКТ stdout:
  Перед финальным JSON-блоком — построчные логи (для прогресс-вью).
  Финальный JSON-блок ОБРАМЛЁН маркерами:
      ===GATES_RESULT_BEGIN===
      { ...JSON... }
      ===GATES_RESULT_END===
  Бэкенд парсит ровно этот блок.

ПРОГРАММНОЕ ИСПОЛЬЗОВАНИЕ (из бэкенда напрямую, без subprocess):
  from gates.runner import run_chain
  result = run_chain(run_id, gate_ids=None, run_meta=run_meta)
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

# Чтобы работать и из bin'арника, и из инсталляции, и при `python -m gates.runner`.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Windows-консоль по умолчанию cp1251 → UnicodeEncodeError на любых не-ASCII логах.
# Переключаем stdout/stderr в UTF-8 (Python 3.7+ поддерживает reconfigure).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

from gates.base import (  # noqa: E402
    GateContext, GateResult, GATE_REGISTRY, _ensure_gates_loaded, ordered_gate_ids, run_one,
)

RESULT_BEGIN = "===GATES_RESULT_BEGIN==="
RESULT_END = "===GATES_RESULT_END==="


def _download_run_artifacts(run_id: str, dest: Path) -> Optional[str]:
    """Скачать все артефакты рана MLflow в dest. Вернуть путь (или None при ошибке)."""
    try:
        from core import mlflow_utils
        return mlflow_utils.download_artifacts(run_id, "", str(dest))
    except Exception as e:  # noqa: BLE001
        print(f"[runner] WARN download_artifacts failed: {e}", file=sys.stderr)
        return None


def _fetch_run_meta(run_id: str) -> dict:
    """Метаданные рана (owner/params/metrics/tags). {} если MLflow недоступен."""
    try:
        from core import mlflow_utils
        return mlflow_utils.get_run_metadata(run_id) or {}
    except Exception as e:  # noqa: BLE001
        print(f"[runner] WARN get_run_metadata failed: {e}", file=sys.stderr)
        return {}


def _select_gates(only: Optional[list[str]] = None,
                  from_gate: Optional[str] = None) -> list[str]:
    """Выбор и порядок гейтов: вся цепочка / one / from-point."""
    all_ids = ordered_gate_ids()
    if only:
        unknown = [g for g in only if g not in GATE_REGISTRY]
        if unknown:
            raise ValueError(f"unknown gate id(s): {unknown}; known: {all_ids}")
        # Сохраняем канонический порядок цепочки.
        return [g for g in all_ids if g in set(only)]
    if from_gate:
        if from_gate not in GATE_REGISTRY:
            raise ValueError(f"unknown gate id: {from_gate}; known: {all_ids}")
        idx = all_ids.index(from_gate)
        return all_ids[idx:]
    return all_ids


def run_chain(run_id: str, *, gate_ids: Optional[list[str]] = None,
              only: Optional[list[str]] = None,
              from_gate: Optional[str] = None,
              run_meta: Optional[dict] = None,
              work_dir: Optional[Path] = None) -> dict:
    """Прогнать цепочку гейтов программно. Возвращает агрегатный dict (как для UI).

    gate_ids — фиксированный список (порядок сохранён, неизвестные id → ValueError).
    only/from_gate — альтернативные способы выбора (передаются в _select_gates).
    """
    _ensure_gates_loaded()

    if gate_ids is not None:
        unknown = [g for g in gate_ids if g not in GATE_REGISTRY]
        if unknown:
            raise ValueError(f"unknown gate id(s): {unknown}; known: {ordered_gate_ids()}")
        # уважаем canonical order
        order = ordered_gate_ids()
        selected = [g for g in order if g in set(gate_ids)]
    else:
        selected = _select_gates(only=only, from_gate=from_gate)

    meta = run_meta or _fetch_run_meta(run_id)

    cleanup = False
    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix=f"mlsec_gates_{run_id[:8]}_"))
        cleanup = True
        _download_run_artifacts(run_id, work_dir)

    ctx = GateContext(run_id=run_id, work_dir=work_dir, run_meta=meta,
                      repo_root=_REPO_ROOT)

    print(f"[runner] run_id={run_id} owner={meta.get('owner','?')} "
          f"work_dir={work_dir} gates={selected}")

    results: list[GateResult] = []
    for gid in selected:
        print(f"[runner] >>> {gid}")
        res = run_one(gid, ctx)
        for line in res.logs:
            print(line)
        print(f"[runner] <<< {gid} {res.status} ({res.duration_ms}ms)")
        results.append(res)

    passed = all(r.status != "FAIL" for r in results)
    agg = {
        "run_id": run_id,
        "selected": selected,
        "passed": passed,
        "gates": [r.to_dict() for r in results],
        "placeholder": False,
        "debug": {
            "owner": meta.get("owner"),
            "experiment_id": meta.get("experiment_id"),
            "work_dir": str(work_dir),
            "n_params": len(meta.get("params", {}) or {}),
            "n_metrics": len(meta.get("metrics", {}) or {}),
        },
    }

    if cleanup:
        # Чистим work_dir, но не падаем если файлы залочены (Windows).
        shutil.rmtree(work_dir, ignore_errors=True)

    return agg


def main() -> int:
    parser = argparse.ArgumentParser(description="MLSecOps security gates runner")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--run-id", help="MLflow run id (артефакты скачиваются автоматически)")
    src.add_argument("--source-dir",
                     help="Папка с источниками (репо, артефакты) — для CI на git-push")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--only", default="", help="ID гейта или CSV-список (G5 или G5,G7)")
    g.add_argument("--from", dest="from_gate", default="",
                   help="ID гейта, с которого продолжить цепочку до конца")
    parser.add_argument("--work-dir", default="",
                        help="Не качать артефакты — взять из этой папки (для --run-id)")
    args = parser.parse_args()

    _ensure_gates_loaded()
    only_list = [g.strip() for g in args.only.split(",") if g.strip()] if args.only else None
    work_dir = Path(args.work_dir) if args.work_dir else None

    try:
        if args.source_dir:
            # Git/repo-mode: source_dir = work_dir; синтетический run_id = sha репо/коммита.
            synthetic = f"src:{Path(args.source_dir).name}"
            result = run_chain(synthetic, only=only_list, from_gate=args.from_gate or None,
                               work_dir=Path(args.source_dir),
                               run_meta={"owner": "ci", "run_id": synthetic})
        else:
            result = run_chain(args.run_id, only=only_list, from_gate=args.from_gate or None,
                               work_dir=work_dir)
    except ValueError as e:
        print(f"[runner] ERROR: {e}", file=sys.stderr)
        return 2

    print(RESULT_BEGIN)
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    print(RESULT_END)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
