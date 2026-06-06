"""ci/retrain.py — переобучение модели с нуля в CI под сервисным аккаунтом `ci`.

Триггерится бэкендом при нажатии «Выкатка в прод» на артефакте, который ещё не
обучен в CI (security.origin != ci_trained). См. docs/05_CANONICAL_FLOW.md канон №1.

ЧТО ДЕЛАЕТ:
  1) Читает теги исходного рана (source_run_id) — model.name, ci.train_script, git_sha;
  2) Логинится в backend как `ci` → JWT;
  3) Запускает train_script подпроцессом с env DEV_USER=ci → новый ран MLflow создаётся
     под сервисным аккаунтом, прокси штампует mlsecops.owner=ci и security.origin=ci_trained;
  4) Печатает новый run_id в stdout (для бэка).

КОНТРАКТ stdout:
  Перед финальным JSON-блоком — построчные логи (для прогресс-вью).
  Финальный JSON-блок:
      ===CI_RETRAIN_RESULT_BEGIN===
      { "ok": bool, "new_run_id": str, "source_run_id": str, "experiment": str, ... }
      ===CI_RETRAIN_RESULT_END===

ЗАПУСК (CLI):
  python -m ci.retrain --source-run RUN_ID [--train-script PATH] [--ci-user ci]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

RESULT_BEGIN = "===CI_RETRAIN_RESULT_BEGIN==="
RESULT_END = "===CI_RETRAIN_RESULT_END==="

# Дефолтный обучающий скрипт. В реальной системе берётся из тега ci.train_script на ране.
DEFAULT_TRAIN_SCRIPT = "examples/demo_train_clean.py"


def _log(msg: str) -> None:
    print(f"[ci.retrain] {msg}", flush=True)


def _login_ci(backend_url: str, ci_user: str, ci_pass: str, timeout: int = 15) -> str:
    """Логин в backend под сервисным аккаунтом → JWT."""
    import requests
    r = requests.post(f"{backend_url}/api/v1/auth/login",
                      json={"username": ci_user, "password": ci_pass}, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"CI login failed: {r.status_code} {r.text}")
    return r.json()["access_token"]


def _fetch_source_run(source_run_id: str) -> dict:
    """Метаданные исходного рана (для извлечения train_script, params)."""
    from core import mlflow_utils
    meta = mlflow_utils.get_run_metadata(source_run_id)
    if not meta:
        raise RuntimeError(f"source run {source_run_id} not found in MLflow")
    return meta


def _resolve_train_script(meta: dict) -> str:
    """Какой скрипт переобучить. Сначала тег ci.train_script, иначе дефолт."""
    tags = meta.get("tags") or {}
    return tags.get("ci.train_script") or DEFAULT_TRAIN_SCRIPT


def _find_latest_run(experiment_name: str, owner: str, before: float = 0.0) -> Optional[dict]:
    """Найти самый свежий ран в эксперименте experiment_name под owner, started > before."""
    from core import mlflow_utils
    try:
        from mlflow.tracking import MlflowClient
        c = MlflowClient(tracking_uri=mlflow_utils.MLFLOW_UPSTREAM_URL)
        exp = c.get_experiment_by_name(experiment_name)
        if exp is None:
            return None
        runs = c.search_runs(experiment_ids=[exp.experiment_id],
                             order_by=["start_time DESC"], max_results=10)
        for r in runs:
            if r.info.start_time / 1000 >= before:
                tags = r.data.tags or {}
                if tags.get("mlsecops.owner") == owner or tags.get("mlflow.user") == owner:
                    return mlflow_utils._run_to_dict(r, {exp.experiment_id: exp.name})
    except Exception as e:  # noqa: BLE001
        _log(f"WARN _find_latest_run: {e}")
    return None


def retrain(source_run_id: str, *, train_script: Optional[str] = None,
            ci_user: str = "ci", ci_pass: Optional[str] = None,
            backend_url: Optional[str] = None, timeout: int = 600) -> dict:
    """Программный API: переобучить модель с нуля под аккаунтом CI."""
    backend_url = backend_url or os.getenv("GATEKEEPER_URL", "http://backend:8200")
    ci_pass = ci_pass or os.getenv("CI_USER_PASSWORD", "ci-pass")

    _log(f"source_run={source_run_id}  backend={backend_url}  ci_user={ci_user}")

    meta = _fetch_source_run(source_run_id)
    train_script = train_script or _resolve_train_script(meta)
    train_script_path = _REPO_ROOT / train_script
    if not train_script_path.exists():
        raise RuntimeError(f"train_script not found: {train_script_path}")

    _log(f"train_script={train_script}  model.name={(meta.get('tags') or {}).get('model.name')}")

    # 1) Логинимся как CI — проверяем что юзер заведён и пароль свежий.
    token = _login_ci(backend_url, ci_user, ci_pass)
    _log(f"CI login OK (token len={len(token)})")

    # 2) Спавним train-скрипт под CI-юзером. Скрипты читают DEV_USER/DEV_PASSWORD env.
    env = {**os.environ,
           "DEV_USER": ci_user,
           "DEV_PASSWORD": ci_pass,
           "GATEKEEPER_URL": backend_url,
           # Сигнал скрипту: «это CI-перетрейн» — для своих тегов (опц.)
           "CI_RETRAIN_OF": source_run_id,
           "PYTHONPATH": str(_REPO_ROOT)}
    started_at = time.time()
    _log(f"$ python {train_script}")
    proc = subprocess.run(
        [sys.executable, str(train_script_path)],
        cwd=str(_REPO_ROOT), env=env,
        capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace",
    )
    _log(f"train rc={proc.returncode}  (took {time.time()-started_at:.1f}s)")
    if proc.stdout:
        for ln in (proc.stdout.splitlines()[-20:]):
            _log(f"  | {ln}")
    if proc.returncode != 0:
        if proc.stderr:
            for ln in (proc.stderr.splitlines()[-20:]):
                _log(f"  ! {ln}")
        raise RuntimeError(f"train script failed (rc={proc.returncode})")

    # 3) Находим новый ран в MLflow (создан под ci-юзером, после started_at).
    expected_exp = f"{ci_user}_demo_clean"  # совпадает с demo_train_clean.py EXPERIMENT
    new_run = None
    for _ in range(10):
        new_run = _find_latest_run(expected_exp, owner=ci_user, before=started_at)
        if new_run:
            break
        time.sleep(1)
    if not new_run:
        raise RuntimeError(f"new run not found in experiment {expected_exp!r} "
                           f"(возможно train_script использует другое имя эксперимента)")
    _log(f"new_run_id={new_run['run_id']}  experiment={new_run.get('experiment')}")

    return {
        "ok": True,
        "source_run_id": source_run_id,
        "new_run_id": new_run["run_id"],
        "experiment": new_run.get("experiment"),
        "train_script": train_script,
        "duration_sec": time.time() - started_at,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="MLSecOps CI retrainer (promote precondition)")
    parser.add_argument("--source-run", required=True, help="MLflow run id артефакта-кандидата")
    parser.add_argument("--train-script", default=None,
                        help="Путь к обучающему скрипту (по умолчанию из тега ci.train_script)")
    parser.add_argument("--ci-user", default=os.getenv("CI_USERNAME", "ci"))
    parser.add_argument("--ci-pass", default=os.getenv("CI_USER_PASSWORD", "ci-pass"))
    parser.add_argument("--backend", default=os.getenv("GATEKEEPER_URL", "http://backend:8200"))
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()

    try:
        result = retrain(args.source_run, train_script=args.train_script,
                         ci_user=args.ci_user, ci_pass=args.ci_pass,
                         backend_url=args.backend, timeout=args.timeout)
    except Exception as e:  # noqa: BLE001
        _log(f"FAIL: {type(e).__name__}: {e}")
        print(RESULT_BEGIN)
        print(json.dumps({"ok": False, "source_run_id": args.source_run,
                          "error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))
        print(RESULT_END)
        return 1

    print(RESULT_BEGIN)
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    print(RESULT_END)
    return 0


if __name__ == "__main__":
    sys.exit(main())
