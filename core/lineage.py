"""core/lineage.py — verify_lineage: «прошли ли проверку данные и код этого артефакта».

Точка контроля промоушена в прод (см. docs/05_CANONICAL_FLOW.md, канон №1):
прод-артефакт ДОЛЖЕН быть обучен в CI на проверенных данных и проверенном коде.
Эта функция отвечает «можно ли в принципе пускать ретрейн → промоушен», читая
журнал pipeline_runs.

Контракт:
    verify_lineage(run_meta) -> {
        "data_ok": bool,
        "code_ok": bool,
        "ok": bool,                  # AND
        "data_evidence": {...},      # pipeline_run id, dataset_digest, time
        "code_evidence": {...},      # pipeline_run id, git_sha, ref
        "data_missing_reason": str|None,
        "code_missing_reason": str|None,
        "origin": str,               # security.origin тег рана
    }
"""
from __future__ import annotations

from typing import Optional

from core import db


def _extract_dataset_digest(run_meta: dict) -> Optional[str]:
    """Достаём digest входного датасета (mlflow.log_input лежит в base['dataset_inputs'])."""
    inputs = run_meta.get("dataset_inputs") or []
    for di in inputs:
        d = di.get("digest")
        if d:
            return str(d)
    # fallback на тег
    return (run_meta.get("tags") or {}).get("security.dataset_sha256") or \
           run_meta.get("dataset_sha256")


def _extract_git_sha(run_meta: dict) -> Optional[str]:
    """Достаём git commit, на котором обучили (mlflow ставит тег mlflow.source.git.commit)."""
    if run_meta.get("git_sha"):
        return str(run_meta["git_sha"])
    tags = run_meta.get("tags") or {}
    return tags.get("mlflow.source.git.commit") or tags.get("security.git_sha")


def verify_lineage(run_meta: dict) -> dict:
    """Проверить что данные и код этого артефакта прошли security check (через pipeline_runs).

    «Данные прошли»: есть pipeline_run с source=dataset_digest и passed DATA-гейтом.
    «Код прошёл»:    есть pipeline_run с source=git_sha и passed G0-гейтом.

    Если в ране нет lineage-тегов (digest/git_sha) — конкретная сторона помечается
    как невозможная-к-верификации, с пояснением.
    """
    tags = run_meta.get("tags") or {}
    origin = tags.get("security.origin", "")

    data_digest = _extract_dataset_digest(run_meta)
    git_sha = _extract_git_sha(run_meta)

    data_pr = data_evidence = data_missing = None
    if not data_digest:
        data_missing = ("Нет dataset digest в ране (используй mlflow.log_input(dataset, ...) "
                        "при обучении — иначе невозможно проверить что эти данные прошли DATA-гейт)")
    else:
        data_pr = db.find_passing_pipeline_run(data_digest, gate_id="DATA")
        if data_pr is None:
            data_missing = (f"Датасет с digest={data_digest[:16]}... не имеет passed DATA-гейта. "
                            f"Прогоните DATA-гейт на источнике данных перед промоушеном.")
        else:
            data_evidence = {"pipeline_run_id": data_pr["id"], "digest": data_digest,
                             "ts": data_pr.get("finished_at") or data_pr.get("ts")}

    code_pr = code_evidence = code_missing = None
    if not git_sha:
        code_missing = ("Нет git_sha в ране (запусти обучение из git-checkout-а или поставь "
                        "тег security.git_sha — иначе невозможно проверить что код прошёл G0).")
    else:
        code_pr = db.find_passing_pipeline_run(git_sha, gate_id="G0")
        if code_pr is None:
            code_missing = (f"Код по git_sha={git_sha[:12]}... не имеет passed G0-гейта. "
                            f"Дождись прохождения CI (workflow gates.yml) перед промоушеном.")
        else:
            code_evidence = {"pipeline_run_id": code_pr["id"], "git_sha": git_sha,
                             "ref": code_pr.get("ref"),
                             "ts": code_pr.get("finished_at") or code_pr.get("ts")}

    data_ok = data_pr is not None
    code_ok = code_pr is not None
    return {
        "ok": data_ok and code_ok,
        "data_ok": data_ok,
        "code_ok": code_ok,
        "origin": origin,
        "data_evidence": data_evidence,
        "code_evidence": code_evidence,
        "data_missing_reason": data_missing,
        "code_missing_reason": code_missing,
        "dataset_digest": data_digest,
        "git_sha": git_sha,
    }
