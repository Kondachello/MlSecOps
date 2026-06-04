"""GitHub Actions API helpers for CI/CD logs in UI."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional

try:
    import requests
except Exception:
    requests = None  # type: ignore


def _duration(created: str, updated: str) -> str:
    try:
        c = datetime.fromisoformat(created.replace("Z", "+00:00"))
        u = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        sec = max(0, int((u - c).total_seconds()))
    except Exception:
        return "—"
    m, s = divmod(sec, 60)
    return f"{m}m{s:02d}s" if m else f"{s}s"


def _gh_status(conclusion: Optional[str]) -> str:
    if not conclusion:
        return "running"
    m = {
        "success": "success",
        "failure": "failed",
        "cancelled": "cancelled",
        "skipped": "skipped",
        "neutral": "success",
    }
    return m.get(conclusion, conclusion)


def _api_get(path: str, token: str, repo: str, params: Optional[dict] = None) -> Any:
    if not requests:
        return None
    resp = requests.get(
        f"https://api.github.com/repos/{repo}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        params=params or {},
        timeout=20,
    )
    if resp.status_code != 200:
        return None
    return resp.json()


def _map_steps(steps: list[dict]) -> list[dict]:
    out: list[dict] = []
    for s in steps:
        st = _gh_status(s.get("conclusion"))
        item: dict = {
            "name": s.get("name", "step"),
            "status": st,
            "log": f"conclusion={s.get('conclusion', 'unknown')}",
        }
        if st == "failed":
            item["exit"] = 1
            item["log"] = (
                f"Step failed in GitHub Actions (run log: job step #{s.get('number', '?')}).\n"
                f"##[error]Process completed with exit code 1."
            )
        out.append(item)
    return out


def _map_jobs(jobs_payload: Optional[dict]) -> list[dict]:
    if not jobs_payload:
        return []
    jobs: list[dict] = []
    for j in jobs_payload.get("jobs", []):
        jobs.append({
            "name": j.get("name", "job"),
            "status": _gh_status(j.get("conclusion")),
            "duration": _duration(j.get("started_at", ""), j.get("completed_at", ""))
            if j.get("started_at") and j.get("completed_at")
            else "",
            "steps": _map_steps(j.get("steps") or []),
        })
    return jobs


def list_cicd_runs(token: str, repo: str, *, limit: int = 20) -> list[dict]:
    """Recent workflow runs in UI shape (docs/14_FRONTEND_UI.md MOCK_CICD_RUNS)."""
    if not (token and repo and requests):
        return []
    data = _api_get("/actions/runs", token, repo, {"per_page": limit})
    if not data:
        return []
    runs: list[dict] = []
    for r in data.get("workflow_runs", []):
        run_id = r.get("id")
        wf_path = (r.get("path") or "").split("/")[-1] or r.get("name", "workflow")
        jobs_payload = _api_get(f"/actions/runs/{run_id}/jobs", token, repo) if run_id else None
        trigger = r.get("display_title") or r.get("event", "unknown")
        actor = (r.get("actor") or {}).get("login", "github")
        runs.append({
            "id": f"run-{r.get('run_number', run_id)}",
            "workflow": wf_path,
            "trigger": trigger,
            "actor": actor,
            "commit": (r.get("head_sha") or "")[:7],
            "branch": r.get("head_branch") or "",
            "status": _gh_status(r.get("conclusion")),
            "ts": r.get("updated_at", ""),
            "duration": _duration(r.get("run_started_at", r.get("created_at", "")),
                                  r.get("updated_at", "")),
            "jobs": _map_jobs(jobs_payload),
            "github_run_id": str(run_id) if run_id else "",
        })
    return runs
