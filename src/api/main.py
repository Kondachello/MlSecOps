"""Gatekeeper — FastAPI бэкенд. Единая точка: deep audit, реестр, RBAC, триггер CI.

Эндпоинты и контракт /verify — docs/11_BACKEND_API.md.
Личность — из auth-прокси (identity.current_user). Привилегии — require_role.
Скелет: маршруты объявлены, логика помечена TODO.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

try:
    from fastapi import FastAPI, HTTPException, Request, UploadFile
    from pydantic import BaseModel
except Exception:  # graceful для py_compile без установленных пакетов
    FastAPI = None  # type: ignore

    class BaseModel:  # type: ignore
        pass

try:
    import requests as _http
except Exception:
    _http = None  # type: ignore

app = FastAPI(title="MLSecOps Gatekeeper") if FastAPI else None


class VerifyRequest(BaseModel):
    model_name: str
    run_id: str
    git_sha: str
    requested_by: str
    reason: str


class TriggerWorkflowRequest(BaseModel):
    check_type: str
    target: str = "data/train_m1_clean.csv"


GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "")
GITHUB_REF = os.getenv("GITHUB_REF", "sasha")
UPLOAD_DIR = Path(__file__).resolve().parents[2] / "data"


# ---- видимость / выпадашки ----
if app:
    @app.get("/api/v1/models")
    def list_models():
        """Список моделей из MLflow + реестр (для выпадашек). TODO: mlflow_utils.list_models()."""
        return {"models": []}  # TODO

    @app.get("/api/v1/runs")
    def list_runs(model: str):
        """Раны модели из MLflow. TODO: mlflow_utils.list_runs(model)."""
        return {"runs": []}  # TODO

    # ---- датасеты ----
    @app.post("/api/v1/datasets/ingest")
    def ingest_dataset(request: Request):
        """Онбординг датасета (обёртка над src.ingest_dataset). RBAC: DS/DE/MLSecOps. TODO."""
        return {"status": "TODO"}

    # ---- ГЛАВНАЯ ручка: deep audit ----
    @app.post("/api/v1/verify")
    def verify(req: VerifyRequest, request: Request):
        """Deep audit по контракту docs/11_BACKEND_API.md §11.3.

        Ветка external → G3+G4+G5 на замороженном артефакте, статус pending_hitl.
        Ветка своя-модель → G5+G2+G3 на коде → триггер train.yml → G4 на CI-артефакте.
        На каждую FAIL — add_finding; log_event(verify_started/passed/blocked).
        PASS+Tier≠HIGH → approved; PASS+HIGH → pending_hitl; FAIL → quarantine.
        TODO.
        """
        return {"passed": None, "status": "TODO", "gate_results": [],
                "findings_ids": [], "next_action": "TODO"}

    # ---- обучение / деплой / HITL / прод-операции (RBAC) ----
    @app.post("/api/v1/train")
    def train(request: Request):
        """Запустить обучение в CI (train.yml). RBAC: DS/MLSecOps. TODO: dispatch workflow."""
        return {"status": "TODO"}

    @app.post("/api/v1/deploy/{model}/{version}")
    def deploy(model: str, version: str, request: Request):
        """Запустить deploy.yml. RBAC: MLSecOps. HIGH стоит до approve. TODO."""
        return {"status": "TODO"}

    @app.post("/api/v1/deploy/{model}/{version}/approve")
    def approve(model: str, version: str, request: Request):
        """HITL Approve для Tier=HIGH. RBAC: MLSecOps (не своя модель). +reason +event. TODO."""
        return {"status": "TODO"}

    @app.post("/api/v1/prod/{model}/rollback")
    def rollback(model: str, request: Request):
        """Откат на previous (alias). RBAC: MLSecOps. +reason +event. TODO."""
        return {"status": "TODO"}

    @app.post("/api/v1/prod/{model}/{version}/retire")
    def retire(model: str, version: str, request: Request):
        """Вывод из эксплуатации. RBAC: MLSecOps. +reason +event. TODO."""
        return {"status": "TODO"}

    # ---- скан ресурса всеми применимыми образами ----
    @app.post("/api/v1/scan/{asset_type}/{asset_id}")
    def scan(asset_type: str, asset_id: str, request: Request):
        """Кнопка 'просканировать ресурс всеми применимыми образами' → запуск гейтов/workflow. TODO."""
        return {"status": "TODO"}

    # ---- CI/CD интеграция (запуск гейтов в процессе) ----
    @app.post("/api/v1/ci/trigger")
    def trigger_workflow(req: TriggerWorkflowRequest):
        """Запустить гейт безопасности напрямую."""
        allowed = {"data_gate", "code_gate", "dependency_gate"}
        if req.check_type not in allowed:
            raise HTTPException(400, f"check_type must be one of {allowed}")

        repo_root = Path(__file__).resolve().parents[2]
        target_path = repo_root / req.target if not Path(req.target).is_absolute() else Path(req.target)

        if req.check_type == "data_gate":
            if not target_path.exists():
                import subprocess
                subprocess.run(
                    ["python", str(repo_root / "data" / "make_datasets.py")],
                    cwd=str(repo_root), check=True,
                )
            from src.gates.data_gate.data_gate import build_report, gate_check
            results = gate_check(str(target_path))
            report = build_report(req.target, results)

        elif req.check_type == "code_gate":
            from src.gates.code_gate.code_gate import build_report, gate_check
            results = gate_check(str(repo_root), stage="ci")
            report = build_report(req.target, results)

        elif req.check_type == "dependency_gate":
            from src.gates.dependency_gate.dependency_gate import build_report, gate_check
            results = gate_check(str(repo_root))
            report = build_report(req.target, results)

        return {"status": "ok", "report": report}

    @app.post("/api/v1/upload")
    def upload_file(file: UploadFile):
        """Загрузить CSV-файл на сервер."""
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = Path(file.filename).name
        if not safe_name.lower().endswith(".csv"):
            raise HTTPException(400, "Only .csv files are accepted")
        dest = UPLOAD_DIR / safe_name
        content = file.file.read()
        dest.write_bytes(content)
        return {"status": "ok", "filename": safe_name, "size": len(content)}

    @app.get("/api/v1/files")
    def list_files():
        """Список CSV-файлов доступных для проверки."""
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        files = sorted(UPLOAD_DIR.glob("*.csv"))
        return {"files": [f"data/{f.name}" for f in files]}

    # ---- False Positives ----
    @app.post("/api/v1/findings/{finding_id}/false_positive")
    def false_positive(finding_id: int, request: Request):
        """Отметить находку FP. RBAC: MLSecOps. +reason +event. TODO."""
        return {"status": "TODO"}

    # ---- видимость ----
    @app.get("/api/v1/findings")
    def findings():
        return {"findings": []}  # TODO

    @app.get("/api/v1/events")
    def events():
        return {"events": []}  # TODO

    @app.get("/api/v1/registry")
    def registry():
        return {"models": [], "datasets": []}  # TODO

    # ---- админка RBAC ----
    @app.post("/api/v1/admin/users")
    def admin_users(request: Request):
        """Регистрация пользователя. RBAC: MLSecOps. TODO."""
        return {"status": "TODO"}

    @app.post("/api/v1/admin/roles")
    def admin_roles(request: Request):
        """Назначение роли. RBAC: MLSecOps. TODO."""
        return {"status": "TODO"}

    @app.post("/api/v1/admin/access")
    def admin_access(request: Request):
        """Выдача доступа к датасету (+can_export). RBAC: MLSecOps. TODO."""
        return {"status": "TODO"}
