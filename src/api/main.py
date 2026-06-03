"""Gatekeeper — FastAPI бэкенд. Единая точка: deep audit, реестр, RBAC, триггер CI.

Эндпоинты и контракт /verify — docs/11_BACKEND_API.md.
Личность — из auth-прокси (identity.current_user). Привилегии — require_role.
Скелет: маршруты объявлены, логика помечена TODO.
"""
from __future__ import annotations

from typing import Optional

try:
    from fastapi import FastAPI, Request
    from pydantic import BaseModel
except Exception:  # graceful для py_compile без установленных пакетов
    FastAPI = None  # type: ignore

    class BaseModel:  # type: ignore
        pass

app = FastAPI(title="MLSecOps Gatekeeper") if FastAPI else None


class VerifyRequest(BaseModel):
    model_name: str
    run_id: str
    git_sha: str
    requested_by: str
    reason: str


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

    @app.get("/api/v1/admin/users")
    def list_users():
        """Список пользователей с ролями/правами (UI «Пользователи»). TODO: из users/roles."""
        return []  # TODO

    # ---- видимость по объектам (UI читает эти ручки) ----
    @app.get("/api/v1/models/{name}/versions")
    def model_versions(name: str):
        """Версии модели с lineage/гейтами (UI Реестр/Паспорт). TODO: model_versions."""
        return []  # TODO

    @app.get("/api/v1/datasets/{key}")
    def dataset_card(key: str):
        """Карточка датасета + отчёт G1 (UI Паспорт «Открыть датасет»). TODO."""
        return {}  # TODO

    @app.get("/api/v1/resources")
    def resources():
        """Ресурсы для раннера гейтов (datasets/models/code + применимые гейты). TODO."""
        return []  # TODO

    @app.get("/api/v1/events/verify_chain")
    def verify_chain():
        """Проверка целостности Audit Trail (hash-chain). TODO: core.db.verify_chain()."""
        return {"ok": True, "verified": 0, "broken_at": None}  # TODO

    @app.get("/api/v1/cicd/runs")
    def cicd_runs():
        """Прогоны CI/CD (run→jobs→steps→log) для UI «CI/CD логи». RBAC: MLSecOps.
        TODO: проксирование к GitHub Actions API / чтение статусов self-hosted runner."""
        return []  # TODO

    # ---- раннер гейтов: матрица ресурс×гейт ----
    @app.post("/api/v1/scan")
    def scan_batch(request: Request):
        """Прогнать выбранные гейты на нескольких ресурсах (fail_closed опц.).
        Запускает образы гейтов (docker run mlsec-gate-*), пишет findings/events.
        Возврат: {matrix:[{gate:status}], detail:{'res|gate':[status,msg]}, resources:[...]}. TODO."""
        return {"matrix": [], "detail": {}, "resources": []}  # TODO

    # ---- находки: действия (UI Находки) ----
    @app.post("/api/v1/findings/{finding_id}/fp")
    def finding_fp(finding_id: int, request: Request):
        """Отметить находку False Positive. RBAC: MLSecOps. +reason +event. TODO."""
        return {"ok": True}

    @app.post("/api/v1/findings/{finding_id}/rerun")
    def finding_rerun(finding_id: int, request: Request):
        """Перезапустить проверку по находке. RBAC: MLSecOps. TODO."""
        return {"ok": True, "status": "queued"}

    @app.post("/api/v1/findings/{finding_id}/close")
    def finding_close(finding_id: int, request: Request):
        """Закрыть находку. RBAC: MLSecOps. TODO."""
        return {"ok": True}

    # ---- GRC: каталог контролей и принятие остаточного риска ----
    @app.get("/api/v1/controls")
    def controls():
        """Каталог контролей (угроза→контроль→тест→стандарты+статус) для «Карты покрытия».
        Источник: src.common.controls.CONTROLS + статусы accepted из БД. TODO."""
        try:
            from src.common.controls import CONTROLS
            return CONTROLS
        except Exception:  # noqa: BLE001
            return []

    @app.post("/api/v1/controls/{control_id}/accept")
    def control_accept(control_id: str, request: Request):
        """RiskAcceptance: принять остаточный риск контроля (GRC exception).
        RBAC: MLSecOps. Персистит в БД + событие. TODO."""
        return {"ok": True, "control": control_id, "status": "accepted"}
