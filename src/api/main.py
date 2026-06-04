"""Gatekeeper — FastAPI бэкенд. Единая точка: deep audit, реестр, RBAC, триггер CI.

Эндпоинты и контракт /verify — docs/11_BACKEND_API.md.
Личность — из JWT (core.identity.current_user). Привилегии — require_role.

Auth-модель (локальный JWT-issuer, docs/06): саморегистрация без роли → MLSecOps
выдаёт роль → один и тот же JWT действителен и для нашего API, и (через прокси) для MLflow.
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

from core import db, github_actions, identity

app = FastAPI(title="MLSecOps Gatekeeper") if FastAPI else None

if app:
    db.init_db()  # SQLite-дев: создать схему (в Postgres — no-op, схема из init.sql)
    # Auth-прокси перед MLflow (валидирует JWT, штампует X-Authenticated-User).
    from src.api.mlflow_proxy import router as mlflow_router
    app.include_router(mlflow_router)


# ---- модели запросов --------------------------------------------------------
class VerifyRequest(BaseModel):
    model_name: str = ""
    run_id: str = ""
    git_sha: str = ""
    requested_by: str = "ui"
    reason: str = ""
    # поля из Streamlit UI (ui/app.py)
    version: str = ""
    dataset: str = ""  # формат name@version или путь data/...
    flow: str = "A"
    dataset_path: str = "data/train_m1_clean.csv"
    dataset_name: str = ""
    dataset_version: str = ""
    dataset_sha256: str = ""
    dataset_already_verified: bool = False
    model_card_path: str = "demo/model_card_complete.json"
    model_artifact_path: str = ""
    source: str = "internal"


class TrainDispatchRequest(BaseModel):
    model_name: str
    dataset_name: str
    dataset_version: str
    git_commit: str


class TriggerWorkflowRequest(BaseModel):
    check_type: str
    target: str = "data/train_m1_clean.csv"


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    roles: list[str] = []


class AssignRoleRequest(BaseModel):
    username: str
    role: str


class GrantAccessRequest(BaseModel):
    username: str
    dataset_name: str
    dataset_version: str
    can_export: bool = False


class CiIngestRequest(BaseModel):
    workflow: str = "verify"
    github_run_id: str = ""
    summary: dict


class CiRegisterModelRequest(BaseModel):
    model_name: str
    version: str
    sha256: str
    tier: str = "MED"
    source: str = "ci_trained"
    status: str = "approved"
    owner: str = "ci"
    dataset_name: str = ""
    dataset_version: str = ""
    git_sha: str = ""
    run_id: str = ""
    card: dict = {}


class ApproveRequest(BaseModel):
    reason: str = "HITL approve"


class FindingActionRequest(BaseModel):
    reason: str = ""


class ScanMatrixRequest(BaseModel):
    gates: list[str] = []
    resources: list[str] = []
    fail_closed: bool = True


class IngestDatasetRequest(BaseModel):
    name: str
    version: str
    path: str
    owner: str = ""


GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "")
GITHUB_REF = os.getenv("GITHUB_REF", "kate_merge")
CI_INGEST_TOKEN = os.getenv("CI_INGEST_TOKEN", "")
APP_DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"
UPLOAD_DIR = Path(__file__).resolve().parents[2] / "data"
_PUBLIC = os.getenv("GATEKEEPER_PUBLIC_URL", "http://localhost:8000").rstrip("/")
MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", f"{_PUBLIC}/mlflow")


def _github_dispatch(event_type: str, client_payload: dict) -> dict:
    """Запустить workflow через repository_dispatch (см. docs/Rina_do_befor_work.md)."""
    if not (GITHUB_TOKEN and GITHUB_REPO and _http):
        return {
            "status": "skipped",
            "mode": "no_github",
            "detail": "Задайте GITHUB_TOKEN и GITHUB_REPO для dispatch",
        }
    payload = {**client_payload, "ref": GITHUB_REF}
    resp = _http.post(
        f"https://api.github.com/repos/{GITHUB_REPO}/dispatches",
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
        },
        json={"event_type": event_type, "client_payload": payload},
        timeout=15,
    )
    if resp.status_code == 204:
        return {
            "status": "ok",
            "mode": "github_actions",
            "event_type": event_type,
            "repo": GITHUB_REPO,
            "ref": GITHUB_REF,
        }
    raise HTTPException(resp.status_code, resp.text)


# ---- RBAC-хелперы (мапинг AuthError → HTTP + событие) -----------------------
def _require(request, role: str) -> str:
    """Требовать роль. 401 если нет личности, 403 (+event access_denied) если нет роли."""
    try:
        username = identity.current_user(request)
    except identity.AuthError as e:
        if APP_DEBUG:
            demo = (request.headers.get("X-Demo-Role") or "").strip()
            if demo == role:
                return f"demo-{demo.lower()}"
        raise HTTPException(401, str(e))
    roles = identity.get_roles(username)
    if role not in roles:
        db.log_event(username, sorted(roles)[0] if roles else "none", "access_denied",
                     result="blocked", reason=f"need role {role}",
                     details={"required_role": role})
        raise HTTPException(403, f"user '{username}' lacks role '{role}'")
    return username


if app:
    # ======================= AUTH (регистрация / логин) =======================
    @app.post("/api/v1/auth/register")
    def auth_register(req: RegisterRequest):
        """Саморегистрация: создаёт юзера БЕЗ роли. Роль потом выдаёт MLSecOps."""
        if db.get_user(req.username):
            raise HTTPException(409, "username already taken")
        uid = db.register_user(req.username, req.email,
                               password_hash=identity.hash_password(req.password))
        db.log_event(req.username, "none", "user_registered", asset=req.username,
                     result="ok", reason="self-registration (no role yet)")
        return {"status": "ok", "user_id": uid, "username": req.username,
                "roles": [], "note": "ожидайте назначения роли от MLSecOps"}

    @app.post("/api/v1/auth/login")
    def auth_login(req: LoginRequest):
        """Логин по паролю → JWT (действителен для API и MLflow через прокси)."""
        try:
            info = identity.authenticate(req.username, req.password)
        except identity.AuthError:
            raise HTTPException(401, "invalid username or password")
        token = identity.create_token(info["username"], info["roles"])
        db.log_event(req.username, sorted(info["roles"])[0] if info["roles"] else "none",
                     "login", result="ok")
        return {"access_token": token, "token_type": "bearer", "roles": info["roles"]}

    @app.get("/api/v1/auth/me")
    def auth_me(request: Request):
        """Кто я: личность из токена + актуальные роли из БД."""
        try:
            username = identity.current_user(request)
        except identity.AuthError as e:
            raise HTTPException(401, str(e))
        return {"username": username, "roles": sorted(identity.get_roles(username))}

    @app.post("/api/v1/auth/token")
    def auth_token(request: Request):
        """Выдать свежий токен для MLflow SDK + подсказку по настройке (нужен Bearer)."""
        try:
            username = identity.current_user(request)
        except identity.AuthError as e:
            raise HTTPException(401, str(e))
        roles = sorted(identity.get_roles(username))
        token = identity.create_token(username, roles)
        return {
            "access_token": token,
            "mlflow_tracking_uri": MLFLOW_TRACKING_URI,
            "usage": (
                "import os, mlflow\n"
                f'os.environ["MLFLOW_TRACKING_URI"] = "{MLFLOW_TRACKING_URI}"\n'
                f'os.environ["MLFLOW_TRACKING_TOKEN"] = "{token}"\n'
                'mlflow.set_experiment("my_experiment")'
            ),
        }

    # ---- видимость / выпадашки ----
    @app.get("/api/v1/models")
    def list_models():
        """Модели для UI: сначала реестр PG, иначе MLflow, иначе []."""
        ui_models = db.list_models_ui()
        if ui_models:
            return {"models": ui_models}
        from core import mlflow_utils
        ml = mlflow_utils.list_models()
        if ml and isinstance(ml[0], dict) and "tier" in ml[0]:
            return {"models": ml}
        return {"models": ml}

    @app.get("/api/v1/models/{name}/versions")
    def model_versions(name: str):
        """Версии модели (реестр) для UI «Паспорт»."""
        versions = db.list_model_versions_ui(name)
        return {"versions": versions}

    @app.get("/api/v1/mlflow/runs")
    def mlflow_runs(request: Request, limit: int = 50):
        """Последние MLflow-раны по всем экспериментам (нужна аутентификация)."""
        try:
            identity.current_user(request)
        except identity.AuthError as e:
            raise HTTPException(401, str(e))
        from core import mlflow_utils
        return {"runs": mlflow_utils.list_recent_runs(limit)}

    @app.get("/api/v1/runs")
    def list_runs(model: str):
        """Раны модели из MLflow. TODO: mlflow_utils.list_runs(model)."""
        return {"runs": []}  # TODO

    # ---- датасеты ----
    @app.post("/api/v1/datasets/ingest")
    def ingest_dataset(req: IngestDatasetRequest, request: Request):
        """Онбординг датасета: G1 + запись в реестр."""
        try:
            actor = identity.current_user(request)
            roles = identity.get_roles(actor)
            if not ({"DS", "DE", "MLSecOps"} & roles):
                raise HTTPException(403, "need DS, DE or MLSecOps")
        except identity.AuthError as e:
            raise HTTPException(401, str(e))
        owner = req.owner or actor
        path = Path(req.path)
        if not path.is_absolute():
            path = UPLOAD_DIR.parent / req.path
        if not path.exists():
            raise HTTPException(404, f"dataset file not found: {req.path}")
        from src.gates.data_gate.data_gate import build_report, gate_check
        import hashlib

        results = gate_check(str(path))
        report = build_report(req.path, results)
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if not report.get("passed"):
            db.register_dataset(
                req.name, req.version, sha, "local", "quarantine",
                bucket="quarantine", owner=owner,
            )
            ids = db.ingest_gate_report(report, "dataset")
            db.log_event(actor, "DS", "dataset_ingest_blocked", asset=f"{req.name}@{req.version}",
                         result="blocked", reason="G1 FAIL", details={"finding_ids": ids})
            raise HTTPException(400, {"status": "blocked", "report": report, "finding_ids": ids})
        db.register_dataset(req.name, req.version, sha, "local", "available",
                            bucket="datasets", owner=owner)
        db.mark_dataset_verified(req.name, req.version, sha)
        db.log_event(actor, "DS", "dataset_ingest_ok", asset=f"{req.name}@{req.version}",
                     result="ok", reason="G1 PASS")
        return {"status": "available", "sha256": sha, "report": report}

    # ---- ГЛАВНАЯ ручка: deep audit ----
    @app.post("/api/v1/verify")
    def verify(req: VerifyRequest, request: Request):
        """Deep audit: триггер verify.yml (G1→G2+G3+G5 или B: G3+G4+G5)."""
        try:
            actor = identity.current_user(request)
            role = sorted(identity.get_roles(actor))[0] if identity.get_roles(actor) else "DS"
        except identity.AuthError:
            actor, role = req.requested_by, "DS"
        flow = "B" if req.source.lower() == "external" or req.flow.upper() == "B" else "A"
        ds_path = req.dataset_path
        ds_name, ds_ver = req.dataset_name, req.dataset_version
        if req.dataset:
            if req.dataset.startswith("data/"):
                ds_path = req.dataset
            elif "@" in req.dataset:
                ds_name, ds_ver = req.dataset.split("@", 1)
                candidate = UPLOAD_DIR.parent / "data" / f"{ds_name}.csv"
                if candidate.exists():
                    ds_path = str(candidate.as_posix())
            else:
                candidate = UPLOAD_DIR.parent / "data" / f"{req.dataset}.csv"
                if candidate.exists():
                    ds_path = str(candidate.as_posix())
        run_id = req.run_id or req.version or "local"
        model_name = req.model_name or "model"
        db.log_event(
            actor, role, "verify_started",
            asset=f"{model_name}/{run_id}", result="pending",
            reason=req.reason,
            details={"flow": flow, "git_sha": req.git_sha},
        )
        dispatch = _github_dispatch(
            "verify",
            {
                "flow": flow,
                "model_name": model_name,
                "run_id": run_id,
                "git_sha": req.git_sha,
                "dataset_path": ds_path,
                "dataset_name": ds_name,
                "dataset_version": ds_ver,
                "dataset_sha256": req.dataset_sha256,
                "dataset_already_verified": req.dataset_already_verified,
                "model_card_path": req.model_card_path,
                "model_artifact_path": req.model_artifact_path,
            },
        )
        return {
            "passed": None,
            "status": "running",
            "flow": flow,
            "dispatch": dispatch,
            "gate_results": [],
            "findings_ids": [],
            "next_action": "poll GitHub Actions verify.yml; затем train (A) или HITL (B)",
        }

    # ---- обучение / деплой / HITL / прод-операции (RBAC) ----
    @app.post("/api/v1/train")
    def train(req: TrainDispatchRequest, request: Request):
        """Запустить train.yml (после успешного verify, поток A)."""
        try:
            actor = identity.current_user(request)
            role = sorted(identity.get_roles(actor))[0] if identity.get_roles(actor) else "DS"
        except identity.AuthError:
            actor, role = "ci", "DS"
        db.log_event(actor, role, "train_started", asset=req.model_name, result="pending")
        return _github_dispatch(
            "train",
            {
                "model_name": req.model_name,
                "dataset_name": req.dataset_name,
                "dataset_version": req.dataset_version,
                "git_commit": req.git_commit,
            },
        )

    @app.post("/api/v1/deploy/{model}/{version}")
    def deploy(model: str, version: str, request: Request):
        """Запустить deploy.yml (SAST+SCA+trivy+G4+cosign)."""
        try:
            actor = _require(request, "MLSecOps")
        except HTTPException:
            actor = "ci"
        m = db.get_model(model, version)
        if not m:
            raise HTTPException(404, "model not in registry")
        if m["status"] not in ("approved", "prod", "verified"):
            raise HTTPException(400, f"deploy blocked: status={m['status']} (need approved)")
        payload = {
            "model_name": model,
            "version": version,
            "expected_sha": m.get("sha256") or "",
        }
        db.log_event(actor, "MLSecOps", "deploy_started", asset=f"{model}/{version}", result="pending",
                     details={"expected_sha": payload["expected_sha"]})
        return _github_dispatch("deploy", payload)

    @app.post("/api/v1/deploy/{model}/{version}/approve")
    def approve(model: str, version: str, req: ApproveRequest, request: Request):
        """HITL Approve: Tier=HIGH / external — два разных MLSecOps; иначе один."""
        admin = _require(request, "MLSecOps")
        m = db.get_model(model, version)
        if not m:
            raise HTTPException(404, "model not in registry")
        if m["status"] not in ("pending_hitl", "approved", "verified"):
            raise HTTPException(400, f"cannot approve status={m['status']}")
        count = db.record_hitl_approval(model, version, admin, req.reason)
        new_status = db.try_finalize_hitl(model, version)
        db.log_event(
            admin, "MLSecOps", "hitl_approve",
            asset=f"{model}/{version}", result="ok",
            reason=req.reason,
            details={"approvals": count, "required": db._hitl_required(m["tier"], m["source"]),
                     "status": new_status},
        )
        return {
            "status": new_status,
            "approvals_count": count,
            "approvals_required": db._hitl_required(m["tier"], m["source"]),
        }

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
        """Скан одного ресурса — dispatch verify/scan или локальный мок."""
        try:
            identity.current_user(request)
        except identity.AuthError:
            pass
        return {"status": "TODO", "asset_type": asset_type, "asset_id": asset_id}

    def _scan_matrix_mock(resource_id: str, gate: str) -> tuple[str, str]:
        """Детерминированный прогон (совпадает с ui/app.py _run_gate_mock)."""
        if "poisoned" in resource_id and gate == "G1":
            return "FAIL", "дисбаланс классов + PII"
        if resource_id.startswith("PR#42") and gate == "G2":
            return "FAIL", "gitleaks: секрет leaky.py:13"
        if resource_id.startswith("PR#42") and gate == "G3":
            return "FAIL", "typosquatting: pytirch, tenserflew"
        return "PASS", "проверки пройдены"

    @app.post("/api/v1/scan")
    def scan_matrix(req: ScanMatrixRequest, request: Request):
        """Раннер гейтов: матрица ресурс×гейт (UI «Верификация»)."""
        try:
            actor = identity.current_user(request)
            role = sorted(identity.get_roles(actor))[0] if identity.get_roles(actor) else "DS"
        except identity.AuthError:
            actor, role = "ui", "MLSecOps"
        gates = req.gates or ["G1", "G2", "G3", "G4", "G5"]
        resources = req.resources or []
        matrix = []
        detail: dict[str, tuple[str, str]] = {}
        for rid in resources:
            row: dict = {}
            for g in gates:
                status, msg = _scan_matrix_mock(rid, g)
                row[g] = status
                detail[f"{rid}|{g}"] = (status, msg)
            matrix.append(row)
        db.log_event(actor, role, "gate_matrix_run", asset=",".join(resources[:3]),
                     result="ok", reason="scan matrix",
                     details={"gates": gates, "resources": len(resources)})
        return {"matrix": matrix, "detail": detail, "resources": resources}

    # ---- CI/CD интеграция (GitHub Actions + локальный fallback) ----
    @app.post("/api/v1/ci/trigger")
    def trigger_workflow(req: TriggerWorkflowRequest):
        """Запустить гейт: GitHub Actions если токен задан, иначе локально."""
        allowed = {"data_gate", "code_gate", "dependency_gate"}
        if req.check_type not in allowed:
            raise HTTPException(400, f"check_type must be one of {allowed}")

        # --- GitHub Actions путь ---
        if GITHUB_TOKEN and GITHUB_REPO and _http:
            resp = _http.post(
                f"https://api.github.com/repos/{GITHUB_REPO}/dispatches",
                headers={
                    "Authorization": f"Bearer {GITHUB_TOKEN}",
                    "Accept": "application/vnd.github.v3+json",
                },
                json={
                    "event_type": "run-security-scan",
                    "client_payload": {
                        "check_type": req.check_type,
                        "target": req.target,
                        "ref": GITHUB_REF,
                    },
                },
                timeout=10,
            )
            if resp.status_code == 204:
                return {
                    "status": "ok",
                    "mode": "github_actions",
                    "detail": "Workflow запущен в GitHub Actions",
                    "repo": GITHUB_REPO,
                }
            raise HTTPException(resp.status_code, resp.text)

        # --- Локальный fallback (нет токена) ---
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

        return {"status": "ok", "mode": "local", "report": report}

    def _check_ci_ingest(request: Request) -> None:
        if not CI_INGEST_TOKEN:
            return
        got = request.headers.get("X-CI-Ingest-Token", "")
        if got != CI_INGEST_TOKEN:
            raise HTTPException(401, "invalid CI ingest token")

    @app.post("/api/v1/ci/register-model")
    def ci_register_model(req: CiRegisterModelRequest, request: Request):
        """Регистрация CI-артефакта после train (Postgres/SQLite)."""
        _check_ci_ingest(request)
        mid = db.register_model(
            req.model_name, req.version,
            tier=req.tier.upper(), status=req.status, source=req.source,
            owner=req.owner, card=req.card, sha256=req.sha256,
        )
        db.add_model_version(
            req.model_name, req.version,
            dataset_name=req.dataset_name or None,
            dataset_version=req.dataset_version or None,
            dataset_sha256=None,
            git_sha=req.git_sha or None,
            run_id=req.run_id or None,
            trained_in_ci=True,
            sha256=req.sha256,
            status=req.status,
        )
        db.log_event("github-actions", "MLSecOps", "model_registered",
                     asset=f"{req.model_name}/{req.version}", result="ok",
                     details={"model_id": mid, "sha256": req.sha256})
        return {"status": "ok", "model_id": mid, "sha256": req.sha256}

    @app.post("/api/v1/ci/ingest-reports")
    def ci_ingest_reports(req: CiIngestRequest, request: Request):
        """Принять verify/ci summary из workflow → findings + event (для UI)."""
        _check_ci_ingest(request)
        summary = req.summary or {}
        finding_ids: list[int] = []
        for report in summary.get("gates", []):
            gate = report.get("gate", "?")
            finding_ids.extend(
                db.ingest_gate_report(report, db.asset_type_for_gate(gate))
            )
        passed = summary.get("passed", False)
        run_ref = req.github_run_id or summary.get("github_run_id", "")
        db.log_event(
            "github-actions",
            "MLSecOps",
            f"{req.workflow}_completed",
            asset=f"{req.workflow}/{run_ref}" if run_ref else req.workflow,
            result="passed" if passed else "failed",
            reason="CI gate summary ingest",
            details={
                "workflow": req.workflow,
                "passed": passed,
                "failed_gates": summary.get("failed_gates", []),
                "finding_ids": finding_ids,
            },
        )
        return {
            "status": "ok",
            "passed": passed,
            "finding_ids": finding_ids,
            "ingested_gates": len(summary.get("gates", [])),
        }

    @app.get("/api/v1/cicd/runs")
    def cicd_runs(request: Request, limit: int = 20):
        """Прогоны CI/CD для вкладки «CI/CD логи» (GitHub API + пустой список без токена)."""
        try:
            _require(request, "MLSecOps")
        except HTTPException:
            pass
        runs = github_actions.list_cicd_runs(GITHUB_TOKEN, GITHUB_REPO, limit=limit)
        return {"runs": runs}

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

    def _finding_fp(finding_id: int, req: FindingActionRequest, request: Request):
        admin = _require(request, "MLSecOps")
        if not req.reason.strip():
            raise HTTPException(400, "reason required for false positive")
        db.mark_false_positive(finding_id, admin, req.reason)
        db.log_event(admin, "MLSecOps", "finding_false_positive", asset=str(finding_id),
                     result="ok", reason=req.reason)
        return {"status": "false_positive", "id": finding_id}

    def _finding_close(finding_id: int, req: FindingActionRequest, request: Request):
        admin = _require(request, "MLSecOps")
        db.set_finding_status(finding_id, "fixed")
        db.log_event(admin, "MLSecOps", "finding_closed", asset=str(finding_id),
                     result="ok", reason=req.reason or "closed")
        return {"status": "fixed", "id": finding_id}

    def _finding_rerun(finding_id: int, request: Request):
        admin = _require(request, "MLSecOps")
        db.log_event(admin, "MLSecOps", "finding_rerun_requested", asset=str(finding_id),
                     result="pending", reason="rerun queued")
        return {"status": "queued", "id": finding_id}

    @app.post("/api/v1/findings/{finding_id}/false_positive")
    def false_positive(finding_id: int, req: FindingActionRequest, request: Request):
        return _finding_fp(finding_id, req, request)

    @app.post("/api/v1/findings/{finding_id}/fp")
    def false_positive_alias(finding_id: int, req: FindingActionRequest, request: Request):
        return _finding_fp(finding_id, req, request)

    @app.post("/api/v1/findings/{finding_id}/close")
    def close_finding(finding_id: int, req: FindingActionRequest, request: Request):
        return _finding_close(finding_id, req, request)

    @app.post("/api/v1/findings/{finding_id}/rerun")
    def rerun_finding(finding_id: int, request: Request):
        return _finding_rerun(finding_id, request)

    # ---- видимость ----
    @app.get("/api/v1/findings")
    def findings(status: Optional[str] = None, limit: int = 200):
        return {"findings": db.list_findings(status=status, limit=limit)}

    @app.get("/api/v1/events")
    def events(limit: int = 100):
        """История событий (Audit Trail, новые сверху)."""
        return {"events": db.list_events(limit)}

    @app.get("/api/v1/events/verify_chain")
    def events_verify_chain():
        """Проверка hash-chain Audit Trail (демо #24)."""
        chk = db.verify_chain()
        return {
            "ok": chk.get("ok", False),
            "verified": chk.get("count", 0),
            "broken_at": chk.get("broken_at"),
        }

    @app.get("/api/v1/registry")
    def registry():
        return db.list_registry()

    @app.get("/api/v1/controls")
    def list_controls():
        try:
            from src.common import controls as ctrl
            return {"controls": ctrl.CONTROLS}
        except Exception:
            return {"controls": []}

    @app.get("/api/v1/resources")
    def list_resources():
        """Ресурсы для раннера гейтов (матрица в UI)."""
        return {
            "resources": [
                {"id": "train_m1_clean@v1", "type": "dataset",
                 "gates": ["G1", "G2", "G3", "G4", "G5"]},
                {"id": "train_m1_poisoned@v1", "type": "dataset",
                 "gates": ["G1", "G2", "G3", "G4", "G5"]},
                {"id": "PR#42 (code)", "type": "code", "gates": ["G2", "G3", "G5"]},
                {"id": "PR#41 (code)", "type": "code", "gates": ["G2", "G3", "G5"]},
                {"id": "credit_scoring@1.0.0", "type": "model",
                 "gates": ["G4", "G5", "G6", "G7"]},
            ]
        }

    @app.get("/api/v1/datasets/{dataset_key}")
    def get_dataset_card(dataset_key: str):
        """Карточка датасета name@version."""
        if "@" in dataset_key:
            name, version = dataset_key.split("@", 1)
        else:
            name, version = dataset_key, "v1"
        reg = db.list_registry()
        for ds in reg.get("datasets", []):
            if ds["name"] == name and ds["version"] == version:
                return {
                    "name": name, "version": version, "rows": 0,
                    "columns": [], "source_type": "registry",
                    "uploaded_by": ds.get("owner", ""), "sha256": ds.get("sha256", ""),
                    "status": ds.get("status", "unknown"),
                    "g1": {"passed": ds.get("status") == "available"},
                    "ts": "",
                }
        raise HTTPException(404, "dataset not found")

    # ======================= админка RBAC (MLSecOps) =======================
    @app.post("/api/v1/admin/users")
    def admin_users(req: CreateUserRequest, request: Request):
        """Создать пользователя (+опц. роли). RBAC: MLSecOps."""
        admin = _require(request, "MLSecOps")
        if db.get_user(req.username):
            raise HTTPException(409, "username already taken")
        uid = db.register_user(req.username, req.email,
                               password_hash=identity.hash_password(req.password))
        db.log_event(admin, "MLSecOps", "user_created", asset=req.username, result="ok",
                     reason="создан админом")
        for role in req.roles:
            if role not in identity.ROLES:
                raise HTTPException(400, f"unknown role {role}")
            db.assign_role(uid, role)
            db.log_event(admin, "MLSecOps", "role_assigned", asset=req.username, result="ok",
                         reason=f"выдана роль {role}", details={"role": role})
        return {"status": "ok", "user_id": uid, "username": req.username,
                "roles": sorted(identity.get_roles(req.username))}

    @app.post("/api/v1/admin/roles")
    def admin_roles(req: AssignRoleRequest, request: Request):
        """Назначить роль пользователю. RBAC: MLSecOps."""
        admin = _require(request, "MLSecOps")
        if req.role not in identity.ROLES:
            raise HTTPException(400, f"unknown role {req.role}")
        user = db.get_user(req.username)
        if not user:
            raise HTTPException(404, "user not found")
        db.assign_role(user["id"], req.role)
        db.log_event(admin, "MLSecOps", "role_assigned", asset=req.username, result="ok",
                     reason=f"выдана роль {req.role}", details={"role": req.role})
        return {"status": "ok", "username": req.username,
                "roles": sorted(identity.get_roles(req.username))}

    @app.post("/api/v1/admin/access")
    def admin_access(req: GrantAccessRequest, request: Request):
        """Выдать доступ к датасету (+can_export). RBAC: MLSecOps."""
        admin = _require(request, "MLSecOps")
        user = db.get_user(req.username)
        if not user:
            raise HTTPException(404, "user not found")
        db.grant_access(user["id"], req.dataset_name, req.dataset_version,
                        can_export=req.can_export, granted_by=admin)
        db.log_event(admin, "MLSecOps", "access_granted",
                     asset=f"{req.dataset_name}@{req.dataset_version}", result="ok",
                     reason=f"доступ для {req.username}",
                     details={"user": req.username, "can_export": req.can_export})
        return {"status": "ok", "user": req.username,
                "dataset": f"{req.dataset_name}@{req.dataset_version}",
                "can_export": req.can_export}

    @app.get("/api/v1/admin/users")
    def admin_list_users(request: Request):
        """Список пользователей с ролями. RBAC: MLSecOps."""
        _require(request, "MLSecOps")
        return {"users": db.list_users()}


# ======================= демо/самопроверка (TestClient) =======================
if __name__ == "__main__":
    import tempfile

    db.SQLITE_PATH = str(Path(tempfile.gettempdir()) / "mlsec_api_demo.db")
    if Path(db.SQLITE_PATH).exists():
        Path(db.SQLITE_PATH).unlink()
    db.init_db()

    # Сид первого MLSecOps-админа (как infra/seed_admin.py)
    admin_uid = db.register_user("msecops", "msecops@example.com",
                                 password_hash=identity.hash_password("admin-pass"))
    db.assign_role(admin_uid, "MLSecOps")

    from fastapi.testclient import TestClient
    c = TestClient(app)

    def show(title, r):
        print(f"{title}\n   -> {r.status_code} {r.json()}")

    print("=== Поток регистрации и выдачи роли ===\n")

    # 1) Саморегистрация DS (без роли)
    show("1) POST /auth/register (ivanov)",
         c.post("/api/v1/auth/register",
                json={"username": "ivanov", "password": "hunter2", "email": "i@ex.com"}))

    # 2) Логин ivanov → токен
    r = c.post("/api/v1/auth/login", json={"username": "ivanov", "password": "hunter2"})
    show("2) POST /auth/login (ivanov)", r)
    ivanov_tok = r.json()["access_token"]
    ivanov_h = {"Authorization": f"Bearer {ivanov_tok}"}

    # 3) /me — ролей пока нет
    show("3) GET /auth/me (ivanov, без роли)", c.get("/api/v1/auth/me", headers=ivanov_h))

    # 4) ivanov пытается в админку → 403
    show("4) POST /admin/roles от ivanov (ожидаем 403)",
         c.post("/api/v1/admin/roles", headers=ivanov_h,
                json={"username": "ivanov", "role": "DS"}))

    # 5) Логин админа → токен
    r = c.post("/api/v1/auth/login", json={"username": "msecops", "password": "admin-pass"})
    admin_h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    show("5) POST /auth/login (msecops)", r)

    # 6) Админ выдаёт ivanov роль DS
    show("6) POST /admin/roles (msecops выдаёт DS ivanov)",
         c.post("/api/v1/admin/roles", headers=admin_h,
                json={"username": "ivanov", "role": "DS"}))

    # 7) /me ivanov — теперь DS
    show("7) GET /auth/me (ivanov, после выдачи)", c.get("/api/v1/auth/me", headers=ivanov_h))

    # 8) ivanov получает токен для MLflow SDK
    r = c.post("/api/v1/auth/token", headers=ivanov_h)
    print("\n8) POST /auth/token (ivanov) -> сниппет для ноутбука:")
    print("   " + r.json()["usage"].replace("\n", "\n   "))

    # 9) Аудит: что записалось в hash-chain
    ev = c.get("/api/v1/events").json()["events"]
    print(f"\n9) GET /events — записей: {len(ev)} (новые сверху)")
    for e in ev:
        print(f"   #{e['id']} {e['actor']}/{e['role']}: {e['action']} [{e['result']}] {e.get('reason') or ''}")
    print(f"   verify_chain() = {db.verify_chain()}")
