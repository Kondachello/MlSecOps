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

from core import db, identity

app = FastAPI(title="MLSecOps Gatekeeper") if FastAPI else None

if app:
    db.init_db()  # SQLite-дев: создать схему (в Postgres — no-op, схема из init.sql)
    # Auth-прокси перед MLflow (валидирует JWT, штампует X-Authenticated-User).
    from src.api.mlflow_proxy import router as mlflow_router
    app.include_router(mlflow_router)


# ---- модели запросов --------------------------------------------------------
class VerifyRequest(BaseModel):
    model_name: str
    run_id: str
    git_sha: str
    requested_by: str
    reason: str


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


GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "")
GITHUB_REF = os.getenv("GITHUB_REF", "sasha")
UPLOAD_DIR = Path(__file__).resolve().parents[2] / "data"
MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", "http://authproxy:4180/mlflow")


# ---- RBAC-хелперы (мапинг AuthError → HTTP + событие) -----------------------
def _require(request, role: str) -> str:
    """Требовать роль. 401 если нет личности, 403 (+event access_denied) если нет роли."""
    try:
        username = identity.current_user(request)
    except identity.AuthError as e:
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
        """Зарегистрированные модели из MLflow Registry (для выпадашек)."""
        from core import mlflow_utils
        return {"models": mlflow_utils.list_models()}

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
    def events(limit: int = 100):
        """История событий (Audit Trail, новые сверху)."""
        return {"events": db.list_events(limit)}

    @app.get("/api/v1/registry")
    def registry():
        return {"models": [], "datasets": []}  # TODO

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
