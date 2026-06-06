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


class ShareRequest(BaseModel):
    # roles=None → шаринг по клиренсу роли владельца (read-down, дефолт);
    # roles=[...] → кастомный список ролей (переопределяет клиренс).
    roles: Optional[list[str]] = None
    reason: Optional[str] = None


class ReasonRequest(BaseModel):
    """Тело для изменяющих действий жизненного цикла (reason пишется в Audit Trail)."""
    reason: Optional[str] = None


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


def _current_user(request) -> str:
    """current_user → 401 при отсутствии личности (для не-RBAC ручек)."""
    try:
        return identity.current_user(request)
    except identity.AuthError as e:
        raise HTTPException(401, str(e))


def _primary_role(username: str) -> str:
    roles = sorted(identity.get_roles(username))
    return roles[0] if roles else "none"


def _ensure_artifact(run_id: str):
    """Вернуть (acl, run_meta) для рана; лениво регистрирует владение по данным MLflow.

    Владелец берётся из неподделываемого серверного тега (mlsecops.owner), который
    штампует прокси на runs/create. (acl, meta) = (None, None) если рана нет в MLflow.
    """
    from core import mlflow_utils
    acl = db.get_artifact_acl(run_id)
    meta = mlflow_utils.get_run(run_id)
    if acl is None:
        if not meta:
            return None, None
        db.upsert_artifact(run_id, meta.get("experiment_id", ""), meta.get("owner", ""),
                           session_name=meta.get("run_name"))
        acl = db.get_artifact_acl(run_id)
    return acl, meta


def _artifact_zone(acl: dict) -> str:
    """Зона артефакта в реестре по check_status + stage (для группировки в UI).

    draft (свалка/черновик) · failed (не прошли) · ok (прошли) · deploying (выкатка/HITL)
    · prod · previous · retired.
    """
    stage = acl.get("stage") or "none"
    cs = acl.get("check_status") or "none"
    if stage == "prod":
        return "prod"
    if stage in ("pending_approve", "approved"):
        return "deploying"
    if stage == "previous":
        return "previous"
    if stage == "retired":
        return "retired"
    if cs == "passed":
        return "ok"
    if cs == "failed":
        return "failed"
    return "draft"


def _registry_visible(acl: dict, user: str, roles) -> bool:
    """Видимость артефакта в реестре.

    - MLSecOps как security-ревьюер видит ВЕСЬ реестр (включая «свалку» — чужие непроверенные
      черновики): иначе он не может триажить и допускать артефакты к проду;
    - владелец видит свой артефакт всегда (включая приватные черновики до проверки);
    - остальные — только расшаренное им (clearance/роли).
    """
    if "MLSecOps" in set(roles):
        return True
    if acl.get("owner") == user:
        return True
    return identity.can_view_artifact(acl, user, roles)


def _enrich_artifact(run: dict, acl: Optional[dict]) -> dict:
    """Собрать карточку артефакта для реестра/списков из MLflow-рана + ACL."""
    if acl is None:
        acl = {"owner": run.get("owner") or "", "check_status": "none", "stage": "none",
               "share_status": "private", "share_level": None, "share_roles": None,
               "tier": None, "approved_by": None, "deployed_by": None}
    return {
        "run_id": run["run_id"],
        "experiment_id": run.get("experiment_id"),
        "experiment": run.get("experiment"),
        "run_name": run.get("run_name"),
        "owner": acl.get("owner") or run.get("owner") or "",
        "status": run.get("status"),
        "start_time": run.get("start_time"),
        "metrics": run.get("metrics", {}),
        "params": run.get("params", {}),
        "check_status": acl.get("check_status"),
        "tier": acl.get("tier"),
        "stage": acl.get("stage") or "none",
        "approved_by": acl.get("approved_by"),
        "deployed_by": acl.get("deployed_by"),
        "share_status": acl.get("share_status"),
        "share_level": acl.get("share_level"),
        "share_roles": acl.get("share_roles"),
        "tags": run.get("tags", {}),          # security.*/research.* теги рана (для фильтра в реестре)
        "zone": _artifact_zone(acl),
    }


def _sync_incidents(run_id: str, gates: list) -> list[int]:
    """Пересоздать открытые инциденты артефакта из упавших гейтов (после security check).

    Сначала чистим старые открытые сработки этого артефакта (чтобы не плодить дубли при
    повторной проверке), затем на каждый FAIL-гейт заводим инцидент (db.add_finding).
    Возвращает id созданных инцидентов.
    """
    db.clear_findings_for_asset(run_id)
    ids = []
    for g in gates:
        if g.get("status") == "FAIL":
            fid = db.add_finding(
                gate=g.get("id", "?"), asset_type="model", asset=run_id,
                rule=g.get("name") or g.get("detail") or "gate_failed",
                severity=g.get("severity", "medium"),
                evidence={"detail": g.get("detail"), "threats": g.get("threats", []),
                          "logs": g.get("logs", [])})
            ids.append(fid)
    return ids


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

    @app.get("/api/v1/mlflow/health")
    def mlflow_health(request: Request):
        """Доступность MLflow для UI: {ok, upstream, error, experiments, runs}.

        Реестр/«Мои артефакты» вызывают это при пустом списке, чтобы показать ПРИЧИНУ
        (MLflow недоступен/адрес/ошибка), а не молчаливое «пусто».
        """
        _current_user(request)
        from core import mlflow_utils
        return mlflow_utils.mlflow_status()

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
    def list_runs(model: str, request: Request):
        """Раны конкретной модели/эксперимента из MLflow (нужна аутентификация)."""
        _current_user(request)
        from core import mlflow_utils
        return {"runs": mlflow_utils.list_runs(model)}

    # ---- артефакты MLflow: приватность по умолчанию + контролируемый шаринг ----
    # Разработчик работает в IDE через MLflow (свой эксперимент = «аккаунт»). Сервис
    # подтягивает его раны (= сессии разработки: data+код+модель) и даёт по кнопке
    # запустить security check, после чего — расшарить (по клиренсу роли или кастомным ролям).
    @app.get("/api/v1/artifacts")
    def list_artifacts(request: Request):
        """Артефакты (сессии) пользователя: свои + расшаренные ему. Видимость по clearance/ролям."""
        user = _current_user(request)
        roles = sorted(identity.get_roles(user))
        from core import mlflow_utils
        runs = mlflow_utils.list_recent_runs(200)
        acls = db.list_artifact_acls([r["run_id"] for r in runs])
        # Ленивая регистрация владения для ещё не отслеживаемых ранов — ОДНОЙ транзакцией.
        new_rows = [(r["run_id"], r.get("experiment_id", ""), r.get("owner") or "",
                     r.get("run_name"))
                    for r in runs if r["run_id"] not in acls]
        db.upsert_artifacts_bulk(new_rows)
        mine, shared = [], []
        for r in runs:
            rid = r["run_id"]
            acl = acls.get(rid)
            if acl is None:
                owner = r.get("owner") or ""
                acl = {"owner": owner, "share_status": "private", "check_status": "none",
                       "share_level": None, "share_roles": None}
            enriched = {**r, "owner": acl["owner"], "check_status": acl.get("check_status"),
                        "share_status": acl.get("share_status"),
                        "share_level": acl.get("share_level"),
                        "share_roles": acl.get("share_roles")}
            if acl["owner"] == user:
                mine.append(enriched)
            elif identity.can_view_artifact(acl, user, roles):
                shared.append(enriched)
        return {"mine": mine, "shared_with_me": shared,
                "my_clearance": identity.clearance(roles)}

    @app.post("/api/v1/artifacts/manual")
    def artifact_manual_upload(request: Request, name: str = "", description: str = "",
                               file: Optional[UploadFile] = None):
        """Подгрузить артефакт ВРУЧНУЮ и по отдельности (без связи с экспериментом-исследованием).

        Доступно DS/DE/MLSecOps. Создаёт ран в личном «ручном» эксперименте владельца, штампует
        владельца серверно, регистрирует владение в ACL. Артефакт появляется в «Моих артефактах»
        и реестре как обычная сессия (можно прогнать security check, расшарить, выкатить).
        """
        user = _current_user(request)
        roles = identity.get_roles(user)
        if not ({"DS", "DE", "MLSecOps"} & set(roles)):
            db.log_event(user, _primary_role(user), "access_denied", result="blocked",
                         reason="manual upload requires DS/DE/MLSecOps")
            raise HTTPException(403, "ручная загрузка артефактов доступна ролям DS/DE/MLSecOps")
        run_name = (name or (file.filename if file else None) or "manual_artifact").strip()
        from core import mlflow_utils
        saved = None
        if file is not None:
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            saved = str(UPLOAD_DIR / Path(file.filename or run_name).name)
            Path(saved).write_bytes(file.file.read())
        try:
            res = mlflow_utils.create_manual_run(user, run_name, file_path=saved,
                                                 description=description)
        except RuntimeError as e:
            raise HTTPException(502, f"MLflow недоступен — ручная загрузка не выполнена: {e}")
        db.set_experiment_owner(res["experiment_id"], user)
        db.upsert_artifact(res["run_id"], res["experiment_id"], user, session_name=run_name)
        db.log_event(user, _primary_role(user), "artifact_manual_upload", asset=res["run_id"],
                     result="ok", reason=description or "ручная загрузка артефакта",
                     details={"experiment": res["experiment"], "file": bool(saved)})
        return {"status": "ok", **res, "run_name": run_name}

    @app.post("/api/v1/artifacts/{run_id}/check")
    def artifact_check(run_id: str, request: Request,
                       from_gate: Optional[str] = None):
        """Запустить security check артефакта. Только владелец. Пишет статус+событие.

        Query `?from_gate=G5` — рестарт цепочки с указанного гейта до конца. Цепочка
        мёржится с предыдущим check_detail (гейты до точки рестарта сохраняются).
        Без `from_gate` — полная цепочка (как раньше).
        """
        user = _current_user(request)
        acl, meta = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        if acl["owner"] != user:
            db.log_event(user, _primary_role(user), "access_denied", asset=run_id,
                         result="blocked", reason="not artifact owner")
            raise HTTPException(403, "только владелец артефакта может запускать проверку")
        from core import security_check
        db.set_check_status(run_id, "pending")
        result = security_check.run_artifact_check(run_id, meta, from_gate=from_gate)
        # Если рестарт с точки — смёрджить с предыдущей цепочкой.
        if from_gate:
            prev = acl.get("check_detail") or {}
            prev_gates = {g["id"]: g for g in (prev.get("gates") or [])}
            for g in result.get("gates", []):
                prev_gates[g["id"]] = g
            merged = list(prev_gates.values())
            merged.sort(key=lambda g: g.get("id"))
            result["gates"] = merged
            result["passed"] = all(g.get("status") != "FAIL" for g in merged)
        status = "passed" if result["passed"] else "failed"
        db.set_check_status(run_id, status, result)
        db.set_artifact_tier(run_id, result.get("tier"))
        if not result["passed"]:
            db.set_artifact_stage(run_id, "none")
        incident_ids = _sync_incidents(run_id, result.get("gates", []))
        db.log_event(user, _primary_role(user), "artifact_security_check", asset=run_id,
                     result="ok" if result["passed"] else "blocked",
                     reason=(f"security check rerun from {from_gate}" if from_gate
                             else "security check (gate chain)"),
                     details={"check_status": status, "passed": result["passed"],
                              "tier": result.get("tier"), "incidents": incident_ids,
                              "from_gate": from_gate})
        return {"run_id": run_id, "check_status": status, "tier": result.get("tier"),
                "incidents": incident_ids, "result": result}

    @app.post("/api/v1/artifacts/{run_id}/share")
    def artifact_share(run_id: str, req: ShareRequest, request: Request):
        """Расшарить артефакт. Только владелец и только после успешного security check.

        roles=None → по клиренсу роли владельца (read-down); roles=[...] → кастомный список.
        """
        user = _current_user(request)
        roles = sorted(identity.get_roles(user))
        acl, _ = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        if acl["owner"] != user:
            db.log_event(user, _primary_role(user), "access_denied", asset=run_id,
                         result="blocked", reason="not artifact owner")
            raise HTTPException(403, "только владелец артефакта может его расшаривать")
        if acl.get("check_status") != "passed":
            raise HTTPException(409, "сначала пройдите security check (кнопка «Проверить»)")
        custom, level = None, None
        if req.roles:
            for r in req.roles:
                if r not in identity.ROLES:
                    raise HTTPException(400, f"unknown role {r}")
            custom = sorted(set(req.roles))
        else:
            level = identity.clearance(roles)
        db.share_artifact(run_id, level=level, roles=custom, shared_by=user)
        db.log_event(user, _primary_role(user), "artifact_shared", asset=run_id, result="ok",
                     reason=req.reason or "shared via cabinet",
                     details={"level": level, "roles": custom})
        return {"run_id": run_id, "share_status": "shared",
                "share_level": level, "share_roles": custom}

    @app.post("/api/v1/artifacts/{run_id}/unshare")
    def artifact_unshare(run_id: str, request: Request):
        """Снять шаринг — артефакт снова приватный. Только владелец."""
        user = _current_user(request)
        acl, _ = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        if acl["owner"] != user:
            raise HTTPException(403, "только владелец артефакта может снять шаринг")
        db.unshare_artifact(run_id)
        db.log_event(user, _primary_role(user), "artifact_unshared", asset=run_id, result="ok",
                     reason="unshared via cabinet")
        return {"run_id": run_id, "share_status": "private"}

    # ---- страница артефакта: детали + цепочка гейтов + жизненный цикл ----
    @app.get("/api/v1/artifacts/{run_id}")
    def artifact_detail(run_id: str, request: Request):
        """Карточка артефакта (паспорт): ACL, метаданные, цепочка гейтов, инциденты, зона."""
        user = _current_user(request)
        roles = sorted(identity.get_roles(user))
        acl, meta = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        if not _registry_visible(acl, user, roles):
            raise HTTPException(403, "нет доступа к этому артефакту")
        card = _enrich_artifact(meta or {"run_id": run_id}, acl)
        card["session_name"] = acl.get("session_name")
        card["check_detail"] = acl.get("check_detail")  # цепочка гейтов с логами (если проверяли)
        card["incidents"] = db.list_findings(asset=run_id)
        card["can_act"] = "MLSecOps" in roles            # деплой/approve — MLSecOps
        card["is_owner"] = acl.get("owner") == user
        return card

    @app.post("/api/v1/artifacts/{run_id}/gates/{gate_id}/rerun")
    def artifact_gate_rerun(run_id: str, gate_id: str, request: Request):
        """Перезапустить ОДИН гейт цепочки (владелец или MLSecOps). Обновляет check_detail."""
        user = _current_user(request)
        roles = sorted(identity.get_roles(user))
        acl, meta = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        if acl.get("owner") != user and "MLSecOps" not in roles:
            raise HTTPException(403, "перезапуск гейта доступен владельцу или MLSecOps")
        from core import security_check
        single = security_check.run_artifact_check(run_id, meta, only=[gate_id])
        new_gates = single.get("gates", [])
        if not new_gates:
            raise HTTPException(404, f"неизвестный гейт {gate_id}")
        # Слить результат в сохранённую цепочку (или начать новую, если проверки ещё не было).
        detail = acl.get("check_detail") or {"run_id": run_id, "gates": [], "placeholder": True}
        gates = detail.get("gates", [])
        by_id = {g["id"]: g for g in gates}
        for g in new_gates:
            by_id[g["id"]] = g
        merged = list(by_id.values())
        detail["gates"] = merged
        detail["passed"] = all(g.get("status") != "FAIL" for g in merged)
        detail["tier"] = acl.get("tier") or single.get("tier")
        status = "passed" if detail["passed"] else "failed"
        db.set_check_status(run_id, status, detail)
        if not detail["passed"]:
            db.set_artifact_stage(run_id, "none")
        incident_ids = _sync_incidents(run_id, merged)
        db.log_event(user, _primary_role(user), "gate_rerun", asset=run_id,
                     result="ok" if detail["passed"] else "blocked",
                     reason=f"перезапуск {gate_id}",
                     details={"gate": gate_id, "check_status": status})
        return {"run_id": run_id, "gate": new_gates[0], "check_status": status,
                "passed": detail["passed"], "incidents": incident_ids}

    @app.post("/api/v1/artifacts/{run_id}/deploy")
    def artifact_deploy(run_id: str, req: ReasonRequest, request: Request):
        """Инициировать выкатку артефакта (RBAC: MLSecOps). Реальный CI — плейсхолдер.

        Требует passed security check. Tier=HIGH → стадия pending_approve (нужен HITL Approve);
        иначе сразу approved (готов к промоушену в прод). Движение стадий персистится.
        """
        admin = _require(request, "MLSecOps")
        acl, _ = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        if acl.get("check_status") != "passed":
            raise HTTPException(409, "артефакт не прошёл security check")
        tier = acl.get("tier") or "MED"
        new_stage = "pending_approve" if tier == "HIGH" else "approved"
        db.set_artifact_stage(run_id, new_stage, deployed_by=admin)
        db.log_event(admin, "MLSecOps", "deploy_requested", asset=run_id,
                     result="pending" if new_stage == "pending_approve" else "ok",
                     reason=req.reason or "выкатка инициирована (placeholder)",
                     details={"tier": tier, "stage": new_stage})
        return {"run_id": run_id, "stage": new_stage, "tier": tier,
                "note": "Реального CI-деплоя нет (плейсхолдер) — движение стадий персистится."}

    @app.post("/api/v1/artifacts/{run_id}/approve")
    def artifact_approve(run_id: str, req: ReasonRequest, request: Request):
        """HITL Approve для Tier=HIGH (RBAC: MLSecOps, НЕ владелец артефакта — разделение полномочий)."""
        admin = _require(request, "MLSecOps")
        acl, _ = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        if acl.get("stage") != "pending_approve":
            raise HTTPException(409, "артефакт не ожидает подтверждения (stage != pending_approve)")
        if acl.get("owner") == admin:
            db.log_event(admin, "MLSecOps", "access_denied", asset=run_id, result="blocked",
                         reason="HITL: нельзя подтверждать собственный артефакт")
            raise HTTPException(403, "нельзя подтверждать собственный артефакт (разделение полномочий)")
        db.set_artifact_stage(run_id, "approved", approved_by=admin)
        db.log_event(admin, "MLSecOps", "deploy_approved", asset=run_id, result="ok",
                     reason=req.reason or "HITL approve (Tier=HIGH)")
        return {"run_id": run_id, "stage": "approved", "approved_by": admin}

    @app.post("/api/v1/artifacts/{run_id}/promote")
    def artifact_promote(run_id: str, req: ReasonRequest, request: Request):
        """Перевести одобренный артефакт в ПРОД (RBAC: MLSecOps). Прежний прод эксп-та → previous."""
        admin = _require(request, "MLSecOps")
        acl, _ = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        if acl.get("stage") != "approved":
            raise HTTPException(409, "артефакт не одобрен (stage != approved)")
        demoted = db.demote_prod_artifacts(acl.get("experiment_id", ""), run_id)
        db.set_artifact_stage(run_id, "prod", deployed_by=admin)
        for d in demoted:
            db.log_event(admin, "MLSecOps", "prod_superseded", asset=d, result="ok",
                         reason=f"вытеснен новым прод-артефактом {run_id}")
        db.log_event(admin, "MLSecOps", "promoted_to_prod", asset=run_id, result="ok",
                     reason=req.reason or "промоушен в прод (placeholder)",
                     details={"superseded": demoted})
        return {"run_id": run_id, "stage": "prod", "superseded": demoted}

    @app.post("/api/v1/artifacts/{run_id}/restore")
    def artifact_restore(run_id: str, req: ReasonRequest, request: Request):
        """Вернуть в ПРОД ранее откаченный/предыдущий артефакт (RBAC: MLSecOps).

        Используется на странице ПРОД для «замены» текущей прод-модели на другую (blue-green,
        фиктивный CI). Требует passed security check. Прежняя прод-модель эксперимента → previous.
        """
        admin = _require(request, "MLSecOps")
        acl, _ = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        if acl.get("check_status") != "passed":
            raise HTTPException(409, "артефакт не прошёл security check")
        if (acl.get("stage") or "none") not in ("previous", "approved", "retired"):
            raise HTTPException(409, "восстановить можно предыдущий/одобренный/выведенный артефакт")
        demoted = db.demote_prod_artifacts(acl.get("experiment_id", ""), run_id)
        db.set_artifact_stage(run_id, "prod", deployed_by=admin)
        for d in demoted:
            db.log_event(admin, "MLSecOps", "prod_superseded", asset=d, result="ok",
                         reason=f"вытеснен восстановленным прод-артефактом {run_id}")
        db.log_event(admin, "MLSecOps", "prod_restored", asset=run_id, result="ok",
                     reason=req.reason or "восстановление в прод (placeholder CI)",
                     details={"superseded": demoted})
        return {"run_id": run_id, "stage": "prod", "superseded": demoted}

    @app.post("/api/v1/artifacts/{run_id}/rollback")
    def artifact_rollback(run_id: str, req: ReasonRequest, request: Request):
        """Откатить прод-артефакт (RBAC: MLSecOps). stage prod → previous. +reason +event."""
        admin = _require(request, "MLSecOps")
        acl, _ = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        if acl.get("stage") != "prod":
            raise HTTPException(409, "артефакт не в проде (stage != prod)")
        db.set_artifact_stage(run_id, "previous", deployed_by=admin)
        db.log_event(admin, "MLSecOps", "prod_rollback", asset=run_id, result="ok",
                     reason=req.reason or "откат из прода (placeholder)")
        return {"run_id": run_id, "stage": "previous"}

    @app.post("/api/v1/artifacts/{run_id}/retire")
    def artifact_retire(run_id: str, req: ReasonRequest, request: Request):
        """Вывести артефакт из эксплуатации (RBAC: MLSecOps). stage → retired. +reason +event."""
        admin = _require(request, "MLSecOps")
        acl, _ = _ensure_artifact(run_id)
        if acl is None:
            raise HTTPException(404, "run not found in MLflow")
        db.set_artifact_stage(run_id, "retired", deployed_by=admin)
        db.log_event(admin, "MLSecOps", "artifact_retired", asset=run_id, result="ok",
                     reason=req.reason or "выведен из эксплуатации")
        return {"run_id": run_id, "stage": "retired"}

    # ---- датасеты ----
    @app.post("/api/v1/datasets/ingest")
    def ingest_dataset(request: Request):
        """Онбординг датасета (обёртка над src.ingest_dataset). RBAC: DS/DE/MLSecOps.

        Честная заглушка: реальное скачивание/верификация датасета (src/ingest_dataset) —
        следующий эшелон. Сама запись в реестр (db.register_dataset) уже реализована.
        """
        _current_user(request)
        return {"status": "not_implemented",
                "detail": "Онбординг датасетов (скачивание+верификация источника) ещё не подключён."}

    # ---- deep audit (ветка верификации внешних моделей) ----
    @app.post("/api/v1/verify")
    def verify(req: VerifyRequest, request: Request):
        """Deep audit внешней модели (docs/11_BACKEND_API.md §11.3).

        Честная заглушка: оркестрация CI (train.yml/deploy.yml) и верификация внешних весов —
        следующий эшелон. Для артефактов MLflow используется цепочка гейтов на странице
        артефакта (POST /artifacts/{run_id}/check), которая уже работает.
        """
        _current_user(request)
        return {"passed": None, "status": "not_implemented", "gate_results": [],
                "findings_ids": [],
                "next_action": "use /api/v1/artifacts/{run_id}/check (цепочка гейтов)"}

    # ---- обучение в CI ----
    @app.post("/api/v1/train")
    def train(request: Request):
        """Запустить обучение в CI (train.yml). RBAC: DS/MLSecOps.

        Честная заглушка: dispatch train.yml — следующий эшелон (нужен реальный CI-пайплайн).
        """
        try:
            identity.current_user(request)
        except identity.AuthError as e:
            raise HTTPException(401, str(e))
        return {"status": "not_implemented",
                "detail": "Запуск обучения в CI (train.yml) ещё не подключён."}

    # ---- деплой/HITL/прод по РЕЕСТРУ БД (модель@версия) ----
    # Артефакто-центричный поток — в /api/v1/artifacts/{run_id}/{deploy,approve,promote,...}.
    # Эти ручки работают над таблицей реестра models (когда модели регистрируются в БД).
    @app.post("/api/v1/deploy/{model}/{version}")
    def deploy(model: str, version: str, req: ReasonRequest, request: Request):
        """Перевести версию модели в pending_hitl (HIGH) / approved. RBAC: MLSecOps. Реальный CI — плейсхолдер."""
        admin = _require(request, "MLSecOps")
        rows = [m for m in db.list_models() if m["name"] == model and m["version"] == version]
        if not rows:
            raise HTTPException(404, f"модель {model}@{version} не найдена в реестре БД")
        tier = rows[0].get("tier", "MED")
        new_status = "pending_hitl" if tier == "HIGH" else "approved"
        db.set_status("model", model, version, new_status)
        db.log_event(admin, "MLSecOps", "deploy_requested", asset=f"{model}@{version}",
                     result="pending" if new_status == "pending_hitl" else "ok",
                     reason=req.reason or "выкатка (placeholder)", details={"tier": tier})
        return {"status": "ok", "model": model, "version": version, "model_status": new_status}

    @app.post("/api/v1/deploy/{model}/{version}/approve")
    def approve(model: str, version: str, req: ReasonRequest, request: Request):
        """HITL Approve для Tier=HIGH. RBAC: MLSecOps. +reason +event."""
        admin = _require(request, "MLSecOps")
        rows = [m for m in db.list_models() if m["name"] == model and m["version"] == version]
        if not rows:
            raise HTTPException(404, f"модель {model}@{version} не найдена в реестре БД")
        if rows[0]["status"] != "pending_hitl":
            raise HTTPException(409, "версия не ожидает подтверждения (status != pending_hitl)")
        db.set_status("model", model, version, "approved")
        db.log_event(admin, "MLSecOps", "deploy_approved", asset=f"{model}@{version}",
                     result="ok", reason=req.reason or "HITL approve")
        return {"status": "ok", "model": model, "version": version, "model_status": "approved"}

    @app.post("/api/v1/prod/{model}/rollback")
    def rollback(model: str, req: ReasonRequest, request: Request):
        """Откат прод-версии модели на previous. RBAC: MLSecOps. +reason +event."""
        admin = _require(request, "MLSecOps")
        prod = [m for m in db.list_models() if m["name"] == model and m["status"] == "prod"]
        if not prod:
            raise HTTPException(404, f"у модели {model} нет прод-версии")
        for m in prod:
            db.set_status("model", model, m["version"], "previous")
        db.log_event(admin, "MLSecOps", "prod_rollback", asset=model, result="ok",
                     reason=req.reason or "откат из прода")
        return {"status": "ok", "model": model, "rolled_back": [m["version"] for m in prod]}

    @app.post("/api/v1/prod/{model}/{version}/retire")
    def retire(model: str, version: str, req: ReasonRequest, request: Request):
        """Вывод версии из эксплуатации. RBAC: MLSecOps. +reason +event."""
        admin = _require(request, "MLSecOps")
        rows = [m for m in db.list_models() if m["name"] == model and m["version"] == version]
        if not rows:
            raise HTTPException(404, f"модель {model}@{version} не найдена в реестре БД")
        db.set_status("model", model, version, "retired")
        db.log_event(admin, "MLSecOps", "model_retired", asset=f"{model}@{version}",
                     result="ok", reason=req.reason or "выведена из эксплуатации")
        return {"status": "ok", "model": model, "version": version, "model_status": "retired"}

    # ---- скан ресурса всеми применимыми образами ----
    @app.post("/api/v1/scan/{asset_type}/{asset_id}")
    def scan(asset_type: str, asset_id: str, request: Request):
        """Матричный скан ресурса всеми применимыми гейтами. RBAC: MLSecOps.

        Честная заглушка: для артефактов используется цепочка гейтов на странице артефакта
        (/artifacts/{run_id}/check), для файлов — покнопочный запуск (/ci/trigger).
        """
        _require(request, "MLSecOps")
        return {"status": "not_implemented",
                "detail": "Матричный раннер заменён цепочкой гейтов на странице артефакта."}

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

    # ---- инциденты (находки гейтов) ----
    @app.post("/api/v1/findings/{finding_id}/false_positive")
    def false_positive(finding_id: int, req: ReasonRequest, request: Request):
        """Отметить инцидент как false_positive. RBAC: MLSecOps. +reason +event."""
        admin = _require(request, "MLSecOps")
        db.mark_false_positive(finding_id, admin, req.reason or "")
        db.log_event(admin, "MLSecOps", "incident_false_positive", asset=str(finding_id),
                     result="ok", reason=req.reason or "отмечено как FP")
        return {"status": "ok", "finding_id": finding_id, "new_status": "false_positive"}

    @app.get("/api/v1/findings")
    def findings(request: Request, status: Optional[str] = None):
        """Инциденты (сработки гейтов). MLSecOps видит все; остальные — по своим артефактам."""
        user = _current_user(request)
        roles = sorted(identity.get_roles(user))
        items = db.list_findings(status=status)
        if "MLSecOps" not in roles:
            owned = {rid for rid, a in db.list_artifact_acls().items() if a.get("owner") == user}
            items = [f for f in items if f.get("asset") in owned]
        return {"findings": items}

    @app.get("/api/v1/events")
    def events(limit: int = 100):
        """История событий (Audit Trail, новые сверху)."""
        return {"events": db.list_events(limit)}

    # ─────────────────────── ИСТОРИЯ CI / pipeline_runs ───────────────────────
    @app.get("/api/v1/pipeline_runs")
    def pipeline_runs(request: Request, limit: int = 100,
                      trigger: Optional[str] = None, status: Optional[str] = None):
        """Список CI-прогонов (новые сверху). RBAC: любой аутентифицированный.

        Фильтры: trigger=artifact|git_push|manual_ui|ci_scheduled, status=running|passed|failed|error.
        Поле detail в списке усечено — для деталей зови GET /pipeline_runs/{id}.
        """
        _current_user(request)
        rows = db.list_pipeline_runs(limit, trigger=trigger, status=status)
        # В списке убираем тяжёлый detail-JSON (логи гейтов) — экономим трафик.
        for r in rows:
            r.pop("detail", None)
        return {"pipeline_runs": rows}

    @app.get("/api/v1/pipeline_runs/{run_id}")
    def pipeline_run_detail(run_id: int, request: Request):
        """Полная карточка CI-прогона (включая detail = гейты + логи)."""
        _current_user(request)
        pr = db.get_pipeline_run(run_id)
        if pr is None:
            raise HTTPException(404, "pipeline_run not found")
        return pr

    class PipelineRunCreate(BaseModel):
        # Тело POST от внешнего CI-runner-а (GitHub Actions, см. .github/workflows/gates.yml).
        # Backend сам прогон не делает — только пишет уже готовый результат в журнал.
        trigger: str = "git_push"
        source: Optional[str] = None    # git_sha
        ref: Optional[str] = None       # ветка/PR
        gate_ids: Optional[list[str]] = None
        status: str                     # passed|failed|error
        detail: Optional[dict] = None
        duration_ms: int = 0

    @app.post("/api/v1/pipeline_runs")
    def pipeline_run_ingest(req: PipelineRunCreate, request: Request):
        """Принять готовый результат CI-прогона снаружи (RBAC: MLSecOps или CI-роль).

        Используется CI-раннером (GitHub Actions / self-hosted runner) для записи результата
        прогона гейтов на репо в нашу историю CI. См. .github/workflows/gates.yml.
        """
        try:
            actor = identity.current_user(request)
        except identity.AuthError as e:
            raise HTTPException(401, str(e))
        roles = identity.get_roles(actor)
        # Пока CI-роли нет — пускаем MLSecOps и спец-юзера 'ci'. Расширишь добавив роль 'CI'.
        if "MLSecOps" not in roles and actor != "ci":
            db.log_event(actor, sorted(roles)[0] if roles else "none", "access_denied",
                         result="blocked", reason="pipeline_run ingest requires MLSecOps/ci")
            raise HTTPException(403, "ingest pipeline_run requires MLSecOps or CI role")
        if req.status not in ("passed", "failed", "error"):
            raise HTTPException(400, f"bad status {req.status}")
        pr_id = db.create_pipeline_run(trigger=req.trigger, source=req.source,
                                       actor=actor, gate_ids=req.gate_ids, ref=req.ref)
        db.finish_pipeline_run(pr_id, status=req.status, detail=req.detail,
                               duration_ms=req.duration_ms)
        db.log_event(actor, "MLSecOps" if "MLSecOps" in roles else "ci",
                     "ci_pipeline_recorded", asset=req.source or str(pr_id),
                     result="ok" if req.status == "passed" else "blocked",
                     reason=f"trigger={req.trigger} ref={req.ref}",
                     details={"pipeline_run_id": pr_id, "status": req.status,
                              "gate_ids": req.gate_ids})
        return {"id": pr_id, "status": req.status}

    @app.get("/api/v1/events/verify_chain")
    def events_verify_chain():
        """Проверить целостность hash-chain Audit Trail → {ok, broken_at, count} (угроза #24)."""
        return db.verify_chain()

    @app.get("/api/v1/registry")
    def registry(request: Request):
        """Реестр артефактов по зонам (свалка/ок/не прошли/выкатка/прод).

        Источник — artifact_acl + MLflow-раны. Видимость: владелец видит свои (включая
        черновики до проверки); MLSecOps — все артефакты, попавшие в пайплайн (прошедшие
        security check); остальные — расшаренное им. Без новых таблиц.
        """
        user = _current_user(request)
        roles = sorted(identity.get_roles(user))
        from core import mlflow_utils
        runs = mlflow_utils.list_recent_runs(200)
        acls = db.list_artifact_acls([r["run_id"] for r in runs])
        new_rows = [(r["run_id"], r.get("experiment_id", ""), r.get("owner") or "",
                     r.get("run_name"))
                    for r in runs if r["run_id"] not in acls]
        db.upsert_artifacts_bulk(new_rows)
        if new_rows:
            acls = db.list_artifact_acls([r["run_id"] for r in runs])
        artifacts = []
        seen = set()
        for r in runs:
            acl = acls.get(r["run_id"])
            if acl is None or not _registry_visible(acl, user, roles):
                continue
            seen.add(r["run_id"])
            artifacts.append(_enrich_artifact(r, acl))
        # DB-only артефакты (нет живого MLflow-рана): ручные сиды/демо-инциденты, артефакты из
        # стора, который недоступен сейчас. Чтобы они тоже отображались в реестре (зона «не прошли»
        # и т.п.), строим карточку из ACL. Метрики/имя берём из ACL (session_name).
        for rid, acl in db.list_artifact_acls().items():
            if rid in seen or not _registry_visible(acl, user, roles):
                continue
            stub = {"run_id": rid, "experiment": acl.get("experiment_id"),
                    "experiment_id": acl.get("experiment_id"), "run_name": acl.get("session_name"),
                    "owner": acl.get("owner"), "metrics": {}, "params": {}, "tags": {}}
            artifacts.append(_enrich_artifact(stub, acl))
        zones = {}
        for a in artifacts:
            zones.setdefault(a["zone"], 0)
            zones[a["zone"]] += 1
        return {"artifacts": artifacts, "zones": zones,
                "my_clearance": identity.clearance(roles),
                "storage_note": ("Артефакты физически — в artifact store MLflow (локально ./mlruns; "
                                 "в compose — бакет 'mlflow' в MinIO). Прод/одобренные в перспективе — "
                                 "WORM-копия в S3/MinIO под контролем MLflow + нашего сервиса.")}

    @app.get("/api/v1/monitoring/models")
    def monitoring_models(request: Request):
        """Карточки моделей для мониторинга рантайма: метрики обучения + теги паспорта модели
        + ПЛЕЙСХОЛДЕР инференс-метрик (latency/throughput/error-rate). RBAC: любой аутентифицированный.

        Показывает артефакты в зонах prod / выкатка / прошли проверку (то, что эксплуатируется или
        готово к этому). Инференс-метрики — детерминированный плейсхолдер (рантайм-слой C ещё не
        прокинут в бэкенд A); теги паспорта (model.name/model.description) берём из тегов рана,
        иначе плейсхолдер. Видимость — как в реестре.
        """
        user = _current_user(request)
        roles = sorted(identity.get_roles(user))
        from core import mlflow_utils
        import hashlib
        runs = mlflow_utils.list_recent_runs(200)
        acls = db.list_artifact_acls([r["run_id"] for r in runs])
        out = []
        for r in runs:
            acl = acls.get(r["run_id"])
            if acl is None or not _registry_visible(acl, user, roles):
                continue
            card = _enrich_artifact(r, acl)
            if card["zone"] not in ("prod", "deploying", "ok"):
                continue
            tags = card.get("tags") or {}
            # Детерминированный плейсхолдер инференс-метрик (стабилен для одного run_id).
            seed = int(hashlib.sha256(card["run_id"].encode()).hexdigest(), 16)
            card["model_name"] = tags.get("model.name") or card.get("run_name") or card["run_id"][:8]
            card["model_description"] = (tags.get("model.description")
                                         or tags.get("model.purpose")
                                         or "— (паспорт модели не заполнен, плейсхолдер)")
            card["inference_metrics"] = {
                "p95_latency_ms": 40 + seed % 80,
                "throughput_rps": 50 + seed % 200,
                "error_rate_pct": round((seed % 50) / 10.0, 1),
                "requests_24h": 1000 + seed % 9000,
                "placeholder": True,
            }
            out.append(card)
        # prod выше, затем выкатка, затем ok
        order = {"prod": 0, "deploying": 1, "ok": 2}
        out.sort(key=lambda c: order.get(c["zone"], 9))
        return {"models": out, "inference_metrics_placeholder": True}

    @app.get("/api/v1/approvals/pending")
    def pending_approvals(request: Request):
        """Артефакты, ожидающие HITL Approve (stage=pending_approve). RBAC: MLSecOps.

        DB-driven и устойчиво: берём только pending-раны из ACL (их единицы) и обогащаем
        метаданными MLflow best-effort per-run. НЕ сканируем все 200 ранов MLflow — иначе при
        медленном/недоступном MLflow ручка таймаутила и очередь HITL «моргала» ошибкой.
        """
        _require(request, "MLSecOps")
        from core import mlflow_utils
        out = []
        for rid, acl in db.list_artifact_acls().items():
            if (acl.get("stage") or "none") != "pending_approve":
                continue
            meta = mlflow_utils.get_run(rid) or {
                "run_id": rid, "run_name": acl.get("session_name"),
                "experiment": acl.get("experiment_id"), "owner": acl.get("owner")}
            out.append(_enrich_artifact(meta, acl))
        return {"pending": out}

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
