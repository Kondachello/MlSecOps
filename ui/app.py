"""Streamlit UI — MLSecOps Platform (тёмная тема, интерактив).

Разделы: Дашборд · Верификация/Раннер гейтов · Реестр · Паспорт · История ·
Находки · CI/CD логи · Инструменты · Деплой/Approve · Пользователи.
Навигация — st.radio (поддерживает программные переходы). Данные — моки + fallback к API.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone

try:
    import streamlit as st
    import requests
    _HAS_STREAMLIT = True
except Exception:
    _HAS_STREAMLIT = False
    st = None  # type: ignore

# Каталог контролей (угроза→контроль→тест→покрытие). Pure-data модуль без зависимостей.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from src.common import controls as CTRL
except Exception:  # noqa: BLE001
    CTRL = None

API = os.getenv("GATEKEEPER_URL", "http://backend:8000")
APP_DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"
USE_MOCKS = os.getenv("UI_USE_MOCKS", "false").lower() == "true"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ─────────────────────────────── MOCK DATA ──────────────────────────────────
MOCK_MODELS = [
    {"name": "credit_scoring", "version": "1.0.0", "owner": "ivanov@example.com",
     "tier": "HIGH", "status": "candidate", "trained_in_ci": True,
     "sha256": "1b5e53e0b230e196", "dataset": "train_m1_clean@v1",
     "git_sha": "a1b2c3d4", "run_id": "local-run-001"},
    {"name": "text_classifier", "version": "1.0.0", "owner": "petrova@example.com",
     "tier": "MED", "status": "available", "trained_in_ci": True,
     "sha256": "abc123def456", "dataset": "synthetic_text@v1",
     "git_sha": "a1b2c3d4", "run_id": "local-run-002"},
    {"name": "transaction_risk", "version": "1.0.0", "owner": "ivanov@example.com",
     "tier": "HIGH", "status": "pending_hitl", "trained_in_ci": True,
     "sha256": "deadbeef1234", "dataset": "train_m1_clean@v1",
     "git_sha": "a1b2c3d4", "run_id": "local-run-003"},
]

MOCK_DATASETS = {
    "train_m1_clean@v1": {
        "name": "train_m1_clean", "version": "v1", "rows": 1000,
        "columns": ["amount", "age", "target"], "source_type": "corp_storage",
        "uploaded_by": "de-team@example.com", "sha256": "9f2a1c5e7b3d8a04",
        "status": "available",
        "g1": {"passed": True, "pii": "не найдено", "class_balance": "fraud=2% (норма)"},
        "ts": "2026-05-30 12:04"},
    "synthetic_text@v1": {
        "name": "synthetic_text", "version": "v1", "rows": 4000,
        "columns": ["text", "label"], "source_type": "verified_id",
        "uploaded_by": "ds-team@example.com", "sha256": "3c7d9e1f0a2b6c58",
        "status": "available",
        "g1": {"passed": True, "pii": "не найдено", "injections": "не найдено"},
        "ts": "2026-05-31 09:20"},
}

MOCK_MODEL_VERSIONS = {
    "credit_scoring": [
        {"version": "1.0.0", "status": "candidate", "tier": "HIGH", "author": "ivanov@example.com",
         "dataset": "train_m1_clean@v1", "git_sha": "a1b2c3d4", "run_id": "local-run-001",
         "sha256": "1b5e53e0b230e196", "accuracy": 0.986, "ts": "2026-06-03 11:54",
         "change": "Добавлены фичи amount_per_age; переобучение на чистых данных",
         "approved_by": None, "approve_reason": None,
         "gates": {"G2": "PASS", "G3": "PASS", "G4": "PASS", "G5": "PASS"}},
        {"version": "0.9.0", "status": "previous", "tier": "HIGH", "author": "ivanov@example.com",
         "dataset": "train_m1_clean@v1", "git_sha": "99aa11bb", "run_id": "local-run-000",
         "sha256": "77cc22dd88ee", "accuracy": 0.972, "ts": "2026-05-28 16:10",
         "change": "Базовая версия (LogReg, 2 фичи)",
         "approved_by": "mlsecops@example.com", "approve_reason": "Релиз MVP скоринга",
         "gates": {"G2": "PASS", "G3": "PASS", "G4": "PASS", "G5": "PASS"}},
    ],
    "text_classifier": [
        {"version": "1.0.0", "status": "available", "tier": "MED", "author": "petrova@example.com",
         "dataset": "synthetic_text@v1", "git_sha": "a1b2c3d4", "run_id": "local-run-002",
         "sha256": "abc123def456", "accuracy": 0.941, "ts": "2026-06-03 11:54",
         "change": "TF-IDF + LogReg, спам-классификатор",
         "approved_by": None, "approve_reason": None,
         "gates": {"G2": "PASS", "G3": "PASS", "G4": "PASS", "G5": "PASS"}},
    ],
    "transaction_risk": [
        {"version": "1.0.0", "status": "pending_hitl", "tier": "HIGH", "author": "ivanov@example.com",
         "dataset": "train_m1_clean@v1", "git_sha": "a1b2c3d4", "run_id": "local-run-003",
         "sha256": "deadbeef1234", "accuracy": 0.958, "ts": "2026-06-03 11:54",
         "change": "GBT, 6 фич риска транзакции",
         "approved_by": None, "approve_reason": None,
         "gates": {"G2": "PASS", "G3": "PASS", "G4": "PASS", "G5": "PASS"}},
    ],
}

MOCK_MODEL_META = {
    "credit_scoring":   {"purpose": "Кредитный скоринг физлиц", "framework": "sklearn LogisticRegression",
                         "params": {"max_iter": 1000, "features": 3}, "code_url": "git:src/train/train.py"},
    "text_classifier":  {"purpose": "Классификация текста (спам)", "framework": "TF-IDF + LogReg",
                         "params": {"ngram": "1-2", "features": "tfidf"}, "code_url": "git:src/train/train_text.py"},
    "transaction_risk": {"purpose": "Оценка риска транзакции", "framework": "Gradient Boosting",
                         "params": {"n_estimators": 100, "features": 6}, "code_url": "git:src/train/train_risk.py"},
}

MOCK_EVENTS = [
    {"id": 1, "ts": _now(), "type": "dataset_ingested", "actor": "de-team@example.com",
     "asset": "train_m1_clean@v1", "result": "ok", "detail": "G1 PASS — датасет принят"},
    {"id": 2, "ts": _now(), "type": "gate_run", "actor": "ci-runner",
     "asset": "credit_scoring@1.0.0", "result": "ok", "detail": "G2 PASS: секретов нет"},
    {"id": 3, "ts": _now(), "type": "gate_run", "actor": "ci-runner",
     "asset": "credit_scoring@1.0.0", "result": "ok", "detail": "G4 PASS: формат onnx"},
    {"id": 4, "ts": _now(), "type": "model_registered", "actor": "ci-runner",
     "asset": "credit_scoring@1.0.0", "result": "ok", "detail": "alias=candidate"},
    {"id": 5, "ts": _now(), "type": "dataset_blocked", "actor": "ci-runner",
     "asset": "train_m1_poisoned@v1", "result": "blocked",
     "detail": "G1 FAIL: дисбаланс классов + PII"},
    {"id": 6, "ts": _now(), "type": "deploy_requested", "actor": "ivanov@example.com",
     "asset": "transaction_risk@1.0.0", "result": "pending",
     "detail": "Tier=HIGH — ожидает HITL Approve"},
    {"id": 7, "ts": _now(), "type": "access_denied", "actor": "ivanov@example.com",
     "asset": "transaction_risk@1.0.0", "result": "error",
     "detail": "403: DS не может делать Approve (нужен MLSecOps)"},
]

MOCK_FINDINGS = [
    {"id": 1, "gate": "G1", "check": "pii", "severity": "high", "status": "open",
     "asset": "train_m1_poisoned@v1", "ts": _now(), "detail": "Найдено ПДн: email (3 примера)",
     "evidence": {"types": ["email"], "samples": ["user0@example.com", "user1@example.com"]}},
    {"id": 2, "gate": "G1", "check": "class_balance", "severity": "high", "status": "open",
     "asset": "train_m1_poisoned@v1", "ts": _now(), "detail": "Класс меньшинства = 49.6% (порог 30%)",
     "evidence": {"minority_rate": 0.496, "distribution": {"0": 0.504, "1": 0.496}}},
    {"id": 3, "gate": "G2", "check": "secrets", "severity": "critical", "status": "closed",
     "asset": "PR#42", "ts": _now(), "detail": "Найден API_KEY в leaky.py:13",
     "evidence": {"rule": "generic-api-key", "file": "leaky.py", "line": 13}},
    {"id": 4, "gate": "G2", "check": "sast", "severity": "high", "status": "fp",
     "asset": "PR#41", "ts": _now(), "detail": "B602 subprocess shell=True (демо-фикстура)",
     "evidence": {"test": "subprocess_with_shell", "file": "demo/insecure/leaky.py", "line": 27},
     "fp_reason": "Намеренная SAST-приманка в demo/, не прод-код"},
    {"id": 5, "gate": "G3", "check": "name_allowlist", "severity": "critical", "status": "open",
     "asset": "PR#42", "ts": _now(), "detail": "Typosquatting: pytirch, tenserflew",
     "evidence": {"typosquats": ["pytirch", "tenserflew"]}},
    {"id": 6, "gate": "G4", "check": "weights_format", "severity": "critical", "status": "open",
     "asset": "external_model_unsafe.pkl", "ts": _now(),
     "detail": "Запрещённый формат .pkl (RCE при load)",
     "evidence": {"ext": ".pkl", "blocked": [".pkl", ".joblib", ".pt"]}},
]

MOCK_CICD_RUNS = [
    {"id": "run-1042", "workflow": "ci.yml", "trigger": "PR #42", "actor": "ivanov@example.com",
     "commit": "a1b2c3d", "branch": "feature/new-features", "status": "failed",
     "ts": _now(), "duration": "2m13s", "jobs": [
        {"name": "syntax", "status": "success", "duration": "9s",
         "steps": [{"name": "py_compile", "status": "success", "log": "All files compiled OK"}]},
        {"name": "data-gate", "status": "success", "duration": "18s", "steps": [
            {"name": "clean passes", "status": "success", "log": '{"gate":"G1","passed":true}'},
            {"name": "poisoned is blocked", "status": "success", "log": "ok, заблокировано"}]},
        {"name": "code-gate", "status": "failed", "duration": "41s", "steps": [
            {"name": "install scanners", "status": "success", "log": "installed bandit, pip-audit"},
            {"name": "clean src", "status": "success", "log": '{"gate":"G2","passed":true}'},
            {"name": "insecure fixture (должен FAIL)", "status": "failed", "exit": 1, "log": (
                'Run code_gate --path demo/insecure --stage ci --json\n'
                '{"gate":"G2","passed":false,"failed_checks":["secrets","sast"],'
                '"checks":[{"check":"secrets","status":"FAIL","severity":"critical",'
                '"detail":"gitleaks: 1 secret","evidence":{"rule":"generic-api-key",'
                '"file":"leaky.py","line":13}},{"check":"sast","status":"FAIL","severity":"high",'
                '"detail":"bandit B602 shell=True","evidence":{"file":"leaky.py","line":27}}]}\n'
                '##[error]Process completed with exit code 1.')}]},
        {"name": "dependency-gate", "status": "success", "duration": "6s", "steps": [
            {"name": "clean requirements", "status": "success", "log": '{"gate":"G3","passed":true}'},
            {"name": "typosquat blocked", "status": "success", "log": "pytirch заблокирован"}]},
        {"name": "model-gate", "status": "skipped", "duration": "0s", "steps": []},
        {"name": "registry-gate", "status": "skipped", "duration": "0s", "steps": []},
     ]},
    {"id": "run-1043", "workflow": "train.yml", "trigger": "manual (RUN)", "actor": "ivanov@example.com",
     "commit": "f7e8d9a", "branch": "main", "status": "failed", "ts": _now(), "duration": "5m02s",
     "jobs": [{"name": "train", "status": "failed", "duration": "5m02s", "steps": [
        {"name": "G2 Code Gate (ci)", "status": "success", "log": "G2 PASS"},
        {"name": "обучение в CI", "status": "success",
         "log": "[train] OK: artifacts/credit_scoring.onnx accuracy=0.9860"},
        {"name": "G4 Model Gate", "status": "failed", "exit": 1, "log": (
            '{"gate":"G4","passed":false,"failed_checks":["weights_scan"],'
            '"checks":[{"check":"weights_format","status":"PASS","detail":".onnx разрешён"},'
            '{"check":"weights_scan","status":"FAIL","severity":"critical",'
            '"detail":"modelscan: подозрительный оператор в графе",'
            '"evidence":{"scanner":"modelscan","issues":1}}]}\n'
            '##[error]G4 FAIL — артефакт не допущен в реестр')},
        {"name": "Consistency", "status": "skipped", "log": "(не выполнялся)"},
        {"name": "register", "status": "skipped", "log": "(не выполнялся)"}]}]},
    {"id": "run-1041", "workflow": "deploy.yml", "trigger": "manual (DEPLOY)",
     "actor": "mlsecops@example.com", "commit": "a1b2c3d", "branch": "main", "status": "success",
     "ts": _now(), "duration": "3m48s", "jobs": [{"name": "deploy", "status": "success",
     "duration": "3m48s", "steps": [
        {"name": "HITL gate", "status": "success", "log": "status: approved"},
        {"name": "G2 Code Gate (deploy)", "status": "success", "log": "G2 PASS"},
        {"name": "G4 SHA-сверка", "status": "success", "log": "sha совпал"},
        {"name": "trivy image", "status": "success", "log": "0 CRITICAL, 0 HIGH"},
        {"name": "cosign sign", "status": "success", "log": "model.onnx.sig"},
        {"name": "WORM + docker run", "status": "success", "log": "alias=production; health=ok"}]}]},
]

MOCK_USERS = [
    {"login": "ivanov", "email": "ivanov@example.com", "role": "DS", "status": "active",
     "last": "2026-06-03 10:12", "perms": ["dataset:read", "model:train", "verify:run"]},
    {"login": "petrova", "email": "petrova@example.com", "role": "DS", "status": "active",
     "last": "2026-06-02 18:40", "perms": ["dataset:read", "model:train", "verify:run"]},
    {"login": "de_team", "email": "de-team@example.com", "role": "DE", "status": "active",
     "last": "2026-06-03 09:05", "perms": ["dataset:upload", "dataset:grant"]},
    {"login": "msecops", "email": "mlsecops@example.com", "role": "MLSecOps", "status": "active",
     "last": "2026-06-03 11:58", "perms": ["approve", "deploy", "retire", "tier:set",
                                           "fp:mark", "gate:run", "rbac:admin"]},
    {"login": "ceo", "email": "ceo@example.com", "role": "CEO", "status": "active",
     "last": "2026-06-01 12:00", "perms": ["dashboard:read"]},
]

# Ресурсы для раннера гейтов (тип → применимые гейты)
MOCK_RESOURCES = [
    {"id": "train_m1_clean@v1", "type": "dataset", "gates": ["G1"]},
    {"id": "train_m1_poisoned@v1", "type": "dataset", "gates": ["G1"]},
    {"id": "synthetic_text@v1", "type": "dataset", "gates": ["G1"]},
    {"id": "credit_scoring@1.0.0", "type": "model", "gates": ["G4", "G5"]},
    {"id": "transaction_risk@1.0.0", "type": "model", "gates": ["G4", "G5"]},
    {"id": "PR#42 (code)", "type": "code", "gates": ["G2", "G3"]},
    {"id": "PR#41 (code)", "type": "code", "gates": ["G2", "G3"]},
]

ALL_GATES = ["G1", "G2", "G3", "G4", "G5"]
GATE_TITLE = {"G1": "Data", "G2": "Code", "G3": "Supply", "G4": "Model", "G5": "Registry"}
THREAT_MAP = {
    "G1": "#1 Data Poisoning · #2 PII", "G2": "#8 CVE · #10 Секреты",
    "G3": "#9 Typosquatting · #3 Источник", "G4": "#3 Pickle/RCE · #4 Подмена · #26 Подпись",
    "G5": "#20 Shadow AI · #23 Lineage",
}


def _run_gate_mock(resource_id: str, gate: str) -> tuple[str, str]:
    """Детерминированный мок прогона гейта на ресурсе."""
    res = next((r for r in MOCK_RESOURCES if r["id"] == resource_id), None)
    if not res or gate not in res["gates"]:
        return "SKIP", "гейт не применим к типу ресурса"
    if "poisoned" in resource_id and gate == "G1":
        return "FAIL", "дисбаланс классов 49.6% + PII(email)"
    if resource_id.startswith("PR#42") and gate == "G2":
        return "FAIL", "gitleaks: секрет leaky.py:13; bandit B602"
    if resource_id.startswith("PR#42") and gate == "G3":
        return "FAIL", "typosquatting: pytirch, tenserflew"
    return "PASS", "проверки пройдены"


# ─────────────────────────────── СТИЛЬ ──────────────────────────────────────
_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
:root{
  --bg:#0B0E16; --panel:#121626; --panel2:#171C2E; --line:#262C40;
  --ink:#E6E9F2; --muted:#8B93A7; --accent:#6366F1; --accent2:#22D3EE;
  --ok:#34D399; --okbg:#0E2A22; --bad:#F87171; --badbg:#2A1316;
  --warn:#FBBF24; --warnbg:#2A2210; --info:#818CF8; --infobg:#171A33;
}
html,body,[class*="css"]{font-family:'Inter',system-ui,sans-serif;}
.stApp{background:radial-gradient(1200px 600px at 20% -10%, #161B2E 0%, var(--bg) 55%);}
#MainMenu,footer{visibility:hidden;}
[data-testid="stSidebarCollapsedControl"],[data-testid="collapsedControl"]{visibility:visible!important;display:flex!important;}
.block-container{padding-top:1.6rem;max-width:1240px;}
h1{font-weight:800;letter-spacing:-.025em;font-size:1.7rem;color:var(--ink);}
h2{font-weight:700;font-size:1.25rem;color:var(--ink);}
h3{font-weight:650;font-size:1.0rem;color:var(--ink);margin-top:1.1rem;padding-bottom:.3rem;
   border-bottom:1px solid var(--line);}
p,li,span,label,div{color:var(--ink);}
small,.muted{color:var(--muted)!important;}
code,.mono{font-family:'JetBrains Mono',monospace;font-size:.82rem;color:#C7D2FE;
   background:#0F1424;padding:.05rem .35rem;border-radius:6px;}
/* sidebar */
section[data-testid="stSidebar"]{background:linear-gradient(180deg,#0C1020,#0A0D18);border-right:1px solid var(--line);}
section[data-testid="stSidebar"] *{color:#C4CBDC;}
section[data-testid="stSidebar"] [role="radiogroup"] label{padding:.4rem .55rem;border-radius:10px;margin:1px 0;
   border:1px solid transparent;transition:.15s;}
section[data-testid="stSidebar"] [role="radiogroup"] label:hover{background:#141A2E;border-color:var(--line);}
/* metric cards */
[data-testid="stMetric"]{background:linear-gradient(180deg,var(--panel),var(--panel2));
  border:1px solid var(--line);border-radius:14px;padding:.8rem 1rem;
  box-shadow:0 8px 24px rgba(0,0,0,.25);}
[data-testid="stMetricValue"]{font-weight:800;color:var(--ink);}
[data-testid="stMetricLabel"]{color:var(--muted);}
/* expanders / containers */
[data-testid="stExpander"]{background:var(--panel);border:1px solid var(--line);border-radius:14px;}
[data-testid="stExpander"] summary{font-weight:600;}
/* buttons */
.stButton>button{background:var(--panel2);border:1px solid var(--line);color:var(--ink);
  border-radius:11px;font-weight:600;padding:.45rem 1rem;transition:.15s;}
.stButton>button:hover{border-color:var(--accent);color:#fff;box-shadow:0 0 0 3px rgba(99,102,241,.15);}
/* dataframe */
[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:14px;overflow:hidden;}
/* pills */
.pill{display:inline-block;padding:.14rem .6rem;border-radius:999px;font-size:.73rem;
  font-weight:700;letter-spacing:.03em;border:1px solid transparent;}
.pill-ok{background:var(--okbg);color:var(--ok);border-color:#14533c;}
.pill-bad{background:var(--badbg);color:var(--bad);border-color:#5b2026;}
.pill-warn{background:var(--warnbg);color:var(--warn);border-color:#564216;}
.pill-info{background:var(--infobg);color:var(--info);border-color:#2c2f63;}
.pill-muted{background:#1A2034;color:var(--muted);border-color:var(--line);}
/* event/finding cards */
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--muted);
  border-radius:12px;padding:.7rem .9rem;margin:.45rem 0;box-shadow:0 6px 18px rgba(0,0,0,.18);}
.card.ok{border-left-color:var(--ok);} .card.bad{border-left-color:var(--bad);}
.card.warn{border-left-color:var(--warn);} .card.info{border-left-color:var(--accent2);}
.card .h{font-weight:700;font-size:.92rem;}
.card .s{color:var(--muted);font-size:.8rem;}
/* pipeline */
.stage{display:flex;align-items:center;gap:.6rem;padding:.5rem .7rem;border:1px solid var(--line);
  border-radius:11px;background:var(--panel);margin:.3rem 0;}
.stage.ok{border-left:4px solid var(--ok);} .stage.bad{border-left:4px solid var(--bad);}
.stage.muted{border-left:4px solid var(--muted);opacity:.7;}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;}
.errbox{background:var(--badbg);border:1px solid #5b2026;border-radius:10px;padding:.55rem .8rem;
  color:#FCA5A5;font-family:'JetBrains Mono',monospace;font-size:.8rem;}
hr{border-color:var(--line);}
</style>
"""


def inject_css():
    st.markdown(_CSS, unsafe_allow_html=True)


# ─────────────────────────────── HELPERS ────────────────────────────────────
def _api_headers() -> dict:
    h: dict = {}
    tok = st.session_state.get("access_token")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    elif APP_DEBUG:
        h["X-Demo-Role"] = _role()
    return h


def _api_get(path, mock=None):
    try:
        r = requests.get(f"{API}{path}", headers=_api_headers(), timeout=3)
        if r.ok:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return mock


def _api_items(path: str, key: str, mock=None):
    """GET с обёрткой API: {"findings": [...]} → list; иначе mock/fallback."""
    data = _api_get(path, mock=mock)
    if isinstance(data, dict) and key in data:
        items = data[key]
        return items if isinstance(items, list) else (mock or [])
    if isinstance(data, list):
        return data
    return mock if mock is not None else []


def _norm_event(e: dict) -> dict:
    """События из Postgres (action/reason) → поля UI (type/detail)."""
    return {
        "id": e.get("id"),
        "ts": e.get("ts", ""),
        "type": e.get("type", e.get("action", "")),
        "actor": e.get("actor", ""),
        "asset": e.get("asset", ""),
        "result": e.get("result", ""),
        "detail": e.get("detail", e.get("reason", "")),
    }


def _norm_finding(f: dict) -> dict:
    """Находки из БД (rule) → поля UI (check/detail)."""
    out = dict(f)
    out.setdefault("check", f.get("check", f.get("rule", "")))
    if "detail" not in out or not out["detail"]:
        ev = f.get("evidence")
        out["detail"] = f.get("detail") or (json.dumps(ev, ensure_ascii=False)[:200] if ev else "")
    st = out.get("status", "open")
    if st == "false_positive":
        out["status"] = "fp"
    elif st == "fixed":
        out["status"] = "closed"
    return out


def _api_post(path, data, mock=None):
    try:
        r = requests.post(f"{API}{path}", json=data, headers=_api_headers(), timeout=30)
        if r.ok:
            return r.json()
        return {"ok": False, "error": r.text[:500], "status_code": r.status_code}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    return mock


# ── Data-аксессоры: только API; моки — только при UI_USE_MOCKS=true (офлайн-разработка). ──
def _mock_or(items, mock_list):
    return mock_list if (USE_MOCKS and mock_list is not None) else (items or [])


def get_models():
    items = _api_items("/api/v1/models", "models", mock=None)
    if items and isinstance(items[0], dict) and "tier" in items[0]:
        return items
    return _mock_or([], MOCK_MODELS)


def get_versions(name):
    items = _api_items(f"/api/v1/models/{name}/versions", "versions", mock=None)
    if items:
        return items
    return _mock_or([], MOCK_MODEL_VERSIONS.get(name, []))


def get_dataset(key):
    data = _api_get(f"/api/v1/datasets/{key}", mock=None)
    if data:
        return data
    return MOCK_DATASETS.get(key) if USE_MOCKS else None


def get_users():
    items = _api_items("/api/v1/admin/users", "users", mock=None)
    if not items:
        return _mock_or([], MOCK_USERS)
    out = []
    for u in items:
        roles = u.get("roles") or ["DS"]
        role = roles[0] if roles else "DS"
        out.append({
            "login": u.get("username", u.get("login", "")),
            "email": u.get("email", ""),
            "role": role,
            "status": "active",
            "last": "—",
            "perms": [f"{role.lower()}:read", f"{role.lower()}:write"],
        })
    return out


def get_resources():
    items = _api_items("/api/v1/resources", "resources", mock=None)
    return _mock_or(items, MOCK_RESOURCES)


def get_controls():
    fb = CTRL.CONTROLS if CTRL else []
    items = _api_items("/api/v1/controls", "controls", mock=None)
    return _mock_or(items, fb)


def _rerun():
    fn = getattr(st, "rerun", None) or getattr(st, "experimental_rerun", None)
    if fn:
        fn()


def _goto(page, **pending):
    st.session_state["_nav_request"] = page
    if pending:
        st.session_state["_pending_state"] = pending
    _rerun()


def _role():
    roles = st.session_state.get("roles") or []
    if "MLSecOps" in roles:
        return "MLSecOps"
    if roles:
        return roles[0]
    return st.session_state.get("role", "DS")


def _sidebar_auth():
    """JWT-логин (боевой режим) или переключатель роли (APP_DEBUG)."""
    if APP_DEBUG:
        st.session_state["role"] = st.sidebar.selectbox("Роль (demo)", ["DS", "MLSecOps", "CEO"])
        return
    if st.session_state.get("access_token"):
        me = _api_get("/api/v1/auth/me")
        if me and me.get("username"):
            st.session_state["roles"] = me.get("roles", [])
            st.sidebar.caption(f"**{me['username']}** · {', '.join(me.get('roles') or ['без роли'])}")
            if st.sidebar.button("Выйти", use_container_width=True):
                for k in ("access_token", "username", "roles", "role"):
                    st.session_state.pop(k, None)
                _rerun()
            return
        st.session_state.pop("access_token", None)
    with st.sidebar.form("login", clear_on_submit=False):
        st.markdown("**Вход**")
        user = st.text_input("Логин", value=os.getenv("BOOTSTRAP_ADMIN_USER", "msecops"))
        pwd = st.text_input("Пароль", type="password")
        if st.form_submit_button("Войти", use_container_width=True):
            try:
                r = requests.post(
                    f"{API}/api/v1/auth/login",
                    json={"username": user, "password": pwd},
                    timeout=8,
                )
                if r.ok:
                    data = r.json()
                    st.session_state["access_token"] = data["access_token"]
                    st.session_state["roles"] = data.get("roles", [])
                    st.session_state["username"] = user
                    _rerun()
                else:
                    st.sidebar.error("Неверный логин или пароль")
            except Exception as e:  # noqa: BLE001
                st.sidebar.error(f"API недоступен: {API} ({e})")
    st.sidebar.info("Запустите стенд: `docker compose -f infra/docker-compose.yml up --build`")
    st.stop()


_KIND = {"ok": "ok", "available": "ok", "prod": "ok", "production": "ok", "closed": "ok",
         "pass": "ok", "success": "ok",
         "blocked": "bad", "fail": "bad", "failed": "bad", "open": "bad", "error": "bad",
         "pending": "warn", "pending_hitl": "warn", "running": "warn", "queued": "warn",
         "candidate": "info", "previous": "muted", "retired": "muted", "fp": "muted",
         "skip": "muted", "skipped": "muted"}


def _kind(s):
    return _KIND.get(str(s).lower(), "muted")


def _pill(text, kind="muted"):
    return f"<span class='pill pill-{kind}'>{text}</span>"


def _spill(status):
    return _pill(str(status).replace("_", " ").upper(), _kind(status))


def _tpill(tier):
    k = {"HIGH": "bad", "MED": "warn", "LOW": "ok"}.get(str(tier).upper(), "muted")
    return _pill(str(tier).upper(), k)


def _sevpill(sev):
    k = {"critical": "bad", "high": "bad", "medium": "warn", "low": "info"}.get(str(sev).lower(), "muted")
    return _pill(str(sev).upper(), k)


def _sel(event):
    try:
        rows = event.selection["rows"]
    except Exception:  # noqa: BLE001
        rows = getattr(getattr(event, "selection", None), "rows", []) or []
    return rows[0] if rows else None


def _lineage_dot(version: dict, model_name: str) -> str:
    ds = version.get("dataset", "?")
    return f'''digraph {{
  rankdir=LR; bgcolor="transparent"; pad=0.2; nodesep=0.5; ranksep=0.8;
  node [shape=box style="rounded,filled" fontname="Inter" fontsize=11
        color="#2A3147" fontcolor="#E6E9F2" penwidth=1.2];
  edge [color="#5B6480" fontcolor="#8B93A7" fontname="Inter" fontsize=9];
  data  [label="ДАННЫЕ\\n{ds}" fillcolor="#16263F"];
  code  [label="КОД\\n{version.get('git_sha','?')}" fillcolor="#241C3D"];
  model [label="МОДЕЛЬ\\n{model_name} v{version.get('version','?')}" fillcolor="#0F2A20"];
  run   [label="MLflow run\\n{version.get('run_id','?')}" fillcolor="#1A2236"];
  data -> model [label="trained on"];
  code -> model [label="built by"];
  run  -> model [label="logged"];
}}'''


def _versions_dot(versions: list, model_name: str) -> str:
    chain = list(reversed(versions))
    color = {"prod": "#0F2A20", "production": "#0F2A20", "available": "#0F2A20",
             "candidate": "#1A2347", "pending_hitl": "#2A2210", "previous": "#1A2034",
             "retired": "#15182A", "blocked": "#2A1316"}
    nodes, edges = [], []
    for i, v in enumerate(chain):
        nid = f"v{i}"
        nodes.append(f'{nid} [label="v{v["version"]}\\n{v["status"]}\\n{v["ts"][:10]}" '
                     f'fillcolor="{color.get(v["status"], "#1A2034")}"];')
        if i:
            edges.append(f'v{i-1} -> {nid} [label="promote"];')
    return ('digraph { rankdir=LR; bgcolor="transparent"; pad=0.2; '
            'node [shape=box style="rounded,filled" fontname="Inter" fontsize=10 '
            'color="#2A3147" fontcolor="#E6E9F2"]; '
            'edge [color="#5B6480" fontcolor="#8B93A7" fontname="Inter" fontsize=9]; '
            + " ".join(nodes) + " " + " ".join(edges) + " }")


def _finding_dot(f: dict) -> str:
    return ('digraph { rankdir=LR; bgcolor="transparent"; pad=0.2; '
            'node [shape=box style="rounded,filled" fontname="Inter" fontsize=10 '
            'color="#2A3147" fontcolor="#E6E9F2"]; '
            'edge [color="#5B6480" fontcolor="#8B93A7" fontsize=9]; '
            f'asset [label="АКТИВ\\n{f["asset"]}" fillcolor="#16263F"]; '
            f'gate [label="{f["gate"]} {GATE_TITLE.get(f["gate"], "")}\\n{f["check"]}" fillcolor="#2A1316"]; '
            f'threat [label="УГРОЗА\\n{THREAT_MAP.get(f["gate"], "")}" fillcolor="#241C3D"]; '
            'asset -> gate [label="проверен"]; gate -> threat [label="закрывает"]; }')


def _parse_ci_log(log: str) -> dict:
    """Достать из лога шага JSON-отчёт гейта и строку ##[error]."""
    out = {"checks": [], "error": None, "raw": log, "gate": None}
    m = re.search(r"##\[error\](.*)", log)
    if m:
        out["error"] = m.group(1).strip()
    jstart = log.find("{")
    if jstart >= 0:
        depth, end = 0, -1
        for i in range(jstart, len(log)):
            if log[i] == "{":
                depth += 1
            elif log[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end > 0:
            try:
                data = json.loads(log[jstart:end])
                out["gate"] = data.get("gate")
                out["checks"] = [c for c in data.get("checks", []) if c.get("status") == "FAIL"]
            except Exception:  # noqa: BLE001
                pass
    return out


# ─────────────────────────────── ДАШБОРД ────────────────────────────────────
def page_dashboard():
    if _role() == "CEO":
        st.caption("Статус защищённости (read-only)")
        c = st.columns(4)
        c[0].metric("Моделей в проде", 1, "+1 за неделю")
        c[1].metric("Открытых инцидентов", 3, "+1", delta_color="inverse")
        c[2].metric("Gate PASS rate", "87%", "-3%", delta_color="inverse")
        c[3].metric("Запросов/мин", "~120", "+20%", delta_color="inverse")
        st.success("Основные системы защиты работают штатно")
        return

    st.caption("Кликни по карточке — перейдёшь к деталям.")
    models = get_models()
    findings = [_norm_finding(f) for f in _mock_or(
        _api_items("/api/v1/findings", "findings", mock=None), MOCK_FINDINGS)]
    events = [_norm_event(e) for e in _mock_or(
        _api_items("/api/v1/events", "events", mock=None), MOCK_EVENTS)]
    n_models = len(models)
    n_find = len([f for f in findings if f.get("status") == "open"])
    n_events = len(events)
    n_hitl = len([m for m in models if m.get("status") == "pending_hitl"])
    cards = [("Моделей в реестре", n_models, "info", "Реестр", {}),
             ("Открытых находок", n_find, "bad", "Находки", {"flt_find_status": ["open"]}),
             ("Events сегодня", n_events, "ok", "История", {}),
             ("Ожидают HITL", n_hitl, "warn", "Деплой / Approve", {})]
    cols = st.columns(4)
    for col, (label, val, kind, page, pend) in zip(cols, cards):
        with col:
            st.markdown(
                f"<div class='card {kind}'><div class='s'>{label}</div>"
                f"<div style='font-size:2rem;font-weight:800'>{val}</div></div>",
                unsafe_allow_html=True)
            if st.button("Открыть →", key=f"dash_{label}", use_container_width=True):
                _goto(page, **pend)

    st.markdown("### Мониторинг (G6 / G7)")
    a, b = st.columns(2)
    with a:
        st.markdown("**Дрейф (PSI)**")
        for col, psi in {"amount": 8.88, "age": 0.03}.items():
            k = "bad" if psi > 0.25 else "ok"
            tag = "DRIFT" if psi > 0.25 else "норма"
            st.markdown(f"{_pill(tag, k)} &nbsp; <span class='mono'>{col}</span> PSI = <b>{psi:.2f}</b>",
                        unsafe_allow_html=True)
        if st.button("К находкам дрейфа →", key="dash_drift"):
            _goto("Находки")
    with b:
        st.markdown("**Runtime (G7)**")
        st.markdown(f"{_pill('429', 'warn')} rate-limit: <b>87</b> &nbsp; "
                    f"{_pill('422', 'info')} validation: <b>12</b> &nbsp; "
                    f"{_pill('200', 'ok')} ok: <b>1141</b>", unsafe_allow_html=True)
        st.caption("7% запросов отбито rate-limit — возможная атака (#5/#6)")

    st.markdown("### Gate pass-rate (24ч)")
    cols = st.columns(5)
    for col, g in zip(cols, [("G1", 10, 12), ("G2", 7, 8), ("G3", 6, 8), ("G4", 5, 5), ("G5", 2, 3)]):
        rate = g[1] / g[2] * 100
        k = "ok" if rate >= 80 else "warn" if rate >= 60 else "bad"
        col.markdown(f"<div class='card {k}'><div class='s'>{g[0]} {GATE_TITLE[g[0]]}</div>"
                     f"<div style='font-size:1.4rem;font-weight:800'>{rate:.0f}%</div>"
                     f"<div class='s'>{g[1]}/{g[2]} PASS</div></div>", unsafe_allow_html=True)


# ──────────────────────── ВЕРИФИКАЦИЯ / РАННЕР ГЕЙТОВ ────────────────────────
def page_verify():
    tabs = st.tabs(["Верификация модели", "Раннер гейтов (MLSecOps)"])

    with tabs[0]:
        st.caption("Отправить модель на верификацию — прогон G5+G2+G3, затем обучение и G4.")
        with st.form("verify_form"):
            c1, c2 = st.columns(2)
            model = c1.selectbox("Модель", [m["name"] for m in get_models()])
            version = c1.text_input("Версия", "1.0.0")
            git_sha = c2.text_input("Git SHA", "a1b2c3d4")
            dataset = c2.text_input("Датасет@версия", "train_m1_clean@v1")
            reason = st.text_area("Причина (обязательно)", height=70)
            ok = st.form_submit_button("Запустить верификацию")
        if ok:
            if not reason.strip():
                st.error("Причина обязательна (Audit Trail)")
            else:
                p = st.progress(0, "Запуск")
                for i in range(4):
                    time.sleep(0.15)
                    p.progress((i + 1) / 4)
                p.empty()
                # API-first: бэкенд вернёт реальные gate_results; иначе — оптимистичный мок.
                resp = _api_post("/api/v1/verify",
                                 {"model_name": model, "version": version, "git_sha": git_sha,
                                  "dataset": dataset, "reason": reason},
                                 mock={"passed": True, "gate_results":
                                       [{"gate": g, "passed": True} for g in
                                        ["G5", "G2", "G3", "G4"]]})
                (st.success if resp.get("passed") else st.error)("Верификация завершена")
                for gr in resp.get("gate_results", []):
                    st.markdown(f"{_pill('PASS' if gr['passed'] else 'FAIL', 'ok' if gr['passed'] else 'bad')}"
                                f" &nbsp; {gr['gate']}", unsafe_allow_html=True)

    with tabs[1]:
        if _role() != "MLSecOps":
            st.warning("Раннер гейтов доступен только роли MLSecOps.")
            return
        st.caption("Выбери гейты и ресурсы — прогон матрицей, все результаты сразу.")
        c1, c2 = st.columns(2)
        gates = c1.multiselect("Гейты", ALL_GATES, default=["G1", "G2", "G4"],
                               format_func=lambda g: f"{g} {GATE_TITLE[g]}")
        res_ids = c2.multiselect("Ресурсы", [r["id"] for r in get_resources()],
                                 default=["train_m1_poisoned@v1", "PR#42 (code)",
                                          "credit_scoring@1.0.0"])
        fail_closed = st.checkbox("fail-closed (нет инструмента → блок)", value=True)
        if st.button("Прогнать выбранное", type="primary"):
            # API-first: бэкенд реально гоняет образы гейтов; иначе — детерминированный мок.
            resp = _api_post("/api/v1/scan",
                             {"gates": gates, "resources": res_ids, "fail_closed": fail_closed},
                             mock={"matrix": [{(g): _run_gate_mock(rid, g)[0] for g in gates}
                                              for rid in res_ids],
                                   "detail": {f"{rid}|{g}": _run_gate_mock(rid, g)
                                              for rid in res_ids for g in gates},
                                   "resources": res_ids})
            res_list = resp.get("resources", res_ids)
            mat = resp.get("matrix") or [{g: _run_gate_mock(rid, g)[0] for g in gates} for rid in res_ids]
            st.session_state["gate_run_result"] = [
                {"ресурс": rid, **mat[i]} for i, rid in enumerate(res_list)]
            st.session_state["gate_run_detail"] = {
                (rid, g): tuple(resp.get("detail", {}).get(f"{rid}|{g}", _run_gate_mock(rid, g)))
                for rid in res_list for g in gates}

        rows = st.session_state.get("gate_run_result")
        if rows:
            n_fail = sum(1 for r in rows for g in gates if r.get(g) == "FAIL")
            (st.error if n_fail else st.success)(
                f"Прогон завершён: ресурсов {len(rows)}, гейтов {len(gates)}, "
                f"провалов {n_fail}.")
            cfg = {g: st.column_config.TextColumn(f"{g}") for g in gates}
            ev = st.dataframe(rows, use_container_width=True, hide_index=True,
                              on_select="rerun", selection_mode="single-row",
                              key="gate_matrix", column_config=cfg)
            i = _sel(ev)
            if i is not None:
                rid = rows[i]["ресурс"]
                st.markdown(f"#### Детали: <span class='mono'>{rid}</span>", unsafe_allow_html=True)
                detail = st.session_state.get("gate_run_detail", {})
                for g in gates:
                    status, msg = detail.get((rid, g), ("SKIP", ""))
                    st.markdown(f"{_pill(status, _kind(status))} &nbsp; <b>{g} {GATE_TITLE[g]}</b> — "
                                f"<span class='muted'>{msg}</span>", unsafe_allow_html=True)


# ─────────────────────────────── РЕЕСТР ─────────────────────────────────────
def page_registry():
    st.caption("Интерактивная таблица: выбери модель — увидишь связи (lineage) и версии.")
    models = get_models()
    rows = []
    for m in models:
        rows.append({"модель": m["name"], "версия": m["version"], "tier": m["tier"],
                     "статус": m["status"].replace("_", " "), "owner": m["owner"].split("@")[0],
                     "датасет": m["dataset"], "CI": "да" if m["trained_in_ci"] else "нет",
                     "SHA": m["sha256"][:10]})
    ev = st.dataframe(rows, use_container_width=True, hide_index=True, on_select="rerun",
                      selection_mode="single-row", key="reg_table",
                      column_config={
                          "модель": st.column_config.TextColumn(width="medium"),
                          "SHA": st.column_config.TextColumn("SHA-256")})
    i = _sel(ev)
    if i is None:
        st.info("Выбери строку в таблице, чтобы открыть детали и граф связей.")
        return
    m = models[i]
    versions = get_versions(m["name"])
    st.markdown(f"## {m['name']} · v{m['version']}")
    st.markdown(f"{_tpill(m['tier'])} &nbsp; {_spill(m['status'])} &nbsp; "
                f"<span class='muted'>owner: {m['owner']}</span>", unsafe_allow_html=True)
    # Blast-radius: оценка радиуса поражения (downstream-потребители + критичность)
    consumers = {"credit_scoring": 3, "transaction_risk": 2, "text_classifier": 1}.get(m["name"], 0)
    radius = "высокий" if m["tier"] == "HIGH" else "средний" if m["tier"] == "MED" else "низкий"
    br = st.columns(3)
    br[0].metric("Blast-radius", radius)
    br[1].metric("Downstream-потребителей", consumers)
    br[2].metric("В проде", "да" if m["status"] in ("prod", "production") else "нет")
    g1, g2 = st.columns(2)
    with g1:
        st.markdown("**Связи (lineage)**")
        st.graphviz_chart(_lineage_dot(versions[0] if versions else m, m["name"]),
                          use_container_width=True)
    with g2:
        st.markdown("**Версии**")
        if versions:
            st.graphviz_chart(_versions_dot(versions, m["name"]), use_container_width=True)
    c1, c2 = st.columns(2)
    if c1.button("Открыть паспорт", use_container_width=True):
        _goto("Паспорт", passport_sel=m["name"])
    if c2.button("Открыть находки актива", use_container_width=True):
        _goto("Находки")


# ─────────────────────────────── ПАСПОРТ ────────────────────────────────────
def page_passport():
    names = [m["name"] for m in get_models()]
    c1, c2 = st.columns([2, 1])
    selected = c1.selectbox("Модель", names, key="passport_sel")
    versions = get_versions(selected)
    if not versions:
        st.info("Нет версий")
        return
    vi = c2.selectbox("Версия", range(len(versions)),
                      format_func=lambda i: f"v{versions[i]['version']} · {versions[i]['status']}")
    v = versions[vi]
    meta = MOCK_MODEL_META.get(selected, {})

    st.markdown(f"## {selected} · v{v['version']}")
    st.markdown(f"{_tpill(v['tier'])} &nbsp; {_spill(v['status'])} &nbsp; "
                f"<span class='muted'>{meta.get('purpose','')} · {meta.get('framework','')}</span>",
                unsafe_allow_html=True)

    t = st.tabs(["Обзор", "Данные", "Lineage", "Проверки", "Версии", "История"])

    with t[0]:
        c = st.columns(4)
        c[0].metric("Tier", v["tier"])
        c[1].metric("Статус", v["status"].replace("_", " "))
        c[2].metric("Автор", v["author"].split("@")[0])
        c[3].metric("Accuracy", f"{v['accuracy']:.3f}")
        st.markdown("**Ручной контроль (HITL)**")
        if v["approved_by"]:
            st.success(f"Одобрено: {v['approved_by']} · {v['approve_reason']}")
        elif v["tier"] == "HIGH":
            st.warning("Tier=HIGH — ожидает Approve MLSecOps (в прод без одобрения не уйдёт)")
        else:
            st.info("Tier ниже HIGH — авто-деплой")
        with st.expander("Гиперпараметры и метрики"):
            st.json({"params": meta.get("params", {}), "accuracy": v["accuracy"]})

    with t[1]:
        ds = get_dataset(v["dataset"])
        if ds:
            c = st.columns(3)
            c[0].metric("Строк", ds["rows"])
            c[1].metric("Источник", ds["source_type"])
            c[2].metric("Статус", ds["status"])
            st.markdown(f"- Колонки: {', '.join(ds['columns'])}")
            st.markdown(f"- Загрузил: {ds['uploaded_by']} · {ds['ts']}")
            st.markdown(f"- SHA-256: <span class='mono'>{ds['sha256']}</span>", unsafe_allow_html=True)
            g1 = ds.get("g1", {})
            k = "ok" if g1.get("passed") else "bad"
            st.markdown(f"{_pill('G1 ' + ('PASS' if g1.get('passed') else 'FAIL'), k)} &nbsp; "
                        + " · ".join(f"{a}: {b}" for a, b in g1.items() if a != "passed"),
                        unsafe_allow_html=True)
        else:
            st.markdown(f"Датасет: <span class='mono'>{v['dataset']}</span>", unsafe_allow_html=True)

    with t[2]:
        st.graphviz_chart(_lineage_dot(v, selected), use_container_width=True)
        st.caption("Связка данные → код → модель (требование G5 lineage).")

    with t[3]:
        cols = st.columns(len(v["gates"]))
        for col, (g, res) in zip(cols, v["gates"].items()):
            col.markdown(f"<div class='card {'ok' if res=='PASS' else 'bad'}'>"
                         f"<div class='s'>{g} {GATE_TITLE.get(g,'')}</div>"
                         f"<div style='font-weight:800;font-size:1.1rem'>{res}</div></div>",
                         unsafe_allow_html=True)

    with t[4]:
        st.graphviz_chart(_versions_dot(versions, selected), use_container_width=True)
        st.dataframe(
            [{"версия": x["version"], "статус": x["status"], "tier": x["tier"],
              "автор": x["author"].split("@")[0], "accuracy": x["accuracy"],
              "дата": x["ts"][:16], "изменение": x["change"]} for x in versions],
            use_container_width=True, hide_index=True)

    with t[5]:
        evs = [e for e in MOCK_EVENTS if selected in e.get("asset", "")]
        if evs:
            for e in evs[-8:]:
                st.markdown(f"<div class='card {_kind(e['result'])}'><div class='h'>{e['type']} "
                            f"{_spill(e['result'])}</div><div class='s'>{e['ts'][:16]} · "
                            f"{e['actor']} · {e['detail']}</div></div>", unsafe_allow_html=True)
        else:
            st.caption("Событий нет")


# ─────────────────────────────── ИСТОРИЯ ────────────────────────────────────
def page_events():
    c1, c2 = st.columns([3, 1])
    f_asset = c1.text_input("Фильтр по активу", key="flt_ev_asset")
    if c2.button("Проверить цепочку хешей", use_container_width=True):
        r = _api_get("/api/v1/events/verify_chain",
                     mock={"ok": True, "verified": 7, "broken_at": None})
        (st.success if r.get("ok") else st.error)(
            f"Цепочка валидна ({r.get('verified')} событий)" if r.get("ok")
            else f"Разрыв на позиции {r.get('broken_at')}")

    events = [_norm_event(e) for e in _mock_or(
        _api_items("/api/v1/events", "events", mock=None), MOCK_EVENTS)]
    if f_asset:
        events = [e for e in events if f_asset.lower() in e.get("asset", "").lower()]

    icon = {"ok": "●", "blocked": "■", "error": "▲", "pending": "◆"}
    for e in reversed(events):
        k = _kind(e["result"])
        st.markdown(
            f"<div class='card {k}'><div class='h'>"
            f"<span style='color:var(--{'ok' if k=='ok' else 'bad' if k=='bad' else 'warn'})'>"
            f"{icon.get(e['result'], '●')}</span> {e['type']} &nbsp; {_spill(e['result'])}</div>"
            f"<div class='s'><span class='mono'>{e['ts'][:19]}</span> · {e['actor']} · "
            f"актив <span class='mono'>{e['asset']}</span></div>"
            f"<div style='margin-top:.25rem'>{e['detail']}</div></div>",
            unsafe_allow_html=True)


# ─────────────────────────────── НАХОДКИ ────────────────────────────────────
def page_findings():
    c1, c2, c3 = st.columns(3)
    f_gate = c1.multiselect("Гейт", ["G1", "G2", "G3", "G4", "G5", "G6", "G7"], key="flt_find_gate")
    f_sev = c2.multiselect("Severity", ["critical", "high", "medium", "low"], key="flt_find_sev")
    f_status = c3.multiselect("Статус", ["open", "closed", "fp"], key="flt_find_status")

    data = [_norm_finding(f) for f in _mock_or(
        _api_items("/api/v1/findings", "findings", mock=None), MOCK_FINDINGS)]
    if f_gate:
        data = [f for f in data if f["gate"] in f_gate]
    if f_sev:
        data = [f for f in data if f["severity"] in f_sev]
    if f_status:
        data = [f for f in data if f["status"] in f_status]
    if not data:
        st.info("Находок нет")
        return

    rows = [{"sev": f["severity"].upper(), "гейт": f["gate"], "проверка": f["check"],
             "статус": f["status"].upper(), "актив": f["asset"], "когда": f["ts"][11:19]}
            for f in data]
    ev = st.dataframe(rows, use_container_width=True, hide_index=True, on_select="rerun",
                      selection_mode="single-row", key="find_table",
                      column_config={"sev": st.column_config.TextColumn("SEV", width="small"),
                                     "актив": st.column_config.TextColumn(width="medium")})
    i = _sel(ev)
    if i is None:
        st.info("Выбери находку в таблице — увидишь причину, граф связей и действия.")
        return
    f = data[i]
    st.markdown(f"## [{f['gate']}] {f['check']}")
    st.markdown(f"{_sevpill(f['severity'])} &nbsp; {_spill(f['status'])} &nbsp; "
                f"актив <span class='mono'>{f['asset']}</span>", unsafe_allow_html=True)
    st.markdown(f"**{f['detail']}**")
    if f.get("fp_reason"):
        st.warning(f"False Positive: {f['fp_reason']}")
    a, b = st.columns([1, 1])
    with a:
        st.markdown("**Связи**")
        st.graphviz_chart(_finding_dot(f), use_container_width=True)
    with b:
        st.markdown("**Причина (evidence)**")
        st.json(f["evidence"])
        st.caption(f"Угрозы: {THREAT_MAP.get(f['gate'], '')}")
    if _role() == "MLSecOps" and f["status"] == "open":
        x, y, z = st.columns(3)
        reason = x.text_input("Причина FP", key=f"fpr_{f['id']}")
        if x.button("Отметить FP", key=f"fp_{f['id']}"):
            if reason:
                _api_post(f"/api/v1/findings/{f['id']}/fp", {"reason": reason}, mock={"ok": True})
                st.success("Отмечено FP")
        if y.button("Перезапустить", key=f"re_{f['id']}"):
            _api_post(f"/api/v1/findings/{f['id']}/rerun", {}, mock={"ok": True})
            st.info("В очереди")
        if z.button("Закрыть", key=f"cl_{f['id']}"):
            _api_post(f"/api/v1/findings/{f['id']}/close", {}, mock={"ok": True})
            st.success("Закрыто")


# ─────────────────────────────── CI/CD ЛОГИ ─────────────────────────────────
def page_cicd():
    if _role() != "MLSecOps":
        st.warning("Логи CI/CD доступны только роли MLSecOps.")
        return
    runs = _mock_or(_api_items("/api/v1/cicd/runs", "runs", mock=None), MOCK_CICD_RUNS)
    c1, c2 = st.columns([3, 1])
    only_failed = c2.checkbox("Только упавшие")
    shown = [r for r in runs if (not only_failed or r["status"] == "failed")]
    if not shown:
        st.info("Прогонов нет")
        return
    labels = [f"{r['status'].upper()} · {r['id']} · {r['workflow']} · {r['trigger']}" for r in shown]
    idx = c1.selectbox("Прогон", range(len(shown)), format_func=lambda i: labels[i])
    run = shown[idx]

    cc = st.columns(4)
    cc[0].metric("Workflow", run["workflow"])
    cc[1].metric("Статус", run["status"])
    cc[2].metric("Коммит", run["commit"])
    cc[3].metric("Длит-ть", run["duration"])
    st.markdown(f"<span class='muted'>{run['trigger']} · ветка <span class='mono'>{run['branch']}</span> "
                f"· {run['actor']}</span>", unsafe_allow_html=True)

    st.markdown("### Этапы пайплайна")
    for j in run["jobs"]:
        k = _kind(j["status"])
        st.markdown(f"<div class='stage {k}'><span class='dot' style='background:var(--"
                    f"{'ok' if k=='ok' else 'bad' if k=='bad' else 'muted'})'></span>"
                    f"<b>{j['name']}</b> &nbsp; {_spill(j['status'])} "
                    f"<span class='muted' style='margin-left:auto'>{j.get('duration','')}</span></div>",
                    unsafe_allow_html=True)
        if j["status"] != "failed":
            continue
        # Раскрываем упавшую джобу: показываем шаги и где именно сломалось
        for s in j["steps"]:
            sk = _kind(s["status"])
            st.markdown(f"&nbsp;&nbsp;&nbsp;{_pill(s['status'].upper(), sk)} &nbsp; {s['name']}"
                        + (f" &nbsp;<span class='muted'>exit={s['exit']}</span>"
                           if s.get('exit') is not None else ""), unsafe_allow_html=True)
            if s["status"] != "failed":
                continue
            parsed = _parse_ci_log(s.get("log", ""))
            if parsed["error"]:
                st.markdown(f"<div class='errbox'>✖ {parsed['error']}</div>", unsafe_allow_html=True)
            if parsed["checks"]:
                st.markdown(f"**Гейт {parsed['gate']} — провалившиеся проверки:**")
                for c in parsed["checks"]:
                    st.markdown(
                        f"<div class='card bad'><div class='h'>{_sevpill(c.get('severity','high'))} "
                        f"&nbsp; {c.get('check')}</div><div class='s'>{c.get('detail','')}</div>"
                        f"<div class='mono' style='margin-top:.3rem;color:#FCA5A5'>"
                        f"{json.dumps(c.get('evidence', {}), ensure_ascii=False)}</div></div>",
                        unsafe_allow_html=True)
            with st.expander("Полный сырой лог шага"):
                st.code(s.get("log", ""), language="bash")
            st.download_button("Скачать лог", data=s.get("log", ""),
                               file_name=f"{run['id']}_{j['name']}.log", key=f"dl_{run['id']}_{j['name']}")


# ─────────────────────────────── ИНСТРУМЕНТЫ ────────────────────────────────
def page_scanners():
    st.caption("Инструмент → гейт → угроза, с историей сканирований.")
    tools = {
        "gitleaks": ("G2", "high", "#10 секреты"), "bandit": ("G2", "high", "#8 SAST"),
        "pip-audit": ("G2", "critical", "#8 CVE"), "trivy": ("G2", "critical", "#8 CVE образа"),
        "modelscan": ("G4", "critical", "#3 pickle/RCE"), "cosign": ("G4", "high", "#26 подпись"),
        "pandas": ("G1", "high", "#1/#2 данные"), "redis": ("G7", "high", "#5/#6 rate-limit"),
        "evidently": ("G6", "medium", "#14 дрейф"),
    }
    rows = [{"инструмент": t, "гейт": g, "severity": sev.upper(), "угроза": thr,
             "прогонов": 42, "находок": len([f for f in MOCK_FINDINGS if f["gate"] == g])}
            for t, (g, sev, thr) in tools.items()]
    st.dataframe(rows, use_container_width=True, hide_index=True)


# ─────────────────────────────── ДЕПЛОЙ ─────────────────────────────────────
def page_deploy():
    st.caption("Деплой в прод. Tier=HIGH требует ручного Approve MLSecOps (HITL).")
    models = [m for m in get_models() if m["status"] in ("candidate", "approved", "pending_hitl", "registered")]
    if not models:
        st.info("Нет моделей, ожидающих деплоя")
        return
    for m in models:
        with st.expander(f"{m['name']} v{m['version']} · {m['tier']} · {m['status'].replace('_',' ')}"):
            st.markdown(f"{_tpill(m['tier'])} &nbsp; {_spill(m['status'])}", unsafe_allow_html=True)
            st.markdown(f"owner: {m['owner']} · датасет <span class='mono'>{m['dataset']}</span> · "
                        f"SHA <span class='mono'>{m['sha256']}</span>", unsafe_allow_html=True)
            if m["tier"] == "HIGH" and m["status"] == "pending_hitl":
                st.error("Ожидает HITL Approve — deploy.yml заблокирован")
            if _role() == "MLSecOps":
                reason = st.text_area("Причина Approve (обязательно)", key=f"apr_{m['name']}", height=70)
                cols = st.columns(3)
                if cols[0].button("Approve Deploy", key=f"ap_{m['name']}"):
                    if not reason.strip():
                        st.error("Причина обязательна")
                    else:
                        _api_post(f"/api/v1/deploy/{m['name']}/{m['version']}/approve",
                                  {"reason": reason}, mock={"ok": True})
                        st.success("Одобрено, deploy.yml запущен")
                if cols[1].button("Откат", key=f"rb_{m['name']}"):
                    st.info("Откат инициирован")
                if cols[2].button("Retire", key=f"rt_{m['name']}"):
                    st.warning("Переведено в retire")
            else:
                if st.button("Попытаться Approve (как DS)", key=f"ds_{m['name']}"):
                    st.error("403 Forbidden — у DS нет права Approve (Audit Trail: access_denied)")


# ─────────────────────────────── ПОЛЬЗОВАТЕЛИ ──────────────────────────────
def page_users():
    if _role() != "MLSecOps":
        st.warning("Управление пользователями доступно только MLSecOps.")
        return
    st.caption("Пользователи по логину и правам.")
    users = get_users()
    rows = [{"логин": u["login"], "email": u["email"], "роль": u["role"],
             "статус": u["status"], "последний вход": u["last"],
             "прав": len(u["perms"])} for u in users]
    ev = st.dataframe(rows, use_container_width=True, hide_index=True, on_select="rerun",
                      selection_mode="single-row", key="users_table",
                      column_config={"роль": st.column_config.TextColumn(width="small")})
    i = _sel(ev)
    if i is not None:
        u = users[i]
        st.markdown(f"## {u['login']} &nbsp; {_pill(u['role'], 'info')}", unsafe_allow_html=True)
        st.markdown(f"<span class='muted'>{u['email']} · {u['status']} · вход {u['last']}</span>",
                    unsafe_allow_html=True)
        st.markdown("**Права:**")
        st.markdown(" ".join(_pill(p, "muted") for p in u["perms"]), unsafe_allow_html=True)
    st.divider()
    with st.expander("Добавить пользователя / назначить роль"):
        with st.form("add_user"):
            email = st.text_input("Email")
            role = st.selectbox("Роль", ["DS", "DE", "MLSecOps", "Product", "CEO"])
            if st.form_submit_button("Создать"):
                _api_post("/api/v1/admin/users", {"email": email, "role": role}, mock={"ok": True})
                st.success(f"Пользователь {email} добавлен ({role})")


# ─────────────────────────── КАРТА ПОКРЫТИЯ (GRC) ──────────────────────────
def page_coverage():
    if CTRL is None:
        st.info("Каталог контролей недоступен (src/common/controls.py).")
        return
    cov = CTRL.coverage()
    st.caption("Замкнутый контур GRC: каждая угроза → контроль → тест. Статусы: live / accepted / planned.")
    c = st.columns(4)
    c[0].metric("Покрытие", f"{cov['closed']}/{cov['total']}", f"{cov['pct']}%")
    c[1].metric("Live (реализовано+тест)", cov["live"])
    c[2].metric("Accepted (RiskAcceptance)", cov["accepted"])
    c[3].metric("Planned (инфра/A)", cov["planned"])
    st.progress(cov["pct"] / 100)

    if _role() == "CEO":
        st.success(f"Контролей закрыто {cov['closed']}/{cov['total']} ({cov['pct']}%). "
                   "Остаточные риски приняты через RiskAcceptance.")

    f_layer = st.multiselect("Слой", sorted({x["layer"] for x in CTRL.CONTROLS}), key="cov_layer")
    rows = []
    for ctl in CTRL.CONTROLS:
        if f_layer and ctl["layer"] not in f_layer:
            continue
        rows.append({"ID": ctl["id"], "контроль": ctl["title"], "угрозы": " ".join(ctl["threats"]),
                     "гейт/слой": f"{ctl['gate']} · {ctl['layer']}",
                     "статус": CTRL.effective_status(ctl).upper(),
                     "тестов": len(ctl["tests"]),
                     "ATLAS": ctl["std"].get("ATLAS", "—"), "OWASP": ctl["std"].get("OWASP", "—"),
                     "NIST": ctl["std"].get("NIST", "—"), "ФСТЭК": ctl["std"].get("FSTEC", "—")})
    ev = st.dataframe(rows, use_container_width=True, hide_index=True, on_select="rerun",
                      selection_mode="single-row", key="cov_table",
                      column_config={"ID": st.column_config.TextColumn(width="small"),
                                     "тестов": st.column_config.NumberColumn("тесты")})
    i = _sel(ev)
    if i is None:
        st.info("Выбери контроль — увидишь тесты, стандарты и RiskAcceptance.")
        return
    ctl = [c for c in CTRL.CONTROLS if (not f_layer or c["layer"] in f_layer)][i]
    eff = CTRL.effective_status(ctl)
    st.markdown(f"## {ctl['id']} — {ctl['title']}")
    st.markdown(f"{_pill(eff.upper(), _kind(eff))} &nbsp; гейт <b>{ctl['gate']}</b> · слой {ctl['layer']} "
                f"&nbsp; угрозы {' '.join(ctl['threats'])}", unsafe_allow_html=True)
    st.markdown("**Тесты, покрывающие контроль:**")
    for t in ctl["tests"]:
        st.markdown(f"- <span class='mono'>{t}</span>", unsafe_allow_html=True)
    st.markdown("**Стандарты:** " + " · ".join(
        f"{k}: {v}" for k, v in ctl["std"].items() if v and v != "—"))
    if eff != "live" and _role() == "MLSecOps":
        st.markdown("**RiskAcceptance (GRC exception):**")
        reason = st.text_input("Обоснование принятия остаточного риска", key=f"ra_{ctl['id']}")
        if st.button("Принять остаточный риск", key=f"rab_{ctl['id']}"):
            if reason.strip():
                # API-first: бэкенд персистит решение в БД (GRC); локально — для немедленного UI.
                _api_post(f"/api/v1/controls/{ctl['id']}/accept",
                          {"reason": reason, "by": "mlsecops@example.com"}, mock={"ok": True})
                CTRL.set_accepted(ctl["id"], "mlsecops@example.com", reason)
                st.success(f"{ctl['id']} → ACCEPTED. Записано в журнал (GRC).")
                _rerun()
            else:
                st.error("Обоснование обязательно")


# ─────────────────────────── КОНТУР (LIVE) ─────────────────────────────────
def page_contour():
    st.caption("Сквозной контур: пайплайн жизненного цикла + инфраструктура + рантайм-защиты.")
    cov = CTRL.coverage() if CTRL else {"closed": 0, "total": 0, "pct": 0}
    c = st.columns(4)
    c[0].metric("Состояние", "ТРЕВОГА" if any(f["status"] == "open" for f in MOCK_FINDINGS) else "OK")
    c[1].metric("Открытых сработок", len([f for f in MOCK_FINDINGS if f["status"] == "open"]))
    c[2].metric("Контролей в контуре", cov["total"])
    c[3].metric("Покрытие", f"{cov['pct']}%")

    st.markdown("### Конвейер жизненного цикла")
    stages = [("01", "Приём данных", "ok", 1), ("GATE", "Гейт данных", "bad", 10),
              ("03", "Обучение", "ok", 1), ("04", "Упаковка / Реестр", "ok", 1),
              ("GATE", "Гейт артефакта", "warn", 2), ("GATE", "Валидация / HITL", "ok", 2)]
    cols = st.columns(len(stages))
    for col, (tag, name, k, ctrls) in zip(cols, stages):
        gate = "GATE · fail-closed" if tag == "GATE" else f"шаг {tag}"
        col.markdown(f"<div class='card {k}'><div class='s'>{gate}</div>"
                     f"<div class='h'>{name}</div>"
                     f"<div class='s'>{ctrls} контр. · ARMED</div></div>", unsafe_allow_html=True)
    st.caption("ARMED — превентивный контроль работает молча · GATE — fail-closed гейт · "
               "красный — есть открытые сработки.")

    st.markdown("### Инфраструктура контура")
    infra = [("Control-plane (FastAPI)", "ok"), ("MLflow", "ok"), ("MinIO", "ok"),
             ("Postgres · Audit", "ok"), ("Redis", "ok"), ("CI runner", "ok")]
    cols = st.columns(3)
    for i, (name, k) in enumerate(infra):
        cols[i % 3].markdown(f"<div class='card {k}'><div class='s'>сервис</div>"
                             f"<div class='h'>{name}</div></div>", unsafe_allow_html=True)

    st.markdown("### Рантайм-защиты периметра")
    rt = [("RT-01", "Extraction-детект", "берст одного клиента → 429 + Finding"),
          ("DOS-01", "Load-shedding", "распределённый флуд → 503, ядро живо"),
          ("DOW-01", "Стоимостная квота", "бюджет тенанта исчерпан → 429"),
          ("RT-05", "Валидация входа", "malformed → 422, сервис не падает"),
          ("RT-02", "OOD / adversarial", "вход-выброс → suspect + Finding"),
          ("RT-03", "Output-reduction", "отдаём класс, не вероятности (анти-инверсия)"),
          ("DLP-01", "DLP логов", "ПДн в логах маскируются"),
          ("MON-01", "Дрейф данных", "сдвиг распределения окна → Finding")]
    cols = st.columns(2)
    for i, (cid, name, desc) in enumerate(rt):
        cols[i % 2].markdown(
            f"<div class='card ok'><div class='h'>{_pill(cid, 'info')} &nbsp; {name}</div>"
            f"<div class='s'>{desc}</div></div>", unsafe_allow_html=True)


# ─────────────────────────────── NAV / RENDER ──────────────────────────────
PAGES = {
    "Дашборд": page_dashboard,
    "Контур": page_contour,
    "Карта покрытия": page_coverage,
    "Верификация": page_verify,
    "Реестр": page_registry,
    "Паспорт": page_passport,
    "История": page_events,
    "Находки": page_findings,
    "CI/CD логи": page_cicd,
    "Инструменты": page_scanners,
    "Деплой / Approve": page_deploy,
    "Пользователи": page_users,
}


def render():
    st.set_page_config(page_title="MLSecOps Platform", layout="wide", page_icon="◆")
    inject_css()

    nav = st.session_state.pop("_nav_request", None)
    if nav in PAGES:
        st.session_state["active_page"] = nav
    for k, val in st.session_state.pop("_pending_state", {}).items():
        st.session_state[k] = val

    st.sidebar.markdown(
        "<div style='font-size:1.2rem;font-weight:800;color:#fff;letter-spacing:-.02em'>"
        "&#9670; MLSecOps</div><div style='color:#6B7280;font-size:.76rem;margin-bottom:.6rem'>"
        "Security Platform</div>", unsafe_allow_html=True)

    _sidebar_auth()
    st.sidebar.markdown(_pill(_role(), "info"), unsafe_allow_html=True)
    st.sidebar.divider()

    page = st.sidebar.radio("Разделы", list(PAGES.keys()), key="active_page",
                            label_visibility="collapsed")
    st.markdown(f"<h1>{page}</h1>", unsafe_allow_html=True)
    try:
        PAGES[page]()
    except Exception as e:  # noqa: BLE001
        st.error(f"Ошибка раздела: {e}")


if _HAS_STREAMLIT:
    render()
