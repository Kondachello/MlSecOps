"""Streamlit UI — MLSecOps Platform (объединённый, артефакто-центричный фронтенд).

Слитый UI: тёмная тема второго разработчика + рабочий бэкенд A (аутентификация,
приватность/шаринг артефактов MLflow, цепочка гейтов, реестр по зонам, админка).

Модель: АРТЕФАКТ (MLflow run = сессия data+код+модель) — центр всего, «Реестр» — его хаб.
- Реестр раскладывает артефакты по зонам (черновик/не прошли/ок/выкатка/прод) с фильтрами.
- «Открыть артефакт» → страница артефакта: паспорт + цепочка гейтов (логи/перезапуск гейта),
  перепройти security check, и (для MLSecOps) выкатить/одобрить/в прод/откатить.

Принципы:
- Вход — ТОЛЬКО реальный логин (JWT). Роли — из /auth/me (RBAC), обновляются с TTL-кэшем.
- Все запросы к Gatekeeper идут с Authorization: Bearer <token>.
- Данные — из реального API. Где бэкенд ЗАГЛУШКА — честный плейсхолдер, без фейк-данных.
- GET-запросы кэшируются (TTL≈4с) → быстрый отклик; после изменений кэш инвалидируется.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys

try:
    import streamlit as st
    import requests
    _HAS_STREAMLIT = True
except Exception:  # graceful для py_compile без установленных пакетов
    _HAS_STREAMLIT = False
    st = None  # type: ignore
    requests = None  # type: ignore

# Каталог контролей (угроза→контроль→тест→покрытие). Pure-data модуль без зависимостей.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from src.common import controls as CTRL
except Exception:  # noqa: BLE001
    CTRL = None

API = os.getenv("GATEKEEPER_URL", "http://localhost:8200")
APP_DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"
MLFLOW_UI_URL = os.getenv("MLFLOW_UI_URL", "http://localhost:5000")

ALL_ROLES = ["DS", "DE", "MLSecOps", "Product", "CEO"]
ROLE_LEVEL = {"DS": 1, "DE": 1, "Product": 2, "MLSecOps": 3, "CEO": 4}

ALL_GATES = ["G1", "G2", "G3", "G4", "G5"]
GATE_TITLE = {"G1": "Data", "G2": "Code", "G3": "Supply", "G4": "Model", "G5": "Registry"}

# Зоны реестра (по check_status + stage артефакта; вычисляет бэкенд в поле "zone").
ZONE_ORDER = ["prod", "deploying", "ok", "failed", "draft", "previous", "retired"]
ZONE_LABEL = {
    "draft": "🗂 Черновики (не проверены)", "failed": "⛔ Не прошли проверку",
    "ok": "✅ Прошли проверку", "deploying": "🚀 Выкатка / на согласовании",
    "prod": "🟢 В проде", "previous": "⏮ Предыдущие (откат)", "retired": "🗄 Выведены",
}
ZONE_KIND = {"draft": "muted", "failed": "bad", "ok": "ok", "deploying": "warn",
             "prod": "ok", "previous": "muted", "retired": "muted"}


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
section[data-testid="stSidebar"]{background:linear-gradient(180deg,#0C1020,#0A0D18);border-right:1px solid var(--line);}
section[data-testid="stSidebar"] *{color:#C4CBDC;}
section[data-testid="stSidebar"] [role="radiogroup"] label{padding:.4rem .55rem;border-radius:10px;margin:1px 0;
   border:1px solid transparent;transition:.15s;}
section[data-testid="stSidebar"] [role="radiogroup"] label:hover{background:#141A2E;border-color:var(--line);}
[data-testid="stMetric"]{background:linear-gradient(180deg,var(--panel),var(--panel2));
  border:1px solid var(--line);border-radius:14px;padding:.8rem 1rem;
  box-shadow:0 8px 24px rgba(0,0,0,.25);}
[data-testid="stMetricValue"]{font-weight:800;color:var(--ink);}
[data-testid="stMetricLabel"]{color:var(--muted);}
[data-testid="stExpander"]{background:var(--panel);border:1px solid var(--line);border-radius:14px;}
[data-testid="stExpander"] summary{font-weight:600;}
.stButton>button{background:var(--panel2);border:1px solid var(--line);color:var(--ink);
  border-radius:11px;font-weight:600;padding:.45rem 1rem;transition:.15s;}
.stButton>button:hover{border-color:var(--accent);color:#fff;box-shadow:0 0 0 3px rgba(99,102,241,.15);}
[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:14px;overflow:hidden;}
.pill{display:inline-block;padding:.14rem .6rem;border-radius:999px;font-size:.73rem;
  font-weight:700;letter-spacing:.03em;border:1px solid transparent;}
.pill-ok{background:var(--okbg);color:var(--ok);border-color:#14533c;}
.pill-bad{background:var(--badbg);color:var(--bad);border-color:#5b2026;}
.pill-warn{background:var(--warnbg);color:var(--warn);border-color:#564216;}
.pill-info{background:var(--infobg);color:var(--info);border-color:#2c2f63;}
.pill-muted{background:#1A2034;color:var(--muted);border-color:var(--line);}
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--muted);
  border-radius:12px;padding:.7rem .9rem;margin:.45rem 0;box-shadow:0 6px 18px rgba(0,0,0,.18);}
.card.ok{border-left-color:var(--ok);} .card.bad{border-left-color:var(--bad);}
.card.warn{border-left-color:var(--warn);} .card.info{border-left-color:var(--accent2);}
.card .h{font-weight:700;font-size:.92rem;}
.card .s{color:var(--muted);font-size:.8rem;}
/* gate chain */
.chain{display:flex;flex-wrap:wrap;gap:.4rem;align-items:center;margin:.4rem 0 .2rem;}
.gnode{display:flex;flex-direction:column;align-items:center;min-width:74px;padding:.45rem .5rem;
  border:1px solid var(--line);border-radius:12px;background:var(--panel);}
.gnode.ok{border-color:#14533c;} .gnode.bad{border-color:#5b2026;} .gnode.muted{opacity:.65;}
.gnode .gid{font-weight:800;font-size:.9rem;} .gnode .gn{font-size:.7rem;color:var(--muted);}
.garrow{color:var(--muted);font-size:1.1rem;}
.errbox{background:var(--badbg);border:1px solid #5b2026;border-radius:10px;padding:.55rem .8rem;
  color:#FCA5A5;font-family:'JetBrains Mono',monospace;font-size:.8rem;}
hr{border-color:var(--line);}
</style>
"""


def inject_css():
    st.markdown(_CSS, unsafe_allow_html=True)


# ─────────────────────────── HTTP-слой (Bearer-токен) ───────────────────────
def _auth_headers() -> dict:
    tok = st.session_state.get("token")
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def api_get(path: str, **kw):
    return requests.get(f"{API}{path}", headers=_auth_headers(), **kw)


def api_post(path: str, json=None, headers=None, files=None, **kw):
    h = _auth_headers()
    if headers:
        h.update(headers)
    return requests.post(f"{API}{path}", json=json, files=files, headers=h, **kw)


if _HAS_STREAMLIT:
    @st.cache_data(ttl=4, show_spinner=False)
    def _cached_get(path: str, token: str, timeout: int = 8):
        """Кэшированный GET (ключ = путь+токен), TTL≈4с — снимает лаг от ререндеров Streamlit."""
        try:
            hdr = {"Authorization": f"Bearer {token}"} if token else {}
            r = requests.get(f"{API}{path}", headers=hdr, timeout=timeout)
            if r.ok:
                return r.json()
        except Exception:  # noqa: BLE001
            return None
        return None

    def _invalidate():
        """Сбросить кэш GET-ов (после изменяющих действий — чтобы реестр/история обновились)."""
        try:
            _cached_get.clear()
        except Exception:  # noqa: BLE001
            pass
else:  # pragma: no cover — для py_compile
    def _cached_get(path, token, timeout=8):
        return None

    def _invalidate():
        pass


def get_json(path: str, default=None, timeout: int = 8):
    """Кэшированный GET → JSON или default. БЕЗ mock-фолбэка (честные заглушки в UI)."""
    data = _cached_get(path, st.session_state.get("token", ""), timeout)
    return data if data is not None else default


def get_json_fresh(path: str, default=None, timeout: int = 8):
    """Некэшированный GET — для динамичных списков (реестр/артефакты): ВСЕГДА свежие данные.

    Реестр и список артефактов меняются от внешних экспериментов (ноутбук), поэтому их не кэшируем —
    иначе на странице видны устаревшие данные до ручного «Обновить».
    """
    try:
        r = api_get(path, timeout=timeout)
        if r.ok:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return default


def _not_implemented(what: str, endpoint: str | None = None, note: str | None = None):
    """Честная заглушка: раздел есть в UI, но бэкенд-ручка ещё не реализована."""
    st.info(f"🚧 **{what}** — UI готов, бэкенд-ручка ещё не реализована (без фейк-данных).")
    if endpoint:
        st.caption(f"Ожидаемый эндпоинт: `{endpoint}`.")
    if note:
        st.caption(note)


# ─────────────────────────── мелкие хелперы ─────────────────────────────────
def _rerun():
    fn = getattr(st, "rerun", None) or getattr(st, "experimental_rerun", None)
    if fn:
        fn()


def _goto(page, **pending):
    st.session_state["_nav_request"] = page
    if pending:
        st.session_state["_pending_state"] = pending
    _rerun()


def _open_artifact(run_id: str):
    """Открыть страницу артефакта (в разделе «Реестр»)."""
    _goto("Реестр", _artifact_open=run_id)


def _roles() -> list[str]:
    return st.session_state.get("roles", []) or []


def _has(*roles) -> bool:
    return bool(set(roles) & set(_roles()))


def _clearance() -> int:
    return max((ROLE_LEVEL.get(r, 0) for r in _roles()), default=0)


def _when(ts) -> str:
    if not ts:
        return "—"
    try:
        return _dt.datetime.fromtimestamp(int(ts) / 1000).strftime("%Y-%m-%d %H:%M")
    except Exception:  # noqa: BLE001
        return str(ts)[:19]


_KIND = {"ok": "ok", "available": "ok", "prod": "ok", "production": "ok", "closed": "ok",
         "pass": "ok", "success": "ok", "approved": "ok", "passed": "ok",
         "blocked": "bad", "fail": "bad", "failed": "bad", "open": "bad", "error": "bad",
         "pending": "warn", "pending_approve": "warn", "pending_hitl": "warn",
         "running": "warn", "queued": "warn", "deploying": "warn",
         "candidate": "info", "previous": "muted", "retired": "muted", "fp": "muted",
         "false_positive": "muted", "skip": "muted", "skipped": "muted", "none": "muted",
         "draft": "muted", "private": "muted", "shared": "ok"}


def _kind(s):
    return _KIND.get(str(s).lower(), "muted")


def _pill(text, kind="muted"):
    return f"<span class='pill pill-{kind}'>{text}</span>"


def _spill(status):
    return _pill(str(status).replace("_", " ").upper(), _kind(status))


def _tpill(tier):
    if not tier:
        return _pill("TIER —", "muted")
    k = {"HIGH": "bad", "MED": "warn", "LOW": "ok"}.get(str(tier).upper(), "muted")
    return _pill(f"TIER {str(tier).upper()}", k)


def _sevpill(sev):
    k = {"critical": "bad", "high": "bad", "medium": "warn", "low": "info"}.get(str(sev).lower(), "muted")
    return _pill(str(sev).upper(), k)


def _sel(event):
    try:
        rows = event.selection["rows"]
    except Exception:  # noqa: BLE001
        rows = getattr(getattr(event, "selection", None), "rows", []) or []
    return rows[0] if rows else None


def _share_badge(a: dict) -> str:
    if a.get("share_status") != "shared":
        return "🔒 приватный"
    if a.get("share_roles"):
        return f"🔗 роли: {', '.join(a['share_roles'])}"
    return f"🔗 клиренс ≥ {a.get('share_level')}"


def _label(a: dict) -> str:
    return a.get("run_name") or a.get("session_name") or (a.get("run_id", "")[:8])


# ──────────────────────────── ЭКРАН ВХОДА ───────────────────────────────────
def render_login():
    inject_css()
    st.markdown("<h1>🛡️ MLSecOps Platform</h1>", unsafe_allow_html=True)
    st.caption(f"Backend: {API} · вход только по реальному аккаунту (JWT + RBAC)")

    tab_login, tab_reg = st.tabs(["🔑 Вход", "📝 Регистрация"])

    with tab_login:
        with st.form("login_form"):
            u = st.text_input("Логин")
            p = st.text_input("Пароль", type="password")
            submitted = st.form_submit_button("Войти")
        if submitted:
            try:
                r = api_post("/api/v1/auth/login", json={"username": u, "password": p}, timeout=10)
            except Exception as e:  # noqa: BLE001
                st.error(f"Бэкенд недоступен ({API}): {e}")
                return
            if r.status_code == 200:
                data = r.json()
                st.session_state["token"] = data["access_token"]
                st.session_state["username"] = u
                st.session_state["roles"] = data.get("roles", [])
                _invalidate()
                _rerun()
            else:
                st.error(f"Не удалось войти: {r.json().get('detail', r.text)}")

    with tab_reg:
        st.info("После регистрации роль выдаёт MLSecOps — сразу привилегированных действий не будет.")
        with st.form("reg_form"):
            u = st.text_input("Логин", key="reg_u")
            e = st.text_input("Email (необязательно)", key="reg_e")
            p = st.text_input("Пароль", type="password", key="reg_p")
            submitted = st.form_submit_button("Зарегистрироваться")
        if submitted:
            try:
                r = api_post("/api/v1/auth/register",
                             json={"username": u, "password": p, "email": e or None}, timeout=10)
            except Exception as ex:  # noqa: BLE001
                st.error(f"Бэкенд недоступен ({API}): {ex}")
                return
            if r.status_code == 200:
                st.success(f"Аккаунт '{u}' создан. Войдите на вкладке «Вход». "
                           f"Роль вам назначит MLSecOps.")
            else:
                st.error(f"Ошибка регистрации: {r.json().get('detail', r.text)}")


# ─────────────────────────────── ДАШБОРД ────────────────────────────────────
def page_dashboard():
    reg = get_json("/api/v1/registry", {}) or {}
    artifacts = reg.get("artifacts", [])
    events = (get_json("/api/v1/events?limit=100", {}) or {}).get("events", [])
    incidents = (get_json("/api/v1/findings", {}) or {}).get("findings", [])
    open_inc = [f for f in incidents if f.get("status") == "open"]

    zones = reg.get("zones", {})
    n_prod = zones.get("prod", 0)
    n_ok = zones.get("ok", 0)

    st.caption("Сводка из реального бэкенда. Кликни карточку — перейдёшь к разделу.")
    cards = [("В проде", n_prod, "ok", "Реестр"),
             ("Прошли проверку", n_ok, "info", "Реестр"),
             ("Открытых инцидентов", len(open_inc), "bad" if open_inc else "ok", "Инциденты"),
             ("Событий в истории", len(events), "muted", "История")]
    cols = st.columns(4)
    for col, (label, val, kind, page) in zip(cols, cards):
        with col:
            st.markdown(
                f"<div class='card {kind}'><div class='s'>{label}</div>"
                f"<div style='font-size:2rem;font-weight:800'>{val}</div></div>",
                unsafe_allow_html=True)
            if st.button("Открыть →", key=f"dash_{label}", use_container_width=True):
                _goto(page)

    # Панель «Ожидают Human Approve» (HITL для Tier=HIGH) — для MLSecOps.
    if _has("MLSecOps"):
        st.markdown("### ⏳ Ожидают Human Approve (HITL, Tier=HIGH)")
        pend = (get_json("/api/v1/approvals/pending", {}) or {}).get("pending", [])
        if not pend:
            st.caption("Очередь подтверждений пуста.")
        for a in pend:
            c1, c2 = st.columns([4, 1])
            c1.markdown(
                f"<div class='card warn'><div class='h'>{_label(a)} &nbsp; {_tpill(a.get('tier'))}</div>"
                f"<div class='s'>владелец {a.get('owner')} · эксперимент {a.get('experiment')} · "
                f"<span class='mono'>{a.get('run_id','')[:12]}</span></div></div>",
                unsafe_allow_html=True)
            if c2.button("Рассмотреть →", key=f"appr_{a['run_id']}", use_container_width=True):
                _open_artifact(a["run_id"])
    elif _has("CEO"):
        st.markdown("### Статус защищённости")
        chain = get_json("/api/v1/events/verify_chain", {}) or {}
        if chain.get("ok"):
            st.success(f"Audit Trail цел: цепочка из {chain.get('count', 0)} событий валидна.")
        else:
            st.info("Статус целостности Audit Trail недоступен.")

    st.markdown("### Мониторинг рантайма (G6 / G7)")
    _not_implemented("Дрейф (PSI), статистика 429/422, pass-rate гейтов",
                     note="Метрики считает рантайм-слой C (monitor.py / serve) и пишет в "
                          "logs/inference_*.jsonl. В бэкенд A они пока не прокинуты.")


# ─────────────────────────────── КАБИНЕТ ────────────────────────────────────
def page_cabinet():
    st.subheader("Личный кабинет")
    me = get_json("/api/v1/auth/me", {}) or {}
    st.write(f"**Пользователь:** `{me.get('username', st.session_state.get('username','?'))}`")
    rs = me.get("roles") or _roles()
    st.write(f"**Роли:** {', '.join(rs) if rs else '— (ожидайте назначения от MLSecOps)'}")
    st.write(f"**Клиренс:** {_clearance()}")

    st.markdown("#### 🔗 Доступ к MLflow из ноутбука")
    st.caption("Нажми кнопку — получишь персональный токен и готовый сниппет для Jupyter.")
    if st.button("Получить MLflow-токен"):
        r = api_post("/api/v1/auth/token")
        if r.status_code == 200:
            st.code(r.json()["usage"], language="python")
            st.caption("Токен короткоживущий; для нового сеанса получи заново.")
        else:
            st.error(f"Ошибка: {r.json().get('detail', r.text)}")

    st.markdown("#### 🧪 Последние MLflow раны")
    st.markdown(f"🔗 [Открыть MLflow UI напрямую →]({MLFLOW_UI_URL})")
    runs = (get_json("/api/v1/mlflow/runs?limit=50", {}, timeout=30) or {}).get("runs", [])
    if not runs:
        st.info("Ранов пока нет. Залогируй сессию через ноутбук (см. examples/dev_train_mock.py).")
        return
    rows = [{"experiment": r.get("experiment"), "run": r.get("run_name") or r["run_id"][:8],
             "owner": r.get("owner"), "status": r.get("status"), "when": _when(r.get("start_time")),
             "metrics": ", ".join(f"{k}={v}" for k, v in r.get("metrics", {}).items())}
            for r in runs]
    st.dataframe(rows, use_container_width=True, hide_index=True)


# ─────────────────────────────── МОИ АРТЕФАКТЫ ──────────────────────────────
def page_artifacts():
    st.subheader("Мои артефакты (сессии разработки MLflow)")
    st.caption("Каждый ран = сессия (data+код+модель). По умолчанию приватен. Чтобы открыть доступ "
               "другим ролям — сначала пройди security check, затем выбери видимость.")
    data = get_json_fresh("/api/v1/artifacts", {}, timeout=30) or {}
    mine = data.get("mine", [])
    shared = data.get("shared_with_me", [])
    st.caption(f"Твой клиренс: {data.get('my_clearance')}")

    if not mine:
        st.info("Своих ранов пока нет. Залогируй сессию через ноутбук/мок "
                "(examples/dev_train_mock.py) — они появятся здесь.")
    for a in mine:
        rid = a["run_id"]
        title = f"{_label(a)} — {_share_badge(a)} · check: {a.get('check_status')}"
        with st.expander(title):
            st.write(f"**run_id:** `{rid}`  ·  **эксперимент:** {a.get('experiment')}")
            if a.get("metrics"):
                st.caption("метрики: " + ", ".join(f"{k}={v}" for k, v in a["metrics"].items()))
            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("🛡 Security check", key=f"chk_{rid}"):
                    r = api_post(f"/api/v1/artifacts/{rid}/check", timeout=60)
                    if r.status_code == 200:
                        res = r.json()
                        (st.success if res["check_status"] == "passed" else st.error)(
                            f"Проверка: {res['check_status']} (Tier {res.get('tier')})")
                        _invalidate()
                        _rerun()
                    else:
                        st.error(r.json().get("detail", r.text))
                if st.button("📄 Открыть в реестре →", key=f"open_{rid}"):
                    _open_artifact(rid)
            with c2:
                custom = st.multiselect("Открыть доступ ролям (опц.)", ALL_ROLES, key=f"roles_{rid}",
                                        help="Пусто — доступ по клиренсу твоей роли (read-down). "
                                             "Иначе — только выбранным ролям.")
                if st.button("🔗 Открыть доступ", key=f"shr_{rid}",
                             disabled=a.get("check_status") != "passed",
                             help="Делает артефакт видимым другим ролям. Доступно после security check."):
                    r = api_post(f"/api/v1/artifacts/{rid}/share", json={"roles": custom or None})
                    if r.status_code == 200:
                        st.success("Доступ открыт.")
                        _invalidate()
                        _rerun()
                    else:
                        st.error(r.json().get("detail", r.text))
                if a.get("check_status") != "passed":
                    st.caption("Доступ откроется после успешной проверки.")
            with c3:
                if a.get("share_status") == "shared" and st.button("🔒 Закрыть доступ", key=f"uns_{rid}"):
                    r = api_post(f"/api/v1/artifacts/{rid}/unshare")
                    if r.status_code == 200:
                        st.info("Снова приватный.")
                        _invalidate()
                        _rerun()
                    else:
                        st.error(r.json().get("detail", r.text))

    st.divider()
    st.markdown("#### 📥 Доступно мне (открыли доступ другие)")
    if not shared:
        st.caption("Пока ничего не открыто вам.")
    else:
        st.dataframe(
            [{"run": _label(s), "owner": s.get("owner"), "эксперимент": s.get("experiment"),
              "видимость": _share_badge(s)} for s in shared],
            use_container_width=True, hide_index=True)


# ─────────────────────────── РЕЕСТР (хаб артефактов) ────────────────────────
def page_registry():
    # Если открыт конкретный артефакт — показываем его страницу (паспорт + гейты + деплой).
    rid = st.session_state.get("_artifact_open")
    if rid:
        _render_artifact_detail(rid)
        return

    reg = get_json_fresh("/api/v1/registry", {}) or {}
    artifacts = reg.get("artifacts", [])
    st.caption("Артефакты MLflow по зонам жизненного цикла. Открой артефакт → паспорт, цепочка "
               "гейтов, перезапуск проверки и выкатка.")
    st.caption("📦 " + (reg.get("storage_note") or
               "Артефакты физически — в artifact store MLflow; прод-копия в перспективе — WORM в S3/MinIO."))

    if not artifacts:
        st.info("Реестр пуст. Артефакты появляются, когда разработчики логируют раны в MLflow "
                "и (для общего обзора) запускают по ним security check.")
        return

    # Фильтры по тегам (security.*) и статусам (а не по поисковой строке).
    owners = sorted({a.get("owner") or "?" for a in artifacts})
    tiers = sorted({a.get("tier") for a in artifacts if a.get("tier")})
    all_tags = sorted({f"{k}={v}" for a in artifacts for k, v in (a.get("tags") or {}).items()
                       if k.startswith("security.")})
    ftag = (st.multiselect("Теги (security.*)", all_tags, key="reg_tags",
                           help="Фильтр по тегам безопасности рана (источник данных, PII и т.п.).")
            if all_tags else [])
    f1, f2, f3, f4 = st.columns(4)
    fz = f1.multiselect("Зона", ZONE_ORDER, format_func=lambda z: ZONE_LABEL.get(z, z), key="reg_zone")
    fc = f2.multiselect("Статус проверки", ["none", "pending", "passed", "failed"], key="reg_check")
    ft = f3.multiselect("Tier", tiers, key="reg_tier")
    fo = f4.multiselect("Владелец", owners, key="reg_owner")

    def keep(a):
        if fz and a.get("zone") not in fz:
            return False
        if fc and (a.get("check_status") or "none") not in fc:
            return False
        if ft and a.get("tier") not in ft:
            return False
        if fo and (a.get("owner") or "?") not in fo:
            return False
        if ftag and not (set(ftag) & {f"{k}={v}" for k, v in (a.get("tags") or {}).items()}):
            return False
        return True

    shown = [a for a in artifacts if keep(a)]
    st.caption(f"Показано {len(shown)} из {len(artifacts)} артефактов.")

    by_zone = {}
    for a in shown:
        by_zone.setdefault(a.get("zone", "draft"), []).append(a)
    for zone in ZONE_ORDER:
        items = by_zone.get(zone, [])
        if not items:
            continue
        st.markdown(f"### {ZONE_LABEL.get(zone, zone)} &nbsp; {_pill(len(items), ZONE_KIND.get(zone,'muted'))}",
                    unsafe_allow_html=True)
        for a in items:
            c1, c2, c3 = st.columns([5, 1, 1])
            badges = f"{_tpill(a.get('tier'))} &nbsp; {_spill(a.get('check_status') or 'none')}"
            if (a.get("stage") or "none") != "none":
                badges += " &nbsp; " + _spill(a.get("stage"))
            if a.get("share_status") == "shared":
                badges += " &nbsp; " + _pill("SHARED", "ok")
            c1.markdown(
                f"<div class='card {ZONE_KIND.get(zone,'muted')}'><div class='h'>{_label(a)} &nbsp; {badges}</div>"
                f"<div class='s'>владелец {a.get('owner')} · эксп. {a.get('experiment')} · "
                f"<span class='mono'>{a.get('run_id','')[:12]}</span></div></div>",
                unsafe_allow_html=True)
            if c2.button("Открыть →", key=f"reg_open_{a['run_id']}", use_container_width=True):
                _open_artifact(a["run_id"])
            # «Выкатить в прод» прямо из реестра — только MLSecOps, только для прошедших проверку
            # и ещё не запущенных в выкатку (RBAC + статус/доступ аккаунта).
            can_deploy = (_has("MLSecOps") and a.get("check_status") == "passed"
                          and (a.get("stage") or "none") in ("none", "previous"))
            if c3.button("🚀 В прод", key=f"reg_dep_{a['run_id']}", use_container_width=True,
                         disabled=not can_deploy,
                         help="Инициировать выкатку (MLSecOps, после успешной проверки). "
                              "HIGH-Tier потребует Human Approve. Полный цикл — на странице артефакта."):
                r = api_post(f"/api/v1/artifacts/{a['run_id']}/deploy", json={"reason": "выкатка из реестра"})
                if r.status_code == 200:
                    st.success(f"Выкатка инициирована: стадия {r.json().get('stage')}.")
                    _invalidate(); _rerun()
                else:
                    st.error(r.json().get("detail", r.text))


# ───────────────── СТРАНИЦА АРТЕФАКТА (паспорт + цепочка гейтов + деплой) ─────
def _gate_chain_html(gates: list) -> str:
    nodes = []
    by_id = {g["id"]: g for g in gates}
    for gid in ALL_GATES:
        g = by_id.get(gid)
        if g is None:
            nodes.append(f"<div class='gnode muted'><div class='gid'>{gid}</div>"
                         f"<div class='gn'>{GATE_TITLE.get(gid,'')}</div><div>—</div></div>")
        else:
            k = _kind(g.get("status"))
            mark = {"PASS": "✓", "FAIL": "✕", "SKIP": "∅"}.get(g.get("status"), "?")
            nodes.append(f"<div class='gnode {k}'><div class='gid'>{gid}</div>"
                         f"<div class='gn'>{g.get('name','')}</div>"
                         f"<div>{_pill(mark + ' ' + str(g.get('status')), k)}</div></div>")
    return "<div class='chain'>" + "<span class='garrow'>→</span>".join(nodes) + "</div>"


def _render_artifact_detail(run_id: str):
    if st.button("← К реестру"):
        st.session_state.pop("_artifact_open", None)
        _rerun()
        return
    card = get_json_fresh(f"/api/v1/artifacts/{run_id}", None)
    if card is None:
        st.error("Артефакт недоступен (нет в MLflow или нет прав).")
        return

    zone = card.get("zone", "draft")
    st.markdown(f"## {_label(card)} &nbsp; {_pill(ZONE_LABEL.get(zone, zone), ZONE_KIND.get(zone,'muted'))}",
                unsafe_allow_html=True)
    st.markdown(
        f"{_tpill(card.get('tier'))} &nbsp; {_spill(card.get('check_status') or 'none')} &nbsp; "
        f"стадия {_spill(card.get('stage') or 'none')} &nbsp; {_share_badge(card)}",
        unsafe_allow_html=True)
    st.caption(f"run_id `{card.get('run_id')}` · владелец {card.get('owner')} · "
               f"эксперимент {card.get('experiment')} · запуск {_when(card.get('start_time'))}")

    # Паспорт: метрики/параметры (lineage).
    cols = st.columns(2)
    with cols[0]:
        st.markdown("##### Метрики")
        m = card.get("metrics") or {}
        st.dataframe([{"метрика": k, "значение": v} for k, v in m.items()] or [{"метрика": "—", "значение": "—"}],
                     use_container_width=True, hide_index=True)
    with cols[1]:
        st.markdown("##### Параметры")
        p = card.get("params") or {}
        st.dataframe([{"параметр": k, "значение": v} for k, v in p.items()] or [{"параметр": "—", "значение": "—"}],
                     use_container_width=True, hide_index=True)

    # Цепочка гейтов.
    st.markdown("### Цепочка security-гейтов")
    detail = card.get("check_detail") or {}
    gates = detail.get("gates") or []
    is_owner = card.get("is_owner")
    can_rerun = is_owner or _has("MLSecOps")

    if not gates:
        st.info("Security check ещё не запускался. Прогони цепочку гейтов — появится паспорт проверки.")
    else:
        st.markdown(_gate_chain_html(gates), unsafe_allow_html=True)
        st.caption("Гейты — конфиг-driven плейсхолдеры (config/gates.yml): структура реальная, "
                   "логика пока отдаёт PASS. Разверни гейт — логи и перезапуск.")
        for g in gates:
            k = _kind(g.get("status"))
            with st.expander(f"{g['id']} · {g.get('name','')} — {g.get('status')}  "
                             f"(severity {g.get('severity')}, угрозы {' '.join(g.get('threats', []))})"):
                st.write(g.get("detail", ""))
                logs = g.get("logs") or []
                if logs:
                    st.markdown("<div class='errbox'>" + "<br>".join(
                        str(x).replace("<", "&lt;") for x in logs) + "</div>", unsafe_allow_html=True)
                if can_rerun and st.button(f"🔁 Перезапустить {g['id']}", key=f"rerun_{run_id}_{g['id']}"):
                    r = api_post(f"/api/v1/artifacts/{run_id}/gates/{g['id']}/rerun", timeout=60)
                    if r.status_code == 200:
                        st.success(f"{g['id']}: {r.json()['gate']['status']}")
                        _invalidate()
                        _rerun()
                    else:
                        st.error(r.json().get("detail", r.text))

    if is_owner:
        if st.button("🛡 Перепройти security check (вся цепочка)", key=f"recheck_{run_id}"):
            r = api_post(f"/api/v1/artifacts/{run_id}/check", timeout=60)
            if r.status_code == 200:
                res = r.json()
                (st.success if res["check_status"] == "passed" else st.error)(
                    f"Проверка: {res['check_status']} (Tier {res.get('tier')})")
                _invalidate()
                _rerun()
            else:
                st.error(r.json().get("detail", r.text))

    # Инциденты артефакта.
    incs = card.get("incidents") or []
    if incs:
        st.markdown("### Инциденты артефакта")
        st.dataframe([{"гейт": f.get("gate"), "severity": str(f.get("severity")).upper(),
                       "правило": f.get("rule"), "статус": str(f.get("status")).upper(),
                       "когда": str(f.get("ts", ""))[:19]} for f in incs],
                     use_container_width=True, hide_index=True)

    # Жизненный цикл / деплой (RBAC: MLSecOps). Реальный CI — плейсхолдер, движение персистится.
    st.markdown("### Выкатка и продакшн")
    if not _has("MLSecOps"):
        st.caption("Действия выкатки/approve/прод доступны роли MLSecOps. "
                   "Сейчас стадия: " + (card.get("stage") or "none") + ".")
        return
    stage = card.get("stage") or "none"
    cs = card.get("check_status")
    st.caption("Реального CI-деплоя нет (плейсхолдер) — но движение по стадиям персистится "
               "и видно в реестре/на дашборде.")
    reason = st.text_input("Причина действия (пишется в Audit Trail)", key=f"reason_{run_id}")

    def act(path, label, ok_msg):
        if st.button(label, key=f"act_{run_id}_{label}"):
            r = api_post(f"/api/v1/artifacts/{run_id}/{path}", json={"reason": reason})
            if r.status_code == 200:
                st.success(ok_msg)
                _invalidate()
                _rerun()
            else:
                st.error(r.json().get("detail", r.text))

    if cs != "passed":
        st.warning("Артефакт не прошёл security check — выкатка недоступна.")
    elif stage in ("none",):
        act("deploy", "🚀 Инициировать выкатку", "Выкатка инициирована.")
    elif stage == "pending_approve":
        st.info("Ожидает Human Approve (Tier=HIGH). Подтверждает MLSecOps, не владелец артефакта.")
        if card.get("is_owner"):
            st.caption("Это ваш артефакт — подтвердить должен другой MLSecOps (разделение полномочий).")
        else:
            act("approve", "✅ Approve (HITL)", "Подтверждено.")
    elif stage == "approved":
        act("promote", "🟢 Перевести в ПРОД", "Переведено в прод.")
    elif stage == "prod":
        c1, c2 = st.columns(2)
        with c1:
            act("rollback", "⏮ Откатить из прода", "Откачено.")
        with c2:
            act("retire", "🗄 Вывести из эксплуатации", "Выведено.")
    else:
        st.caption(f"Стадия: {stage}. Доступных действий нет.")
        act("retire", "🗄 Вывести из эксплуатации", "Выведено.")


# ─────────────────────────────── ИСТОРИЯ ────────────────────────────────────
def page_events():
    st.caption("Цепочка событий с hash-chain (актор = серверная личность из токена). "
               "Фильтры — по тегам, не по строке.")
    raw = (get_json("/api/v1/events?limit=200", {}) or {}).get("events", [])
    if not raw:
        st.info("Событий пока нет.")
        return

    actions = sorted({e.get("action") for e in raw if e.get("action")})
    results = sorted({e.get("result") for e in raw if e.get("result")})
    roles = sorted({e.get("role") for e in raw if e.get("role")})
    f1, f2, f3, f4 = st.columns([2, 1, 1, 1])
    fa = f1.multiselect("Тип события", actions, key="ev_action")
    fr = f2.multiselect("Результат", results, key="ev_result")
    fl = f3.multiselect("Роль актора", roles, key="ev_role")
    if f4.button("Проверить цепочку", use_container_width=True):
        r = get_json("/api/v1/events/verify_chain", {}) or {}
        if r.get("ok"):
            st.success(f"Цепочка валидна ({r.get('count', 0)} событий).")
        elif r:
            st.error(f"Разрыв цепочки на событии id={r.get('broken_at')}.")
        else:
            st.error("Не удалось проверить цепочку (бэкенд недоступен).")

    events = []
    for e in raw:
        if fa and e.get("action") not in fa:
            continue
        if fr and e.get("result") not in fr:
            continue
        if fl and e.get("role") not in fl:
            continue
        detail = e.get("reason")
        if not detail and e.get("details"):
            detail = json.dumps(e["details"], ensure_ascii=False)
        events.append({"id": e.get("id"), "ts": e.get("ts") or "", "type": e.get("action"),
                       "actor": e.get("actor"), "role": e.get("role"),
                       "asset": e.get("asset") or "—", "result": e.get("result") or "ok",
                       "detail": detail or ""})
    st.caption(f"Показано {len(events)} из {len(raw)} событий.")

    icon = {"ok": "●", "blocked": "■", "error": "▲", "pending": "◆"}
    for e in events:  # бэкенд отдаёт новые сверху
        k = _kind(e["result"])
        clr = "ok" if k == "ok" else "bad" if k == "bad" else "warn"
        st.markdown(
            f"<div class='card {k}'><div class='h'>"
            f"<span style='color:var(--{clr})'>{icon.get(e['result'], '●')}</span> "
            f"{e['type']} &nbsp; {_spill(e['result'])}</div>"
            f"<div class='s'><span class='mono'>{str(e['ts'])[:19]}</span> · "
            f"{e['actor']}/{e.get('role') or '—'} · актив <span class='mono'>{e['asset']}</span></div>"
            f"<div style='margin-top:.25rem'>{e['detail']}</div></div>",
            unsafe_allow_html=True)


# ─────────────────────────────── ИНЦИДЕНТЫ ──────────────────────────────────
def page_incidents():
    st.caption("Инциденты безопасности — автоматически из упавших гейтов (security check артефактов). "
               "MLSecOps видит все; остальные — по своим артефактам.")
    data = (get_json("/api/v1/findings", {}) or {}).get("findings", [])
    if not data:
        st.success("Открытых инцидентов нет. Инцидент заводится, когда гейт падает (FAIL) на проверке "
                   "артефакта (сейчас гейты-плейсхолдеры обычно проходят).")
        return

    gates = sorted({f.get("gate") for f in data if f.get("gate")})
    sevs = sorted({f.get("severity") for f in data if f.get("severity")})
    f1, f2, f3 = st.columns(3)
    fg = f1.multiselect("Гейт", gates, key="inc_gate")
    fs = f2.multiselect("Severity", sevs, key="inc_sev")
    fst = f3.multiselect("Статус", ["open", "false_positive", "fixed"], key="inc_status")

    rows = [f for f in data
            if (not fg or f.get("gate") in fg)
            and (not fs or f.get("severity") in fs)
            and (not fst or f.get("status") in fst)]
    st.caption(f"Показано {len(rows)} из {len(data)} инцидентов.")

    for f in rows:
        k = _kind(f.get("status"))
        c1, c2 = st.columns([5, 1])
        ev = f.get("evidence") or {}
        c1.markdown(
            f"<div class='card {k}'><div class='h'>{_sevpill(f.get('severity'))} &nbsp; "
            f"{f.get('gate')} · {f.get('rule')} &nbsp; {_spill(f.get('status'))}</div>"
            f"<div class='s'>артефакт <span class='mono'>{str(f.get('asset'))[:14]}</span> · "
            f"{str(f.get('ts',''))[:19]}</div>"
            f"<div style='margin-top:.25rem'>{ev.get('detail','')}</div></div>",
            unsafe_allow_html=True)
        with c2:
            if st.button("Открыть артефакт →", key=f"inc_open_{f['id']}", use_container_width=True):
                _open_artifact(f.get("asset"))
            if _has("MLSecOps") and f.get("status") == "open":
                if st.button("Отметить FP", key=f"inc_fp_{f['id']}", use_container_width=True):
                    r = api_post(f"/api/v1/findings/{f['id']}/false_positive",
                                 json={"reason": "ложное срабатывание (UI)"})
                    if r.status_code == 200:
                        st.info("Отмечено как false positive.")
                        _invalidate()
                        _rerun()
                    else:
                        st.error(r.json().get("detail", r.text))


# ─────────────────────────────── ПОЛЬЗОВАТЕЛИ ──────────────────────────────
def page_users():
    if not _has("MLSecOps"):
        st.warning("Управление пользователями доступно только MLSecOps.")
        return
    st.subheader("Пользователи и доступы")

    r = api_get("/api/v1/admin/users")
    if r.status_code == 200:
        users = r.json().get("users", [])
        rows = [{"логин": u.get("username"), "email": u.get("email") or "—",
                 "роли": ", ".join(u.get("roles") or []) or "— (нет роли)"} for u in users]
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.error(f"Ошибка: {r.text}")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Назначить роль")
        with st.form("assign_role"):
            u = st.text_input("Логин пользователя")
            role = st.selectbox("Роль", ALL_ROLES)
            if st.form_submit_button("Назначить"):
                rr = api_post("/api/v1/admin/roles", json={"username": u, "role": role})
                if rr.status_code == 200:
                    st.success(f"{u}: роли теперь {rr.json()['roles']}")
                    _invalidate()
                    _rerun()
                else:
                    st.error(rr.json().get("detail", rr.text))
    with col2:
        st.markdown("#### Создать пользователя")
        with st.form("create_user"):
            u = st.text_input("Логин", key="cu_u")
            p = st.text_input("Пароль", type="password", key="cu_p")
            role = st.selectbox("Роль (опц.)", ["—"] + ALL_ROLES, key="cu_r")
            if st.form_submit_button("Создать"):
                payload = {"username": u, "password": p, "roles": [] if role == "—" else [role]}
                rr = api_post("/api/v1/admin/users", json=payload)
                if rr.status_code == 200:
                    st.success(f"Создан {u}, роли {rr.json()['roles']}")
                    _invalidate()
                    _rerun()
                else:
                    st.error(rr.json().get("detail", rr.text))

    st.markdown("#### Выдать доступ к датасету")
    with st.form("grant_access"):
        u = st.text_input("Логин", key="ga_u")
        dn = st.text_input("Датасет (name)", key="ga_dn")
        dv = st.text_input("Версия", value="v1", key="ga_dv")
        exp = st.checkbox("Разрешить экспорт (data_export)")
        if st.form_submit_button("Выдать доступ"):
            rr = api_post("/api/v1/admin/access",
                          json={"username": u, "dataset_name": dn,
                                "dataset_version": dv, "can_export": exp})
            if rr.status_code == 200:
                st.success(f"Доступ выдан: {rr.json()}")
            else:
                st.error(rr.json().get("detail", rr.text))


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

    if _has("CEO"):
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
    if eff != "live" and _has("MLSecOps"):
        st.markdown("**RiskAcceptance (GRC exception):**")
        reason = st.text_input("Обоснование принятия остаточного риска", key=f"ra_{ctl['id']}")
        if st.button("Принять остаточный риск", key=f"rab_{ctl['id']}"):
            if reason.strip():
                CTRL.set_accepted(ctl["id"], st.session_state.get("username", "mlsecops"), reason)
                st.success(f"{ctl['id']} → ACCEPTED (локально; персист в БД GRC — TODO).")
                _rerun()
            else:
                st.error("Обоснование обязательно")


# ─────────────────────────── КОНТУР (обзор) ─────────────────────────────────
def page_contour():
    if CTRL is None:
        st.info("Каталог контролей недоступен (src/common/controls.py).")
        return
    st.caption("Сквозной контур: пайплайн жизненного цикла + инфраструктура + рантайм-защиты.")
    incidents = (get_json("/api/v1/findings", {}) or {}).get("findings", [])
    open_find = len([f for f in incidents if f.get("status") == "open"])
    cov = CTRL.coverage()
    c = st.columns(4)
    c[0].metric("Состояние", "ТРЕВОГА" if open_find else "OK")
    c[1].metric("Открытых инцидентов", open_find)
    c[2].metric("Контролей в контуре", cov["total"])
    c[3].metric("Покрытие", f"{cov['pct']}%")

    st.markdown("### Рантайм-защиты периметра (каталог контролей)")
    rt = [c for c in CTRL.CONTROLS if c["layer"] in ("runtime", "infra")]
    cols = st.columns(2)
    for i, ctl in enumerate(rt):
        eff = CTRL.effective_status(ctl)
        cols[i % 2].markdown(
            f"<div class='card {_kind(eff)}'><div class='h'>{_pill(ctl['id'], 'info')} &nbsp; "
            f"{ctl['title']}</div><div class='s'>{eff.upper()} · угрозы {' '.join(ctl['threats'])}</div></div>",
            unsafe_allow_html=True)
    st.caption("Статусы из каталога контролей (controls.py). Живые рантайм-метрики (PSI, 429) "
               "появятся, когда рантайм-слой C начнёт отдавать их в бэкенд.")


# ─────────────────────────────── NAV / RENDER ──────────────────────────────
# (page, функция, предикат видимости по ролям)
PAGE_DEFS = [
    ("Дашборд", page_dashboard, lambda r: True),
    ("Кабинет", page_cabinet, lambda r: True),
    ("Мои артефакты", page_artifacts, lambda r: _has("DS", "DE", "MLSecOps")),
    ("Реестр", page_registry, lambda r: True),
    ("История", page_events, lambda r: True),
    ("Инциденты", page_incidents, lambda r: True),
    ("Пользователи", page_users, lambda r: _has("MLSecOps")),
    ("Карта покрытия", page_coverage, lambda r: CTRL is not None),
    ("Контур", page_contour, lambda r: CTRL is not None),
]


def _logout():
    for k in ("token", "username", "roles", "_artifact_open"):
        st.session_state.pop(k, None)
    _invalidate()
    _rerun()


def render_app():
    inject_css()

    # Роли — источник правды бэкенд. Кэшируем /auth/me (TTL≈4с), чтобы не дёргать на каждый ререндер.
    me = get_json("/api/v1/auth/me", None)
    if me is None:
        # Кэш-промах: либо токен истёк (401), либо бэкенд моргнул. Делаем ОДНУ прямую проверку.
        try:
            chk = api_get("/api/v1/auth/me", timeout=5)
            if chk.status_code == 401:
                _logout()
                return
            if chk.status_code == 200:
                st.session_state["roles"] = chk.json().get("roles", [])
        except Exception:  # noqa: BLE001
            pass  # рендерим по последним известным ролям
    else:
        st.session_state["roles"] = me.get("roles", [])

    roles = _roles()
    username = st.session_state.get("username", "?")

    # Программная навигация (_goto) — применяем до создания radio.
    nav = st.session_state.pop("_nav_request", None)
    for k, val in st.session_state.pop("_pending_state", {}).items():
        st.session_state[k] = val

    visible = [(name, fn) for (name, fn, vis) in PAGE_DEFS if vis(roles)]
    names = [n for n, _ in visible]
    if nav in names:
        st.session_state["active_page"] = nav
    if st.session_state.get("active_page") not in names:
        st.session_state["active_page"] = names[0] if names else "Дашборд"

    with st.sidebar:
        st.markdown(
            "<div style='font-size:1.2rem;font-weight:800;color:#fff;letter-spacing:-.02em'>"
            "&#9670; MLSecOps</div><div style='color:#6B7280;font-size:.76rem;margin-bottom:.6rem'>"
            "Security Platform</div>", unsafe_allow_html=True)
        st.markdown(f"### 👤 {username}", unsafe_allow_html=True)
        st.markdown(" ".join(_pill(r, "info") for r in roles) or _pill("нет роли", "muted"),
                    unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        if c1.button("Обновить", use_container_width=True, help="Сбросить кэш и перечитать данные"):
            _invalidate()
            _rerun()
        if c2.button("Выйти", use_container_width=True):
            _logout()
            return
        st.divider()
        # Смена раздела через сайдбар сбрасывает открытый артефакт.
        prev = st.session_state.get("active_page")
        page = st.radio("Разделы", names, key="active_page", label_visibility="collapsed")
        if page != prev and nav is None:
            st.session_state.pop("_artifact_open", None)
        st.divider()
        st.caption(f"Backend: {API}")

    if not roles:
        st.warning("Вам ещё не назначена роль. Доступен ограниченный набор разделов — "
                   "попросите MLSecOps выдать роль (DS/DE/…).")

    # Заголовок: на странице артефакта внутри «Реестра» — без дублирующего h1.
    if not (page == "Реестр" and st.session_state.get("_artifact_open")):
        st.markdown(f"<h1>{page}</h1>", unsafe_allow_html=True)
    fn = dict(visible).get(page)
    if fn is None:
        st.error("Раздел недоступен для вашей роли.")
        return
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        st.error(f"Ошибка раздела: {e}")


def main():
    st.set_page_config(page_title="MLSecOps Platform", layout="wide", page_icon="◆")
    if not st.session_state.get("token"):
        render_login()
    else:
        render_app()


if _HAS_STREAMLIT:
    main()
