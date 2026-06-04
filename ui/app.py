"""Streamlit UI — MLSecOps Platform (объединённый фронтенд).

Сюда смержены: красивый многостраничный UI второго разработчика (тёмная тема, разделы
Дашборд/Реестр/Паспорт/История/Находки/CI-CD/Деплой/Карта покрытия/Контур) И рабочий
личный кабинет нашего бэкенда A (аутентификация, приватность/шаринг артефактов MLflow,
сканеры через /ci/trigger, админка).

Принципы объединения:
- Вход — ТОЛЬКО реальный логин (JWT от бэкенда). Роли берутся из /auth/me (RBAC),
  обновляются на каждом рендере (учёт выдачи/отзыва роли и истечения токена).
- Все запросы к Gatekeeper идут с заголовком Authorization: Bearer <token>.
- Данные — из реального API. Где бэкенд ещё ЗАГЛУШКА — показываем честный плейсхолдер
  «не реализовано», без фейковых mock-данных.
- Разделы фильтруются по ролям пользователя.
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
THREAT_MAP = {
    "G1": "#1 Data Poisoning · #2 PII", "G2": "#8 CVE · #10 Секреты",
    "G3": "#9 Typosquatting · #3 Источник", "G4": "#3 Pickle/RCE · #4 Подмена · #26 Подпись",
    "G5": "#20 Shadow AI · #23 Lineage",
}


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


def get_json(path: str, default=None, timeout: int = 5):
    """GET → распарсенный JSON или default. БЕЗ mock-фолбэка (честные заглушки в UI)."""
    try:
        r = api_get(path, timeout=timeout)
        if r.ok:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return default


def _not_implemented(what: str, endpoint: str | None = None, note: str | None = None):
    """Честная заглушка: раздел есть в UI, но бэкенд-ручка ещё не реализована."""
    st.warning(f"🚧 **{what}** — раздел готов в UI, но бэкенд-ручка ещё не реализована "
               f"(честная заглушка, без фейковых данных).")
    if endpoint:
        st.caption(f"Ожидаемый эндпоинт: `{endpoint}` — сейчас возвращает TODO/пусто.")
    if note:
        st.caption(note)


# ─────────────────────────── мелкие хелперы ─────────────────────────────────
def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _rerun():
    fn = getattr(st, "rerun", None) or getattr(st, "experimental_rerun", None)
    if fn:
        fn()


def _goto(page, **pending):
    st.session_state["_nav_request"] = page
    if pending:
        st.session_state["_pending_state"] = pending
    _rerun()


def _roles() -> list[str]:
    return st.session_state.get("roles", []) or []


def _role() -> str:
    r = _roles()
    return r[0] if r else "—"


def _has(*roles) -> bool:
    return bool(set(roles) & set(_roles()))


def _clearance() -> int:
    return max((ROLE_LEVEL.get(r, 0) for r in _roles()), default=0)


_KIND = {"ok": "ok", "available": "ok", "prod": "ok", "production": "ok", "closed": "ok",
         "pass": "ok", "success": "ok", "approved": "ok", "passed": "ok",
         "blocked": "bad", "fail": "bad", "failed": "bad", "open": "bad", "error": "bad",
         "pending": "warn", "pending_hitl": "warn", "running": "warn", "queued": "warn",
         "candidate": "info", "previous": "muted", "retired": "muted", "fp": "muted",
         "false_positive": "muted", "skip": "muted", "skipped": "muted", "none": "muted",
         "private": "muted", "shared": "ok"}


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


def _share_badge(a: dict) -> str:
    if a.get("share_status") != "shared":
        return "🔒 приватный"
    if a.get("share_roles"):
        return f"🔗 роли: {', '.join(a['share_roles'])}"
    return f"🔗 клиренс ≥ {a.get('share_level')}"


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
    models = get_json("/api/v1/models", {}).get("models", [])
    events = get_json("/api/v1/events?limit=100", {}).get("events", [])
    findings = get_json("/api/v1/findings", {}).get("findings", [])

    if _has("CEO") and not _has("MLSecOps"):
        st.caption("Статус защищённости (read-only для CEO)")
        c = st.columns(3)
        c[0].metric("Моделей в реестре", len(models))
        c[1].metric("Событий (Audit Trail)", len(events))
        c[2].metric("Открытых находок", len([f for f in findings if f.get("status") == "open"]))
        chain = get_json("/api/v1/events/verify_chain", {})
        if chain.get("ok"):
            st.success(f"Audit Trail цел: цепочка из {chain.get('count', 0)} событий валидна.")
        else:
            st.info("Статус целостности Audit Trail недоступен.")
        return

    st.caption("Сводка из реального бэкенда. Кликни карточку — перейдёшь к разделу.")
    n_models, n_events = len(models), len(events)
    n_find = len([f for f in findings if f.get("status") == "open"])
    cards = [("Моделей в реестре", n_models, "info", "Реестр", {}),
             ("Открытых находок", n_find, "bad" if n_find else "ok", "Находки", {}),
             ("Событий в истории", n_events, "ok", "История", {}),
             ("Мой клиренс", _clearance(), "info", "Кабинет", {})]
    cols = st.columns(4)
    for col, (label, val, kind, page, pend) in zip(cols, cards):
        with col:
            st.markdown(
                f"<div class='card {kind}'><div class='s'>{label}</div>"
                f"<div style='font-size:2rem;font-weight:800'>{val}</div></div>",
                unsafe_allow_html=True)
            if st.button("Открыть →", key=f"dash_{label}", use_container_width=True):
                _goto(page, **pend)

    st.markdown("### Мониторинг рантайма (G6 / G7)")
    _not_implemented("Дрейф (PSI), статистика 429/422, pass-rate гейтов",
                     note="Эти метрики считает рантайм-слой C (monitor.py / serve) и пишет в "
                          "logs/inference_*.jsonl. В бэкенд A они пока не прокинуты "
                          "(нет ручки агрегации метрик).")


# ─────────────────────────────── КАБИНЕТ ────────────────────────────────────
def page_cabinet():
    st.subheader("Личный кабинет")
    me = get_json("/api/v1/auth/me", {})
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
    try:
        runs = api_get("/api/v1/mlflow/runs?limit=50", timeout=30).json().get("runs", [])
    except Exception as e:  # noqa: BLE001
        st.error(f"Не удалось получить раны: {e}")
        return
    if not runs:
        st.info("Ранов пока нет. Залогируй что-нибудь через ноутбук "
                "(см. examples/dev_train_mock.py).")
        return
    rows = []
    for r in runs:
        ts = r.get("start_time")
        when = _dt.datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M") if ts else ""
        rows.append({
            "experiment": r.get("experiment"), "run": r.get("run_name") or r["run_id"][:8],
            "owner": r.get("owner"), "status": r.get("status"), "when": when,
            "metrics": ", ".join(f"{k}={v}" for k, v in r.get("metrics", {}).items()),
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)


# ─────────────────────────────── МОИ АРТЕФАКТЫ ──────────────────────────────
def page_artifacts():
    st.subheader("Мои артефакты (сессии разработки MLflow)")
    st.caption("Каждый ран = сессия (data+код+модель). По умолчанию приватен. Чтобы расшарить — "
               "сначала пройди security check, затем выбери видимость (по клиренсу или ролям).")
    try:
        data = api_get("/api/v1/artifacts", timeout=30).json()
    except Exception as e:  # noqa: BLE001
        st.error(f"Не удалось получить артефакты: {e}")
        return
    mine = data.get("mine", [])
    shared = data.get("shared_with_me", [])
    st.caption(f"Твой клиренс: {data.get('my_clearance')}")

    if not mine:
        st.info("Своих ранов пока нет. Залогируй сессию через ноутбук/мок "
                "(examples/dev_train_mock.py) — они появятся здесь.")
    for a in mine:
        rid = a["run_id"]
        title = f"{a.get('run_name') or rid[:8]} — {_share_badge(a)} · check: {a.get('check_status')}"
        with st.expander(title):
            st.write(f"**run_id:** `{rid}`  ·  **эксперимент:** {a.get('experiment')}")
            if a.get("metrics"):
                st.caption("метрики: " + ", ".join(f"{k}={v}" for k, v in a["metrics"].items()))
            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("🛡 Запустить security check", key=f"chk_{rid}"):
                    r = api_post(f"/api/v1/artifacts/{rid}/check", timeout=60)
                    if r.status_code == 200:
                        res = r.json()
                        if res["check_status"] == "passed":
                            st.success("✅ Проверка пройдена (placeholder)")
                        else:
                            st.error("❌ Проверка не пройдена")
                        st.json(res["result"])
                        _rerun()
                    else:
                        st.error(r.json().get("detail", r.text))
            with c2:
                custom = st.multiselect("Кастомные роли (опц.)", ALL_ROLES, key=f"roles_{rid}")
                if st.button("🔗 Поделиться", key=f"shr_{rid}",
                             disabled=a.get("check_status") != "passed"):
                    payload = {"roles": custom or None}
                    r = api_post(f"/api/v1/artifacts/{rid}/share", json=payload)
                    if r.status_code == 200:
                        st.success(f"Расшарено: {r.json()}")
                        _rerun()
                    else:
                        st.error(r.json().get("detail", r.text))
                if a.get("check_status") != "passed":
                    st.caption("Шаринг откроется после успешной проверки.")
            with c3:
                if a.get("share_status") == "shared" and st.button("🔒 Снять шаринг", key=f"uns_{rid}"):
                    r = api_post(f"/api/v1/artifacts/{rid}/unshare")
                    if r.status_code == 200:
                        st.info("Снова приватный.")
                        _rerun()
                    else:
                        st.error(r.json().get("detail", r.text))

    st.divider()
    st.markdown("#### 📥 Доступно мне (расшарили другие)")
    if not shared:
        st.caption("Пока ничего не расшарено вам.")
    else:
        st.dataframe(
            [{"run": s.get("run_name") or s["run_id"][:8], "owner": s.get("owner"),
              "эксперимент": s.get("experiment"), "видимость": _share_badge(s)}
             for s in shared],
            use_container_width=True, hide_index=True,
        )


# ──────────────────────── ВЕРИФИКАЦИЯ / РАННЕР ГЕЙТОВ ────────────────────────
def page_verify():
    tabs = st.tabs(["Верификация модели", "Раннер гейтов (MLSecOps)"])

    with tabs[0]:
        st.caption("Отправить ран MLflow на deep-verify (G5+G2+G3 → обучение в CI → G4).")
        with st.form("verify_form"):
            c1, c2 = st.columns(2)
            model = c1.text_input("Имя модели", "credit_scoring")
            run_id = c1.text_input("MLflow Run ID")
            git_sha = c2.text_input("Git SHA", "a1b2c3d4")
            reason = st.text_area("Причина (обязательно — пишется в Audit Trail)", height=70)
            ok = st.form_submit_button("Запустить верификацию")
        if ok:
            if not reason.strip():
                st.error("Причина обязательна (Audit Trail).")
            elif not run_id.strip():
                st.error("Укажи MLflow Run ID.")
            else:
                resp = api_post("/api/v1/verify", json={
                    "model_name": model, "run_id": run_id, "git_sha": git_sha,
                    "requested_by": st.session_state.get("username", ""), "reason": reason})
                if resp.status_code == 200:
                    body = resp.json()
                    if body.get("status") == "TODO" or body.get("passed") is None:
                        st.warning("🚧 Бэкенд принял запрос, но deep-verify ещё не реализован "
                                   "(ручка `/api/v1/verify` — заглушка).")
                        st.json(body)
                    else:
                        (st.success if body.get("passed") else st.error)("Верификация завершена")
                        for gr in body.get("gate_results", []):
                            st.markdown(
                                f"{_pill('PASS' if gr['passed'] else 'FAIL', 'ok' if gr['passed'] else 'bad')}"
                                f" &nbsp; {gr['gate']}", unsafe_allow_html=True)
                else:
                    st.error(f"{resp.status_code}: {resp.text}")
        st.caption("Чтобы реально прогнать отдельные гейты сейчас — раздел «Инструменты».")

    with tabs[1]:
        if not _has("MLSecOps"):
            st.warning("Раннер гейтов доступен только роли MLSecOps.")
            return
        _not_implemented("Матричный раннер гейтов (гейты × ресурсы)",
                         endpoint="/api/v1/scan",
                         note="Покнопочный запуск отдельных гейтов уже работает в разделе "
                              "«Инструменты» (через /api/v1/ci/trigger).")


# ─────────────────────────────── РЕЕСТР ─────────────────────────────────────
def page_registry():
    st.caption("Модели из MLflow Model Registry (реальный бэкенд).")
    models = get_json("/api/v1/models", {}).get("models", [])
    if not models:
        st.info("Реестр пуст — зарегистрированных моделей нет. Модели попадают сюда после "
                "прохождения security-гейтов и регистрации (ручка реестра — в разработке).")
        return
    rows = []
    for m in models:
        if isinstance(m, dict):
            rows.append({"модель": m.get("name", "?"),
                         "версии": ", ".join(str(v) for v in m.get("latest_versions", [])) or "—"})
        else:
            rows.append({"модель": str(m), "версии": "—"})
    st.dataframe(rows, use_container_width=True, hide_index=True)
    st.caption("Детальный паспорт/lineage/Tier появятся, когда будут реализованы ручки "
               "`/api/v1/models/{name}/versions` и реестр в БД (сейчас — заглушки).")


# ─────────────────────────────── ПАСПОРТ ────────────────────────────────────
def page_passport():
    models = get_json("/api/v1/models", {}).get("models", [])
    names = [m.get("name") if isinstance(m, dict) else str(m) for m in models]
    if not names:
        st.info("Нет моделей в реестре — паспорт показывать не для чего.")
        return
    st.selectbox("Модель", names, key="passport_sel")
    _not_implemented("Паспорт модели (Tier, lineage, проверки, версии, история)",
                     endpoint="/api/v1/models/{name}/versions, /api/v1/datasets/{key}",
                     note="Имена моделей берём из MLflow Registry, но детальный паспорт "
                          "(версии/датасеты/гейты) требует ручек реестра — они пока заглушки.")


# ─────────────────────────────── ИСТОРИЯ ────────────────────────────────────
def page_events():
    st.caption("Цепочка событий с hash-chain (актор = серверная личность из токена).")
    c1, c2 = st.columns([3, 1])
    f_asset = c1.text_input("Фильтр по активу", key="flt_ev_asset")
    if c2.button("Проверить цепочку хешей", use_container_width=True):
        r = get_json("/api/v1/events/verify_chain", {})
        if r.get("ok"):
            st.success(f"Цепочка валидна ({r.get('count', 0)} событий).")
        elif r:
            st.error(f"Разрыв цепочки на событии id={r.get('broken_at')}.")
        else:
            st.error("Не удалось проверить цепочку (бэкенд недоступен).")

    raw = get_json("/api/v1/events?limit=100", {}).get("events", [])
    # Адаптер имён полей бэкенда (action/reason/details) → ожидаемые UI (type/detail).
    events = []
    for e in raw:
        detail = e.get("reason")
        if not detail and e.get("details"):
            detail = json.dumps(e["details"], ensure_ascii=False)
        events.append({"id": e.get("id"), "ts": e.get("ts") or "", "type": e.get("action"),
                       "actor": e.get("actor"), "role": e.get("role"),
                       "asset": e.get("asset") or "—", "result": e.get("result") or "ok",
                       "detail": detail or ""})
    if f_asset:
        events = [e for e in events if f_asset.lower() in str(e.get("asset", "")).lower()]
    if not events:
        st.info("Событий пока нет.")
        return

    icon = {"ok": "●", "blocked": "■", "error": "▲", "pending": "◆"}
    for e in events:  # бэкенд уже отдаёт новые сверху
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


# ─────────────────────────────── НАХОДКИ ────────────────────────────────────
def page_findings():
    c1, c2, c3 = st.columns(3)
    c1.multiselect("Гейт", ["G1", "G2", "G3", "G4", "G5", "G6", "G7"], key="flt_find_gate")
    c2.multiselect("Severity", ["critical", "high", "medium", "low"], key="flt_find_sev")
    c3.multiselect("Статус", ["open", "closed", "fp"], key="flt_find_status")

    data = get_json("/api/v1/findings", {}).get("findings", [])
    if not data:
        _not_implemented("Журнал находок (сработки гейтов: причина/evidence/FP/перезапуск)",
                         endpoint="/api/v1/findings",
                         note="Гейты уже умеют отдавать evidence (см. «Инструменты»), но запись "
                              "находок в БД (db.add_finding) и выдача `/api/v1/findings` — в разработке.")
        return
    rows = [{"sev": str(f.get("severity", "")).upper(), "гейт": f.get("gate"),
             "проверка": f.get("check") or f.get("rule"), "статус": str(f.get("status", "")).upper(),
             "актив": f.get("asset"), "когда": str(f.get("ts", ""))[11:19]} for f in data]
    st.dataframe(rows, use_container_width=True, hide_index=True)


# ─────────────────────────────── CI/CD ЛОГИ ─────────────────────────────────
def page_cicd():
    if not _has("MLSecOps"):
        st.warning("Логи CI/CD доступны только роли MLSecOps.")
        return
    _not_implemented("Просмотр прогонов CI/CD (jobs/steps/логи)",
                     endpoint="/api/v1/cicd/runs",
                     note="Запуск гейтов в GitHub Actions УЖЕ работает через "
                          "/api/v1/ci/trigger (см. «Инструменты»), но retrieval статусов "
                          "и логов прогонов обратно в UI пока не реализован.")
    repo = os.getenv("GITHUB_REPO", "")
    if repo:
        st.markdown(f"🔗 [Открыть GitHub Actions →](https://github.com/{repo}/actions)")


# ─────────────────────────────── ИНСТРУМЕНТЫ ────────────────────────────────
def page_scanners():
    st.caption("Запуск отдельных security-гейтов на реальных артефактах (через /api/v1/ci/trigger).")

    def _run_gate(check_type: str, target: str):
        with st.spinner(f"Запускаю {check_type}..."):
            try:
                resp = api_post("/api/v1/ci/trigger",
                                json={"check_type": check_type, "target": target}, timeout=120)
                data = resp.json()
            except Exception as e:  # noqa: BLE001
                st.error(f"Не удалось подключиться к бэкенду: {e}")
                return
        if resp.status_code != 200 or data.get("status") != "ok":
            st.error(f"Ошибка: {data.get('detail', resp.text)}")
            return
        if data.get("mode") == "github_actions":
            repo = data.get("repo", "")
            st.success("✅ Workflow запущен в GitHub Actions!")
            if repo:
                st.markdown(f"[Открыть GitHub Actions →](https://github.com/{repo}/actions)")
            return
        report = data["report"]
        if report.get("passed", False):
            st.success(f"✅ {check_type.upper()} — PASS")
        else:
            st.error(f"❌ {check_type.upper()} — FAIL: {report.get('failed_checks', [])}")
        for check in report.get("checks", []):
            label = f"**{check['check']}** — {check['detail']}"
            if check["status"] == "PASS":
                st.success(label)
            elif check["status"] == "FAIL":
                st.error(label)
            else:
                st.warning(f"⚠️ {label} (SKIP)")

    with st.expander("🗂 G1 — Data Gate (схема, PII, баланс классов)", expanded=True):
        csv_files = []
        try:
            csv_files = api_get("/api/v1/files", timeout=5).json().get("files", [])
        except Exception:  # noqa: BLE001
            pass
        if not csv_files:
            csv_files = ["data/train_m1_clean.csv"]
        target_ds = st.selectbox("Файл для проверки", csv_files, key="ds_select")
        if st.button("Запустить Data Gate", key="btn_data"):
            _run_gate("data_gate", target_ds)

    with st.expander("🔍 G2 — Code Gate (секреты, SAST, CVE)"):
        if st.button("Запустить Code Gate", key="btn_code"):
            _run_gate("code_gate", ".")

    with st.expander("📦 G3 — Dependency Gate (allow-list, пиннинг)"):
        if st.button("Запустить Dependency Gate", key="btn_dep"):
            _run_gate("dependency_gate", ".")

    st.divider()
    st.markdown("#### Загрузить свой CSV")
    uploaded = st.file_uploader("CSV-файл", type=["csv"])
    if uploaded is not None and st.button("Загрузить на сервер", key="btn_upload"):
        try:
            resp = api_post("/api/v1/upload",
                            files={"file": (uploaded.name, uploaded.getvalue(), "text/csv")},
                            timeout=30)
            data = resp.json()
            if data.get("status") == "ok":
                st.success(f"Загружен: {data['filename']} ({data['size']} б). Обнови (F5).")
            else:
                st.error(f"Ошибка: {data.get('detail', '')}")
        except Exception as e:  # noqa: BLE001
            st.error(f"Ошибка загрузки: {e}")

    st.divider()
    st.markdown("#### Карта инструментов → гейт → угроза (справочно)")
    tools = {
        "gitleaks": ("G2", "high", "#10 секреты"), "bandit": ("G2", "high", "#8 SAST"),
        "pip-audit": ("G2", "critical", "#8 CVE"), "trivy": ("G2", "critical", "#8 CVE образа"),
        "modelscan": ("G4", "critical", "#3 pickle/RCE"), "cosign": ("G4", "high", "#26 подпись"),
        "pandas": ("G1", "high", "#1/#2 данные"), "redis": ("G7", "high", "#5/#6 rate-limit"),
        "evidently": ("G6", "medium", "#14 дрейф"),
    }
    st.dataframe(
        [{"инструмент": t, "гейт": g, "severity": sev.upper(), "угроза": thr}
         for t, (g, sev, thr) in tools.items()],
        use_container_width=True, hide_index=True)


# ─────────────────────────────── ДЕПЛОЙ ─────────────────────────────────────
def page_deploy():
    if not _has("MLSecOps"):
        st.warning("Деплой/Approve доступен только роли MLSecOps.")
        return
    st.caption("Деплой в прод. Tier=HIGH требует ручного Approve MLSecOps (HITL).")
    models = get_json("/api/v1/models", {}).get("models", [])
    if not models:
        st.info("Нет моделей, ожидающих деплоя (реестр пуст).")
    _not_implemented("Деплой и HITL-Approve (deploy.yml, статусы candidate/pending_hitl→prod)",
                     endpoint="/api/v1/deploy/{model}/{version}, /api/v1/deploy/.../approve",
                     note="Ручки деплоя/approve/rollback/retire в бэкенде — заглушки (TODO). "
                          "RBAC уже реальный: не-MLSecOps сюда не попадёт.")


# ─────────────────────────────── ПОЛЬЗОВАТЕЛИ ──────────────────────────────
def page_users():
    if not _has("MLSecOps"):
        st.warning("Управление пользователями доступно только MLSecOps.")
        return
    st.subheader("Пользователи и доступы")

    r = api_get("/api/v1/admin/users")
    if r.status_code == 403:
        st.error("Нужна роль MLSecOps.")
        return
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
                payload = {"username": u, "password": p,
                           "roles": [] if role == "—" else [role]}
                rr = api_post("/api/v1/admin/users", json=payload)
                if rr.status_code == 200:
                    st.success(f"Создан {u}, роли {rr.json()['roles']}")
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
                # Бэкенд GRC-журнала пока нет — фиксируем локально для немедленного UI.
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
    findings = get_json("/api/v1/findings", {}).get("findings", [])
    open_find = len([f for f in findings if f.get("status") == "open"])
    cov = CTRL.coverage()
    c = st.columns(4)
    c[0].metric("Состояние", "ТРЕВОГА" if open_find else "OK")
    c[1].metric("Открытых сработок", open_find)
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
    ("Верификация", page_verify, lambda r: _has("DS", "DE", "MLSecOps")),
    ("Реестр", page_registry, lambda r: True),
    ("Паспорт", page_passport, lambda r: True),
    ("История", page_events, lambda r: True),
    ("Находки", page_findings, lambda r: True),
    ("Инструменты", page_scanners, lambda r: _has("DS", "DE", "MLSecOps")),
    ("CI/CD логи", page_cicd, lambda r: _has("MLSecOps")),
    ("Деплой / Approve", page_deploy, lambda r: _has("MLSecOps")),
    ("Пользователи", page_users, lambda r: _has("MLSecOps")),
    ("Карта покрытия", page_coverage, lambda r: CTRL is not None),
    ("Контур", page_contour, lambda r: CTRL is not None),
]


def _logout():
    for k in ("token", "username", "roles"):
        st.session_state.pop(k, None)
    _rerun()


def render_app():
    inject_css()

    # Роли — источник правды это бэкенд. Обновляем на каждом рендере (выдача/отзыв роли,
    # истечение токена). 401 → разлогин.
    try:
        me = api_get("/api/v1/auth/me", timeout=5)
        if me.status_code == 401:
            _logout()
            return
        if me.status_code == 200:
            st.session_state["roles"] = me.json().get("roles", [])
    except Exception:  # noqa: BLE001
        pass  # бэкенд мог моргнуть — рендерим по последним известным ролям

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
        if st.button("Выйти", use_container_width=True):
            _logout()
            return
        st.divider()
        page = st.radio("Разделы", names, key="active_page", label_visibility="collapsed")
        st.divider()
        st.caption(f"Backend: {API}")

    if not roles:
        st.warning("Вам ещё не назначена роль. Доступен ограниченный набор разделов — "
                   "попросите MLSecOps выдать роль (DS/DE/…).")

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
