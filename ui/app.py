"""Streamlit UI — личный кабинет MLSecOps-платформы.

Сначала экран входа/регистрации (JWT от бэкенда хранится в session_state),
затем вкладки личного кабинета (docs/14_FRONTEND_UI.md). Контент — по ролям из /auth/me.
Все запросы к Gatekeeper идут с заголовком Authorization: Bearer <token>.
"""
from __future__ import annotations

import os

try:
    import streamlit as st
    import requests as _http
except Exception:  # graceful для py_compile
    st = None
    _http = None

API = os.getenv("GATEKEEPER_URL", "http://localhost:8000")
APP_DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"

ALL_ROLES = ["DS", "DE", "MLSecOps", "Product", "CEO"]


# ---- HTTP-хелперы (инжектят Bearer-токен из сессии) -------------------------
def _auth_headers() -> dict:
    tok = st.session_state.get("token")
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def api_post(path: str, json=None, headers=None, **kw):
    h = _auth_headers()
    if headers:
        h.update(headers)
    return _http.post(f"{API}{path}", json=json, headers=h, **kw)


def api_get(path: str, **kw):
    return _http.get(f"{API}{path}", headers=_auth_headers(), **kw)


def _rerun():
    (getattr(st, "rerun", None) or st.experimental_rerun)()


def _logout():
    for k in ("token", "username", "roles"):
        st.session_state.pop(k, None)
    _rerun()


# ---- экран входа / регистрации ----------------------------------------------
def render_login():
    st.title("🛡️ MLSecOps Platform")
    st.caption(f"Backend: {API}")

    tab_login, tab_reg = st.tabs(["🔑 Вход", "📝 Регистрация"])

    with tab_login:
        with st.form("login_form"):
            u = st.text_input("Логин")
            p = st.text_input("Пароль", type="password")
            submitted = st.form_submit_button("Войти")
        if submitted:
            try:
                r = api_post("/api/v1/auth/login", json={"username": u, "password": p})
            except Exception as e:
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
        st.info("После регистрации роль выдаёт MLSecOps — сразу действий не будет.")
        with st.form("reg_form"):
            u = st.text_input("Логин", key="reg_u")
            e = st.text_input("Email (необязательно)", key="reg_e")
            p = st.text_input("Пароль", type="password", key="reg_p")
            submitted = st.form_submit_button("Зарегистрироваться")
        if submitted:
            try:
                r = api_post("/api/v1/auth/register",
                             json={"username": u, "password": p, "email": e or None})
            except Exception as ex:
                st.error(f"Бэкенд недоступен ({API}): {ex}")
                return
            if r.status_code == 200:
                st.success(f"Аккаунт '{u}' создан. Войдите на вкладке «Вход». "
                           f"Роль вам назначит MLSecOps.")
            else:
                st.error(f"Ошибка регистрации: {r.json().get('detail', r.text)}")


# ---- вкладки личного кабинета -----------------------------------------------
def tab_cabinet(roles: list[str]):
    st.subheader("Личный кабинет")
    me = api_get("/api/v1/auth/me")
    if me.status_code == 200:
        info = me.json()
        st.write(f"**Пользователь:** `{info['username']}`")
        st.write(f"**Роли:** {', '.join(info['roles']) if info['roles'] else '— (ожидайте назначения)'}")
    st.divider()
    st.markdown("#### 🔗 Доступ к MLflow из ноутбука")
    st.caption("Нажми кнопку — получишь персональный токен и готовый сниппет для Jupyter.")
    if st.button("Получить MLflow-токен"):
        r = api_post("/api/v1/auth/token")
        if r.status_code == 200:
            st.code(r.json()["usage"], language="python")
            st.caption("Токен короткоживущий; для нового сеанса получи заново.")
        else:
            st.error(f"Ошибка: {r.json().get('detail', r.text)}")


def tab_scanners():
    st.subheader("Инструменты / Сканеры")

    def _run_gate(check_type: str, target: str):
        with st.spinner(f"Запускаю {check_type}..."):
            try:
                resp = api_post("/api/v1/ci/trigger",
                                json={"check_type": check_type, "target": target}, timeout=120)
                data = resp.json()
            except Exception as e:
                st.error(f"Не удалось подключиться к бэкенду: {e}")
                return
        if data.get("status") != "ok":
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
        except Exception:
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
        except Exception as e:
            st.error(f"Ошибка загрузки: {e}")


def tab_mlflow():
    st.subheader("MLflow раны")
    st.caption("Эксперименты и раны из MLflow (то, что разработчики залогировали через прокси).")
    mlflow_ui = os.getenv("MLFLOW_UI_URL", "http://localhost:5000")
    st.markdown(f"🔗 [Открыть MLflow UI напрямую →]({mlflow_ui})")
    try:
        runs = api_get("/api/v1/mlflow/runs?limit=50").json().get("runs", [])
    except Exception as e:
        st.error(f"Не удалось получить раны: {e}")
        return
    if not runs:
        st.info("Ранов пока нет. Залогируй что-нибудь через мок-скрипт examples/dev_train_mock.py.")
        return
    import datetime as _dt
    rows = []
    for r in runs:
        ts = r.get("start_time")
        when = _dt.datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M") if ts else ""
        rows.append({
            "experiment": r["experiment"], "run": r.get("run_name") or r["run_id"][:8],
            "user": r.get("user"), "status": r.get("status"), "when": when,
            "metrics": ", ".join(f"{k}={v}" for k, v in r.get("metrics", {}).items()),
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)


def tab_events():
    st.subheader("История событий (Audit Trail)")
    st.caption("Цепочка событий с hash-chain (актор = серверная личность из токена).")
    try:
        events = api_get("/api/v1/events?limit=100").json().get("events", [])
    except Exception as e:
        st.error(f"Не удалось получить события: {e}")
        return
    if not events:
        st.info("Событий пока нет.")
        return
    st.dataframe(
        [{"id": e["id"], "ts": e["ts"], "actor": e["actor"], "role": e["role"],
          "action": e["action"], "result": e["result"], "reason": e.get("reason")}
         for e in events],
        use_container_width=True, hide_index=True,
    )


def tab_admin():
    st.subheader("Админка (только MLSecOps)")

    st.markdown("#### Пользователи")
    r = api_get("/api/v1/admin/users")
    if r.status_code == 403:
        st.error("Нужна роль MLSecOps.")
        return
    if r.status_code == 200:
        st.dataframe(r.json()["users"], use_container_width=True, hide_index=True)
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


# ---- основной рендер --------------------------------------------------------
def render_app():
    roles = st.session_state.get("roles", [])
    username = st.session_state.get("username", "?")

    with st.sidebar:
        st.markdown(f"### 👤 {username}")
        st.caption(f"Роли: {', '.join(roles) if roles else '—'}")
        if st.button("Выйти"):
            _logout()
        st.divider()
        st.caption(f"Backend: {API}")

    st.title("🛡️ MLSecOps Platform")

    tabs_spec = [("Личный кабинет", tab_cabinet),
                 ("MLflow раны", lambda r=None: tab_mlflow()),
                 ("Сканеры", lambda r=None: tab_scanners()),
                 ("История событий", lambda r=None: tab_events())]
    if "MLSecOps" in roles:
        tabs_spec.append(("Админка", lambda r=None: tab_admin()))

    tab_objs = st.tabs([t[0] for t in tabs_spec])
    for tab_obj, (_, fn) in zip(tab_objs, tabs_spec):
        with tab_obj:
            try:
                fn(roles)
            except TypeError:
                fn()


def main():
    st.set_page_config(page_title="MLSecOps Platform", layout="wide")
    if not st.session_state.get("token"):
        render_login()
    else:
        render_app()


if st:
    main()
