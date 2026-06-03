"""Streamlit UI — личный кабинет MLSecOps-платформы.

Вкладки (docs/14_FRONTEND_UI.md): Кабинет/Верификация · Паспорт модели(G0) · Реестр ·
История событий · Находки · Инструменты/Сканеры · Деплой/Approve · Доступы(админка) · Дашборд.
Роль определяется аутентификацией; demo-переключатель — только при APP_DEBUG.
Скелет: разметка вкладок, данные тянутся из Gatekeeper API (TODO).
"""
from __future__ import annotations

import os

try:
    import streamlit as st
    import requests as _http
except Exception:  # graceful для py_compile
    st = None
    _http = None

API = os.getenv("GATEKEEPER_URL", "http://backend:8000")
APP_DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"

TABS = [
    "Кабинет / Верификация",
    "Паспорт модели",
    "Реестр",
    "История событий",
    "Находки",
    "Инструменты / Сканеры",
    "Деплой / Approve",
    "Доступы (админка)",
    "Дашборд",
]


def render():
    st.set_page_config(page_title="MLSecOps Platform", layout="wide")
    st.title("🛡️ MLSecOps Platform")

    if APP_DEBUG:
        st.sidebar.warning("DEBUG: demo-переключатель ролей (выключен в проде)")
        st.session_state["role"] = st.sidebar.selectbox(
            "Режим (demo)", ["DS", "MLSecOps"], index=0)
    # else: роль берётся из аутентификации (X-Authenticated-User)

    tabs = st.tabs(TABS)
    with tabs[0]:
        st.subheader("Запустить проверку безопасности")

        def _run_gate(check_type: str, target: str):
            if _http is None:
                st.error("Библиотека requests не установлена")
                return
            with st.spinner(f"Запускаю {check_type}..."):
                try:
                    resp = _http.post(
                        f"{API}/api/v1/ci/trigger",
                        json={"check_type": check_type, "target": target},
                        timeout=60,
                    )
                    data = resp.json()
                except Exception as e:
                    st.error(f"Не удалось подключиться к бэкенду: {e}")
                    return

            if data.get("status") != "ok":
                st.error(f"Ошибка: {data.get('detail', resp.text)}")
                return

            report = data["report"]
            passed = report.get("passed", False)
            if passed:
                st.success(f"✅ {check_type.upper()} — PASS")
            else:
                st.error(f"❌ {check_type.upper()} — FAIL: {report.get('failed_checks', [])}")

            for check in report.get("checks", []):
                status = check["status"]
                label = f"**{check['check']}** — {check['detail']}"
                if status == "PASS":
                    st.success(label)
                elif status == "FAIL":
                    st.error(label)
                else:
                    st.warning(f"⚠️ {label} (SKIP)")

        # --- G1: Data Gate ---
        with st.expander("🗂 G1 — Data Gate (датасет: схема, PII, баланс классов)", expanded=True):
            # Загрузить список файлов с бэкенда
            csv_files = []
            if _http:
                try:
                    r = _http.get(f"{API}/api/v1/files", timeout=5)
                    csv_files = r.json().get("files", [])
                except Exception:
                    pass
            if not csv_files:
                csv_files = ["data/train_m1_clean.csv"]

            target_ds = st.selectbox("Выбери файл для проверки", csv_files, key="ds_select")
            if st.button("Запустить Data Gate", key="btn_data"):
                _run_gate("data_gate", target_ds)

        # --- G2: Code Gate ---
        with st.expander("🔍 G2 — Code Gate (секреты, SAST, CVE зависимостей)"):
            st.caption("Проверяет весь репозиторий: gitleaks + bandit + pip-audit")
            if st.button("Запустить Code Gate", key="btn_code"):
                _run_gate("code_gate", ".")

        # --- G3: Dependency Gate ---
        with st.expander("📦 G3 — Dependency Gate (allow-list, пиннинг, typosquatting)"):
            st.caption("Проверяет requirements.txt на безопасность зависимостей")
            if st.button("Запустить Dependency Gate", key="btn_dep"):
                _run_gate("dependency_gate", ".")

        st.divider()
        st.subheader("Загрузить свой CSV")
        uploaded = st.file_uploader("Выберите CSV-файл", type=["csv"])
        if uploaded is not None:
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Загрузить на сервер", key="btn_upload"):
                    if _http is None:
                        st.error("Библиотека requests не установлена")
                    else:
                        try:
                            resp = _http.post(
                                f"{API}/api/v1/upload",
                                files={"file": (uploaded.name, uploaded.getvalue(), "text/csv")},
                                timeout=30,
                            )
                            data = resp.json()
                            if data.get("status") == "ok":
                                st.success(f"Загружен: {data['filename']} ({data['size']} байт)")
                                st.info("Файл появится в списке выше — обнови страницу (F5)")
                            else:
                                st.error(f"Ошибка: {data.get('detail', '')}")
                        except Exception as e:
                            st.error(f"Ошибка загрузки: {e}")
            with col2:
                if st.button("Загрузить и сразу проверить (Data Gate)", key="btn_upload_run"):
                    if _http is None:
                        st.error("Библиотека requests не установлена")
                    else:
                        try:
                            resp = _http.post(
                                f"{API}/api/v1/upload",
                                files={"file": (uploaded.name, uploaded.getvalue(), "text/csv")},
                                timeout=30,
                            )
                            data = resp.json()
                            if data.get("status") == "ok":
                                st.success(f"Загружен: {data['filename']}")
                                _run_gate("data_gate", f"data/{data['filename']}")
                            else:
                                st.error(f"Ошибка: {data.get('detail', '')}")
                        except Exception as e:
                            st.error(f"Ошибка: {e}")
    with tabs[1]:
        st.subheader("Паспорт модели (G0)")
        st.caption("owner, Tier, источник, назначение, lineage, история проверок. TODO.")
    with tabs[2]:
        st.subheader("Реестр моделей и датасетов")
        st.caption("Фильтр по статусу/Tier/owner. Что в проде, чьё, версии. TODO.")
    with tabs[3]:
        st.subheader("История событий (Audit Trail)")
        st.caption("Фильтры + кнопка «проверить целостность лога» (hash-chain). TODO.")
    with tabs[4]:
        st.subheader("Находки")
        st.caption("По активу и по системе; «Показать причину» (evidence), «FP», «Перезапуск». TODO.")
    with tabs[5]:
        st.subheader("Инструменты / Сканеры")
        st.caption("Что делает каждый инструмент, к какой угрозе привязан, история сканов. TODO.")
    with tabs[6]:
        st.subheader("Деплой / Approve")
        st.caption("Для Tier=HIGH — Approve (только MLSecOps); откат/retire. TODO.")
    with tabs[7]:
        st.subheader("Доступы (админка)")
        st.caption("Регистрация пользователей, роли, доступ к датасетам, data_export. MLSecOps. TODO.")
    with tabs[8]:
        st.subheader("Дашборд / Мониторинг")
        st.caption("Runtime-метрики, дрейф (PSI), всплески 429, статус защищённости; CEO read-only. TODO.")


if st:
    render()
