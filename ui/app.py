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

        check_type = st.selectbox(
            "Тип проверки (Gate)",
            ["data_gate", "code_gate", "dependency_gate"],
        )

        if check_type == "data_gate":
            target = st.selectbox("Датасет", [
                "data/train_m1_clean.csv",
                "data/train_m1_poisoned.csv",
                "data/prod_traffic_drifted.csv",
            ])
        else:
            target = "."
            st.info("Проверка будет запущена на всём репозитории")

        if st.button("Запустить проверку в CI"):
            if _http is None:
                st.error("Библиотека requests не установлена")
            else:
                try:
                    resp = _http.post(
                        f"{API}/api/v1/ci/trigger",
                        json={"check_type": check_type, "target": target},
                        timeout=10,
                    )
                    data = resp.json()
                    if data.get("status") == "ok":
                        st.success("Workflow запущен!")
                        repo = data.get("repo", "")
                        if repo:
                            st.markdown(
                                f"[Открыть GitHub Actions](https://github.com/{repo}/actions)")
                    else:
                        st.error(f"Ошибка: {data.get('detail', resp.text)}")
                except Exception as e:
                    st.error(f"Не удалось подключиться к бэкенду: {e}")

        st.divider()
        st.subheader("Загрузить CSV для проверки")
        uploaded = st.file_uploader("Выберите CSV-файл", type=["csv"])
        if uploaded is not None and st.button("Загрузить на сервер"):
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
                        st.success(
                            f"Файл загружен: {data['filename']} ({data['size']} байт)")
                    else:
                        st.error(f"Ошибка: {data.get('detail', '')}")
                except Exception as e:
                    st.error(f"Ошибка загрузки: {e}")
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
