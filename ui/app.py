"""
Streamlit UI — видимость платформы.

Вкладки:
  🪪 Паспорт   — интерактивный model_card (G0): форма + свои поля + валидация + регистрация.
  📜 События   — единый Audit Trail (таблица events, hash-chain).
  📦 Датасеты  — реестр датасетов и их статус (available / quarantine).
  🚨 Находки   — сработки гейтов; для заблокированных видна ПРИЧИНА (JSON-отчёт)
                 — это отработка False Positives (боль MLOps).
"""
import sys
from pathlib import Path

import pandas as pd
import streamlit as st
import yaml

# импорт пакета core при локальном запуске
sys.path.append(str(Path(__file__).resolve().parents[1]))
from core.db import (  # noqa: E402
    fetch_events, fetch_datasets, fetch_findings, fetch_models,
    register_model, log_event, verify_chain,
)
from core.model_card import validate_card  # noqa: E402

st.set_page_config(page_title="MLSecOps", page_icon="🛡️", layout="wide")
st.title("🛡️ MLSecOps — видимость системы")


# --- боковая панель ---
with st.sidebar:
    st.header("Действия")
    if st.button("➕ Тестовое событие", use_container_width=True):
        try:
            new_id = log_event("demo_user", "MLSecOps", "test_event",
                               asset="demo-asset", result="ok",
                               details={"note": "проверка контура UI -> БД"})
            st.success(f"Записано событие #{new_id}")
        except Exception as e:  # noqa: BLE001
            st.error(f"Ошибка записи: {e}")
    st.divider()
    if st.button("🔐 Проверить целостность лога", use_container_width=True):
        try:
            ok, bad_id = verify_chain()
            st.success("Hash-chain цел ✅") if ok else \
                st.error(f"⚠️ Цепочка нарушена на #{bad_id} — лог подделан!")
        except Exception as e:  # noqa: BLE001
            st.error(f"Ошибка проверки: {e}")


def _color(val: str) -> str:
    return {
        "ok": "background-color:#eafaf1", "available": "background-color:#eafaf1",
        "blocked": "background-color:#fdecea", "quarantine": "background-color:#fdecea",
        "pending": "background-color:#fef5e7", "error": "background-color:#fdecea",
    }.get(val, "")


def _guard(fetch):
    """Обёртка: ловит ошибку подключения к БД и показывает подсказку."""
    try:
        return fetch(), None
    except Exception as e:  # noqa: BLE001
        return None, str(e)


tab_card, tab_events, tab_datasets, tab_findings = st.tabs(
    ["🪪 Паспорт модели", "📜 События", "📦 Датасеты", "🚨 Находки"]
)

# ===================== ПАСПОРТ МОДЕЛИ (G0) =====================
with tab_card:
    st.subheader("Паспорт модели — G0 Onboarding")
    st.caption("Заполни обязательные поля, при необходимости добавь свои. "
               "Без валидного паспорта модель не регистрируется (анти-Shadow-AI).")

    # хранилище кастомных полей в сессии
    if "extra_fields" not in st.session_state:
        st.session_state.extra_fields = []  # список [key, value]

    c1, c2 = st.columns(2)
    with c1:
        f_name = st.text_input("name *", placeholder="credit_scoring")
        f_owner = st.text_input("owner *", placeholder="ivanov@bank.ru")
        f_data = st.text_input("data_source *", placeholder="scoring_train:v1")
    with c2:
        f_version = st.text_input("version *", placeholder="v1")
        f_tier = st.selectbox("tier *", ["LOW", "MED", "HIGH"], index=2)
        f_framework = st.text_input("framework", placeholder="catboost / onnx")
    f_purpose = st.text_area("purpose *", placeholder="Оценка кредитного риска заявителя")

    # --- интерактивные дополнительные поля ---
    st.markdown("**Дополнительные поля** (extra)")
    bc1, bc2 = st.columns([1, 1])
    if bc1.button("➕ Добавить поле"):
        st.session_state.extra_fields.append(["", ""])
    if bc2.button("➖ Удалить последнее") and st.session_state.extra_fields:
        st.session_state.extra_fields.pop()

    for i, (k, v) in enumerate(st.session_state.extra_fields):
        kc, vc = st.columns(2)
        st.session_state.extra_fields[i][0] = kc.text_input(
            f"ключ #{i + 1}", value=k, key=f"ek{i}")
        st.session_state.extra_fields[i][1] = vc.text_input(
            f"значение #{i + 1}", value=v, key=f"ev{i}")

    # --- сборка карточки ---
    extra = {k: v for k, v in st.session_state.extra_fields if k.strip()}
    card = {
        "name": f_name, "version": f_version, "tier": f_tier,
        "owner": f_owner, "data_source": f_data, "purpose": f_purpose,
    }
    if f_framework.strip():
        card["framework"] = f_framework
    if extra:
        card["extra"] = extra

    st.markdown("**Предпросмотр model_card.yaml**")
    st.code(yaml.safe_dump(card, allow_unicode=True, sort_keys=False), language="yaml")

    a1, a2 = st.columns(2)
    if a1.button("✅ Проверить (G0)", use_container_width=True):
        ok, errors, _ = validate_card(card)
        if ok:
            st.success("G0 PASSED — паспорт валиден ✅")
        else:
            st.error("G0 FAILED — исправь:\n\n- " + "\n- ".join(errors))

    if a2.button("📥 Зарегистрировать модель", use_container_width=True, type="primary"):
        ok, errors, valid = validate_card(card)
        if not ok:
            st.error("Нельзя зарегистрировать — паспорт невалиден:\n\n- " + "\n- ".join(errors))
        else:
            try:
                mid = register_model(valid.model_dump(exclude_none=True),
                                     status="registered")
                log_event("ui_user", "DS", "model_registered",
                          asset=f"{card['name']}:{card['version']}", result="ok",
                          details={"gate": "G0", "tier": card["tier"]})
                st.success(f"Модель зарегистрирована (#{mid}). См. список ниже.")
            except Exception as e:  # noqa: BLE001
                st.error(f"Ошибка регистрации: {e}")

    st.divider()
    st.markdown("**Зарегистрированные модели**")
    models, merr = _guard(lambda: fetch_models(limit=200))
    if merr:
        st.error(f"Нет подключения к БД: {merr}")
    elif not models:
        st.info("Моделей пока нет.")
    else:
        mdf = pd.DataFrame(models)
        st.dataframe(
            mdf[["id", "name", "version", "tier", "owner", "status", "created_at"]]
                .style.map(_color, subset=["status"]),
            use_container_width=True, height=240,
        )

# ============================ СОБЫТИЯ ============================
with tab_events:
    events, err = _guard(lambda: fetch_events(limit=500))
    if err:
        st.error(f"Нет подключения к БД: {err}")
        st.info("Подними стенд:  docker compose -f infra/docker-compose.yml up")
    elif not events:
        st.info("Событий пока нет. Нажми «Тестовое событие» слева или запусти ingest.")
    else:
        df = pd.DataFrame(events)
        c1, c2 = st.columns(2)
        with c1:
            pa = st.selectbox("Действие", ["(все)"] + sorted(df["action"].dropna().unique()))
        with c2:
            pr = st.selectbox("Результат", ["(все)"] + sorted(df["result"].dropna().unique()))
        view = df.copy()
        if pa != "(все)":
            view = view[view["action"] == pa]
        if pr != "(все)":
            view = view[view["result"] == pr]
        st.dataframe(
            view[["id", "ts", "actor", "role", "action", "asset", "result", "details"]]
                .style.map(_color, subset=["result"]),
            use_container_width=True, height=480,
        )
        st.caption(f"Показано {len(view)} из {len(df)} событий.")

# ============================ ДАТАСЕТЫ ============================
with tab_datasets:
    datasets, err = _guard(lambda: fetch_datasets(limit=200))
    if err:
        st.error(f"Нет подключения к БД: {err}")
    elif not datasets:
        st.info("Датасетов нет. Запусти:  python src/ingest_dataset.py data/datasets/train_clean.csv "
                "--name scoring_train --version v1")
    else:
        df = pd.DataFrame(datasets)
        st.dataframe(
            df[["id", "name", "version", "status", "sha256", "created_by", "created_at"]]
                .style.map(_color, subset=["status"]),
            use_container_width=True, height=420,
        )

# ============================ НАХОДКИ ============================
with tab_findings:
    findings, err = _guard(lambda: fetch_findings(limit=200))
    if err:
        st.error(f"Нет подключения к БД: {err}")
    elif not findings:
        st.success("Открытых находок нет — все проверки чисты.")
    else:
        df = pd.DataFrame(findings)
        st.dataframe(
            df[["id", "ts", "gate", "asset_type", "asset_name", "severity", "rule", "status"]],
            use_container_width=True, height=300,
        )
        st.subheader("Причина блокировки (JSON-отчёт гейта)")
        st.caption("Понимание, что именно сломал безопасник — основа отработки False Positives.")
        labels = {f"#{f['id']} · {f['asset_name']} · {f['rule']}": f for f in findings}
        pick = st.selectbox("Выбери находку", list(labels.keys()))
        st.json(labels[pick]["evidence"])
