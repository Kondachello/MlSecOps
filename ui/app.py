"""
Streamlit UI — Шаг 3: единая история событий.

Читает таблицу events из Postgres и показывает её.
Кнопка "тестовое событие" дёргает log_event() — сразу видно, что весь контур
(UI -> log_event -> Postgres -> UI) работает. Дальше сюда добавятся реестр,
находки гейтов и кнопки Approve / False Positive.
"""
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# чтобы импортировать пакет platform при локальном запуске
sys.path.append(str(Path(__file__).resolve().parents[1]))
from core.db import fetch_events, log_event, verify_chain  # noqa: E402

st.set_page_config(page_title="MLSecOps — История событий", page_icon="📜", layout="wide")

st.title("📜 MLSecOps — Единая история событий")
st.caption("Audit Trail: любое действие платформы пишется в таблицу events (hash-chain).")

# --- боковая панель: проверки и тестовое событие ---
with st.sidebar:
    st.header("Действия")

    if st.button("➕ Сгенерировать тестовое событие", use_container_width=True):
        try:
            new_id = log_event(
                actor="demo_user",
                role="MLSecOps",
                action="test_event",
                asset="demo-asset",
                result="ok",
                details={"note": "проверка контура UI -> БД"},
            )
            st.success(f"Записано событие #{new_id}")
        except Exception as e:
            st.error(f"Ошибка записи: {e}")

    st.divider()
    if st.button("🔐 Проверить целостность лога", use_container_width=True):
        try:
            ok, bad_id = verify_chain()
            if ok:
                st.success("Hash-chain цел — историю не подделывали ✅")
            else:
                st.error(f"⚠️ Цепочка нарушена на событии #{bad_id} — лог подделан!")
        except Exception as e:
            st.error(f"Ошибка проверки: {e}")

# --- основная таблица событий ---
try:
    events = fetch_events(limit=500)
except Exception as e:
    st.error(f"Не удалось подключиться к БД: {e}")
    st.info("Убедись, что поднят стенд:  docker compose -f infra/docker-compose.yml up")
    st.stop()

if not events:
    st.info("Событий пока нет. Нажми «Сгенерировать тестовое событие» слева, "
            "чтобы проверить, что контур работает.")
    st.stop()

df = pd.DataFrame(events)

# простые фильтры
c1, c2 = st.columns(2)
with c1:
    actions = ["(все)"] + sorted(df["action"].dropna().unique().tolist())
    pick_action = st.selectbox("Фильтр по действию", actions)
with c2:
    results = ["(все)"] + sorted(df["result"].dropna().unique().tolist())
    pick_result = st.selectbox("Фильтр по результату", results)

view = df.copy()
if pick_action != "(все)":
    view = view[view["action"] == pick_action]
if pick_result != "(все)":
    view = view[view["result"] == pick_result]

# подсветка результата
def _color(val: str) -> str:
    return {
        "ok": "background-color:#eafaf1",
        "blocked": "background-color:#fdecea",
        "pending": "background-color:#fef5e7",
        "error": "background-color:#fdecea",
    }.get(val, "")

st.dataframe(
    view[["id", "ts", "actor", "role", "action", "asset", "result", "details"]]
        .style.map(_color, subset=["result"]),
    use_container_width=True,
    height=520,
)
st.caption(f"Показано {len(view)} из {len(df)} событий.")
