"""Streamlit UI — MLSecOps Platform.

Вкладки (docs/14_FRONTEND_UI.md):
  Кабинет/Верификация · Паспорт модели · Реестр · История событий ·
  Находки · Инструменты/Сканеры · Деплой/Approve · Доступы · Дашборд

Роль: из X-Authenticated-User (сервер) или demo-переключатель при APP_DEBUG.
API: вызовы к Gatekeeper (GATEKEEPER_URL); при недоступности — моки.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone

try:
    import streamlit as st
    import requests
    _HAS_STREAMLIT = True
except Exception:
    _HAS_STREAMLIT = False
    st = None  # type: ignore

API = os.getenv("GATEKEEPER_URL", "http://backend:8000")
APP_DEBUG = os.getenv("APP_DEBUG", "true").lower() == "true"

# ── Маппинг инструмент → угрозы ──────────────────────────────────────────── #
TOOL_THREATS = {
    "gitleaks":  {"gate": "G2", "threats": ["#10 Утечка секретов"], "severity": "critical"},
    "bandit":    {"gate": "G2", "threats": ["#8 Уязвимый код (SAST)"], "severity": "high"},
    "pip-audit": {"gate": "G2", "threats": ["#8 CVE зависимостей"], "severity": "critical"},
    "trivy":     {"gate": "G2", "threats": ["#8 CVE в Docker-образе"], "severity": "critical"},
    "modelscan": {"gate": "G4", "threats": ["#3 Pickle/RCE в весах"], "severity": "critical"},
    "cosign":    {"gate": "G4", "threats": ["#26 Отсутствие подписи", "#4 Подмена модели"], "severity": "high"},
    "pandas":    {"gate": "G1", "threats": ["#1 Data Poisoning", "#2 PII в данных"], "severity": "high"},
    "pydantic":  {"gate": "G7", "threats": ["#6 DoS/большой payload", "#11 Evasion"], "severity": "medium"},
    "redis":     {"gate": "G7", "threats": ["#5 Model Extraction", "#6 DoS"], "severity": "high"},
    "evidently": {"gate": "G6", "threats": ["#14 Data Drift"], "severity": "medium"},
}


# ── Mock-данные для демо без Backend A ───────────────────────────────────── #
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


MOCK_MODELS = [
    {"name": "credit_scoring", "version": "1.0.0", "owner": "ds-team@example.com",
     "tier": "HIGH", "status": "candidate", "trained_in_ci": True,
     "sha256": "1b5e53e0b230e196...", "dataset": "train_m1_clean@v1",
     "git_sha": "a1b2c3d4", "run_id": "local-run-001"},
    {"name": "text_classifier", "version": "1.0.0", "owner": "ds-team@example.com",
     "tier": "MED", "status": "available", "trained_in_ci": True,
     "sha256": "abc123def456...", "dataset": "synthetic_text@v1",
     "git_sha": "a1b2c3d4", "run_id": "local-run-002"},
    {"name": "transaction_risk", "version": "1.0.0", "owner": "ds-team@example.com",
     "tier": "HIGH", "status": "pending_hitl", "trained_in_ci": True,
     "sha256": "deadbeef1234...", "dataset": "train_m1_clean@v1",
     "git_sha": "a1b2c3d4", "run_id": "local-run-003"},
]

MOCK_EVENTS = [
    {"id": 1, "ts": _now(), "type": "dataset_ingested", "actor": "ds@example.com",
     "asset": "train_m1_clean@v1", "result": "ok", "detail": "G1 PASS"},
    {"id": 2, "ts": _now(), "type": "gate_run", "actor": "ci-runner",
     "asset": "credit_scoring@1.0.0", "result": "ok", "detail": "G2 PASS: no secrets"},
    {"id": 3, "ts": _now(), "type": "gate_run", "actor": "ci-runner",
     "asset": "credit_scoring@1.0.0", "result": "ok", "detail": "G4 PASS: format=onnx"},
    {"id": 4, "ts": _now(), "type": "model_registered", "actor": "ci-runner",
     "asset": "credit_scoring@1.0.0", "result": "ok", "detail": "alias=candidate"},
    {"id": 5, "ts": _now(), "type": "dataset_blocked", "actor": "ci-runner",
     "asset": "train_m1_poisoned@v1", "result": "blocked",
     "detail": "G1 FAIL: class_balance + pii"},
    {"id": 6, "ts": _now(), "type": "deploy_requested", "actor": "ds@example.com",
     "asset": "transaction_risk@1.0.0", "result": "pending",
     "detail": "Tier=HIGH — ожидает HITL Approve"},
    {"id": 7, "ts": _now(), "type": "access_denied", "actor": "ds@example.com",
     "asset": "transaction_risk@1.0.0", "result": "error",
     "detail": "403: DS не может делать Approve (требуется MLSecOps)"},
]

MOCK_FINDINGS = [
    {"id": 1, "gate": "G1", "check": "pii", "severity": "high", "status": "open",
     "asset": "train_m1_poisoned@v1", "ts": _now(),
     "detail": "Найдено ПДн: email (3 примера)",
     "evidence": {"types": ["email"], "samples": {"email": ["user0@example.com", "user1@example.com"]}}},
    {"id": 2, "gate": "G1", "check": "class_balance", "severity": "high", "status": "open",
     "asset": "train_m1_poisoned@v1", "ts": _now(),
     "detail": "АНОМАЛИЯ: класс меньшинства = 49.6% (порог 30%)",
     "evidence": {"minority_rate": 0.496, "distribution": {"0": 0.504, "1": 0.496}}},
    {"id": 3, "gate": "G2", "check": "secrets", "severity": "critical", "status": "closed",
     "asset": "demo/insecure@pr-42", "ts": _now(),
     "detail": "Найден API_KEY в leaky.py",
     "evidence": {"findings": [{"rule": "generic-api-key", "file": "leaky.py", "line": 13}]}},
    {"id": 4, "gate": "G2", "check": "sast", "severity": "high", "status": "fp",
     "asset": "src/train@pr-41", "ts": _now(),
     "detail": "B602 subprocess shell=True (False Positive: демо-фикстура)",
     "evidence": {"high_issues": [{"test": "subprocess_popen_with_shell_equals_true",
                                    "file": "demo/insecure/leaky.py", "line": 27}]},
     "fp_reason": "Намеренная SAST-приманка в demo/, не в прод-коде"},
    {"id": 5, "gate": "G3", "check": "name_allowlist", "severity": "critical", "status": "open",
     "asset": "demo/insecure/requirements_vuln.txt", "ts": _now(),
     "detail": "Typosquatting: pytirch, tenserflew",
     "evidence": {"typosquats": ["pytirch", "tenserflew"]}},
    {"id": 6, "gate": "G4", "check": "weights_format", "severity": "critical", "status": "open",
     "asset": "external_model_unsafe.pkl", "ts": _now(),
     "detail": "Запрещённый формат .pkl (исполняет код при load)",
     "evidence": {"ext": ".pkl", "blocked_ext": [".pkl", ".joblib", ".pt"]}},
]


# ── Helpers ───────────────────────────────────────────────────────────────── #
def _api_get(path: str, mock: object = None) -> object:
    try:
        r = requests.get(f"{API}{path}", timeout=3)
        if r.ok:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return mock


def _api_post(path: str, data: dict, mock: object = None) -> object:
    try:
        r = requests.post(f"{API}{path}", json=data, timeout=10)
        if r.ok:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return mock


def _role() -> str:
    return st.session_state.get("role", "DS")


def _badge(status: str) -> str:
    colors = {"ok": "🟢", "available": "🟢", "prod": "🟢",
              "blocked": "🔴", "fail": "🔴", "open": "🔴",
              "pending": "🟡", "pending_hitl": "🟡", "candidate": "🔵",
              "error": "🔴", "fp": "⚪", "closed": "✅"}
    return colors.get(status.lower(), "⬜") + " " + status


def _tier_badge(tier: str) -> str:
    return {"HIGH": "🔴 HIGH", "MED": "🟡 MED", "LOW": "🟢 LOW"}.get(tier, tier)


# ── Tab renderers ─────────────────────────────────────────────────────────── #

def tab_verify():
    st.subheader("Отправить ресурс на верификацию / сканирование")
    with st.form("verify_form"):
        col1, col2 = st.columns(2)
        with col1:
            model_names = [m["name"] for m in MOCK_MODELS]
            model = st.selectbox("Модель", model_names)
            version = st.text_input("Версия", "1.0.0")
        with col2:
            git_sha = st.text_input("Git SHA", "a1b2c3d4e5f6")
            dataset = st.text_input("Датасет@версия", "train_m1_clean@v1")
        reason = st.text_area("Причина запроса (обязательно)", height=80)
        scan_all = st.checkbox("Запустить ВСЕ применимые гейты", value=True)
        submitted = st.form_submit_button("🔍 Запустить верификацию")

    if submitted:
        if not reason.strip():
            st.error("Причина обязательна (записывается в Audit Trail)")
        else:
            st.info(f"Отправляем на верификацию: {model}@{version} …")
            # Mock progress: имитируем прогон гейтов
            progress = st.progress(0, "Запуск …")
            gate_results = []
            gates = [("G5 Registry", True), ("G2 Code Gate (ci)", True),
                     ("G3 Dependency", True), ("G4 Model Gate", True)]
            for i, (gate_name, passed) in enumerate(gates):
                time.sleep(0.3)
                progress.progress((i + 1) / len(gates), f"{gate_name} …")
                gate_results.append((gate_name, passed))

            progress.empty()
            st.success("Верификация завершена")
            for name, passed in gate_results:
                if passed:
                    st.markdown(f"✅ **{name}** — PASS")
                else:
                    st.markdown(f"❌ **{name}** — FAIL")

            # Реальный вызов API (или mock)
            resp = _api_post("/api/v1/verify", {
                "model_name": model, "version": version,
                "git_sha": git_sha, "dataset": dataset, "reason": reason,
            }, mock={"status": "ok", "gate_results": gate_results})
            if resp:
                st.json(resp)


def tab_passport():
    st.subheader("Паспорт модели (G0 Onboarding Gate)")
    model_names = [m["name"] for m in MOCK_MODELS]
    selected = st.selectbox("Выберите модель", model_names, key="passport_model")
    m = next((x for x in MOCK_MODELS if x["name"] == selected), MOCK_MODELS[0])

    col1, col2, col3 = st.columns(3)
    col1.metric("Владелец", m["owner"])
    col2.metric("Tier", _tier_badge(m["tier"]))
    col3.metric("Статус", _badge(m["status"]))

    st.divider()
    col4, col5 = st.columns(2)
    with col4:
        st.markdown("**Lineage**")
        st.markdown(f"- Датасет: `{m['dataset']}`")
        st.markdown(f"- Git SHA: `{m['git_sha']}`")
        st.markdown(f"- MLflow run_id: `{m['run_id']}`")
        st.markdown(f"- SHA-256: `{m['sha256']}`")
        trained_ci = "✅ да" if m.get("trained_in_ci") else "❌ нет"
        st.markdown(f"- Обучена в CI: {trained_ci}")
    with col5:
        st.markdown("**История проверок**")
        model_events = [e for e in MOCK_EVENTS if m["name"] in e.get("asset", "")]
        if model_events:
            for ev in model_events[-5:]:
                st.markdown(f"- `{ev['ts'][:16]}` {ev['type']} → {_badge(ev['result'])}")
        else:
            st.caption("Событий нет")

    # История сканов с детализацией
    findings = [f for f in MOCK_FINDINGS if m["name"] in f.get("asset", "")]
    if findings:
        st.divider()
        st.markdown("**Связанные находки**")
        for f in findings:
            with st.expander(f"[{f['gate']}] {f['check']} — {f['severity']} ({_badge(f['status'])})"):
                st.markdown(f"**{f['detail']}**")
                st.json(f["evidence"])


def tab_registry():
    st.subheader("Реестр моделей и датасетов")
    # Фильтры
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_status = st.multiselect("Статус", ["available", "candidate", "prod", "pending_hitl",
                                                   "blocked"], default=[])
    with col2:
        filter_tier = st.multiselect("Tier", ["HIGH", "MED", "LOW"], default=[])
    with col3:
        filter_owner = st.text_input("Owner (поиск)")

    models = _api_get("/api/v1/models", mock=MOCK_MODELS) or MOCK_MODELS

    # Фильтрация
    if filter_status:
        models = [m for m in models if m.get("status") in filter_status]
    if filter_tier:
        models = [m for m in models if m.get("tier") in filter_tier]
    if filter_owner:
        models = [m for m in models if filter_owner.lower() in m.get("owner", "").lower()]

    if not models:
        st.info("Нет моделей, соответствующих фильтрам")
        return

    st.markdown(f"Показано: **{len(models)}** моделей")
    for m in models:
        with st.expander(f"📦 **{m['name']}** v{m['version']}  ·  {_tier_badge(m['tier'])}  ·  {_badge(m['status'])}"):
            cols = st.columns(4)
            cols[0].markdown(f"**Owner:** {m.get('owner', '?')}")
            cols[1].markdown(f"**Dataset:** {m.get('dataset', '?')}")
            cols[2].markdown(f"**SHA-256:** `{m.get('sha256', '?')[:12]}…`")
            cols[3].markdown(f"**CI:** {'✅' if m.get('trained_in_ci') else '❌'}")
            st.markdown(f"Git: `{m.get('git_sha', '?')}`  Run: `{m.get('run_id', '?')}`")


def tab_events():
    st.subheader("История событий (Audit Trail)")

    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🔗 Проверить целостность лога"):
            resp = _api_get("/api/v1/events/verify_chain",
                            mock={"ok": True, "verified": 7, "broken_at": None})
            if resp and resp.get("ok"):
                st.success(f"Цепочка хешей валидна ({resp.get('verified', '?')} событий)")
            else:
                st.error(f"Разрыв цепочки! Позиция: {resp.get('broken_at', '?')}")

    events = _api_get("/api/v1/events", mock=MOCK_EVENTS) or MOCK_EVENTS

    # Фильтры
    with col1:
        f_asset = st.text_input("Фильтр по активу")

    if f_asset:
        events = [e for e in events if f_asset.lower() in e.get("asset", "").lower()]

    result_colors = {"ok": "🟢", "blocked": "🔴", "error": "🔴", "pending": "🟡"}
    for ev in reversed(events):
        icon = result_colors.get(ev["result"], "⬜")
        with st.expander(f"{icon} `{ev['ts'][:19]}` · **{ev['type']}** · {ev['actor']}"):
            st.markdown(f"**Актив:** {ev['asset']}  |  **Результат:** {_badge(ev['result'])}")
            st.markdown(f"**Детали:** {ev['detail']}")
            st.caption(f"Event ID: {ev['id']}")


def tab_findings():
    st.subheader("Находки (Security Findings)")

    col1, col2, col3 = st.columns(3)
    with col1:
        f_gate = st.multiselect("Гейт", ["G1", "G2", "G3", "G4", "G5", "G6", "G7"])
    with col2:
        f_severity = st.multiselect("Severity", ["critical", "high", "medium", "low"])
    with col3:
        f_status = st.multiselect("Статус", ["open", "closed", "fp"])

    findings = _api_get("/api/v1/findings", mock=MOCK_FINDINGS) or MOCK_FINDINGS
    if f_gate:
        findings = [f for f in findings if f["gate"] in f_gate]
    if f_severity:
        findings = [f for f in findings if f["severity"] in f_severity]
    if f_status:
        findings = [f for f in findings if f["status"] in f_status]

    if not findings:
        st.info("Находок нет")
        return

    sev_icons = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🔵"}
    for f in findings:
        icon = sev_icons.get(f["severity"], "⬜")
        header = f"{icon} [{f['gate']}] **{f['check']}** · {f['severity']} · {_badge(f['status'])}"
        with st.expander(header):
            st.markdown(f"**Актив:** `{f['asset']}`")
            st.markdown(f"**{f['detail']}**")

            # False Positive reason
            if f.get("fp_reason"):
                st.warning(f"⚠ Отмечено как False Positive: {f['fp_reason']}")

            # Показать причину (JSON evidence)
            with st.expander("📋 Показать JSON-evidence (полная причина блока)"):
                st.json(f["evidence"])

            # Угроза
            threat_map = {
                "G1": "#1 Data Poisoning, #2 PII",
                "G2": "#8 CVE, #10 Секреты",
                "G3": "#9 Typosquatting, #3 Источник",
                "G4": "#3 Pickle/RCE, #4 Подмена, #26 Подпись",
                "G5": "#20 Shadow AI, #23 Lineage",
            }
            threat = threat_map.get(f["gate"], "")
            if threat:
                st.caption(f"🎯 Угрозы: {threat}")

            # Кнопки действий (только MLSecOps)
            if _role() == "MLSecOps" and f["status"] == "open":
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    fp_reason = st.text_input("Причина FP", key=f"fp_{f['id']}")
                    if st.button("⚪ Отметить False Positive", key=f"btn_fp_{f['id']}"):
                        if fp_reason:
                            _api_post(f"/api/v1/findings/{f['id']}/fp",
                                      {"reason": fp_reason},
                                      mock={"ok": True})
                            st.success("Отмечено как FP")
                with col_b:
                    if st.button("🔄 Перезапустить проверку", key=f"btn_re_{f['id']}"):
                        _api_post(f"/api/v1/findings/{f['id']}/rerun",
                                  {}, mock={"ok": True, "status": "queued"})
                        st.info("Проверка поставлена в очередь")
                with col_c:
                    if st.button("✅ Закрыть", key=f"btn_cl_{f['id']}"):
                        _api_post(f"/api/v1/findings/{f['id']}/close",
                                  {}, mock={"ok": True})
                        st.success("Закрыто")


def tab_scanners():
    st.subheader("Инструменты / Сканеры")
    st.caption("Каждый инструмент → гейт → угроза из модели угроз")

    for tool, info in TOOL_THREATS.items():
        sev_icon = {"critical": "🚨", "high": "🔴", "medium": "🟡"}.get(info["severity"], "⬜")
        with st.expander(f"{sev_icon} **{tool}** → {info['gate']}"):
            st.markdown(f"**Угрозы:** {', '.join(info['threats'])}")
            st.markdown(f"**Severity:** {info['severity']}")
            # Статистика сканирований (mock)
            mock_stats = {"runs": 42, "findings": len([f for f in MOCK_FINDINGS
                                                        if f["gate"] == info["gate"]]),
                          "last_run": _now()}
            st.metric("Прогонов", mock_stats["runs"])
            st.metric("Находок", mock_stats["findings"])
            st.caption(f"Последний прогон: {mock_stats['last_run'][:16]}")


def tab_deploy():
    st.subheader("Деплой / Approve (Tier=HIGH требует MLSecOps)")

    # Только HIGH-модели, ожидающие деплоя
    deploy_models = [m for m in MOCK_MODELS if m["status"] in ("candidate", "pending_hitl")]

    if not deploy_models:
        st.info("Нет моделей, ожидающих деплоя")
        return

    for m in deploy_models:
        with st.expander(f"📦 **{m['name']}** v{m['version']} · {_tier_badge(m['tier'])} · {_badge(m['status'])}"):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Owner:** {m['owner']}")
                st.markdown(f"**SHA-256:** `{m['sha256']}`")
                st.markdown(f"**Dataset:** `{m['dataset']}`")
                st.markdown(f"**Git SHA:** `{m['git_sha']}`")
            with col2:
                if m["tier"] == "HIGH":
                    st.warning("⚠ Tier=HIGH: требуется ручное подтверждение MLSecOps")
                    if m["status"] == "pending_hitl":
                        st.error("🔴 Ожидает HITL Approve — deploy.yml заблокирован")

            st.divider()
            if _role() == "MLSecOps":
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    approve_reason = st.text_area(
                        "Причина Approve (обязательно)", key=f"apr_{m['name']}", height=80)
                    if st.button(f"✅ Approve Deploy", key=f"btn_approve_{m['name']}"):
                        if not approve_reason.strip():
                            st.error("Причина обязательна")
                        else:
                            resp = _api_post(
                                f"/api/v1/deploy/{m['name']}/{m['version']}/approve",
                                {"reason": approve_reason, "approver": "mlsecops@example.com"},
                                mock={"ok": True, "status": "approved"})
                            st.success(f"Одобрено! deploy.yml запущен: {m['name']}@{m['version']}")
                with col_b:
                    if st.button(f"↩ Откат на предыдущую", key=f"btn_rollback_{m['name']}"):
                        rollback_reason = st.text_input("Причина отката", key=f"rb_{m['name']}")
                        if rollback_reason:
                            _api_post(f"/api/v1/deploy/{m['name']}/rollback",
                                      {"reason": rollback_reason},
                                      mock={"ok": True})
                            st.info("Откат инициирован")
                with col_c:
                    if st.button(f"🗑 Retire (архив)", key=f"btn_retire_{m['name']}"):
                        _api_post(f"/api/v1/models/{m['name']}/{m['version']}/retire",
                                  {}, mock={"ok": True})
                        st.warning("Модель переведена в retire")
            else:
                st.info("⛔ Approve доступен только MLSecOps")
                if st.button(f"→ Попытаться нажать Approve (DS)", key=f"btn_ds_approve_{m['name']}"):
                    st.error("403 Forbidden — у роли DS нет права Approve (запись в Audit Trail: access_denied)")


def tab_admin():
    if _role() != "MLSecOps":
        st.warning("⛔ Доступ только для MLSecOps")
        return
    st.subheader("Доступы (Админка) — только MLSecOps")
    tab_a, tab_b, tab_c = st.tabs(["Пользователи", "Роли", "Доступ к датасетам"])
    with tab_a:
        st.markdown("**Зарегистрированные пользователи:**")
        users = [
            {"email": "ds@example.com", "role": "DS"},
            {"email": "mlsecops@example.com", "role": "MLSecOps"},
            {"email": "ceo@example.com", "role": "CEO"},
        ]
        for u in users:
            st.markdown(f"- `{u['email']}` → **{u['role']}**")
        with st.form("add_user"):
            new_email = st.text_input("Email нового пользователя")
            new_role = st.selectbox("Роль", ["DS", "MLSecOps", "CEO"])
            if st.form_submit_button("Добавить"):
                _api_post("/api/v1/admin/users", {"email": new_email, "role": new_role},
                          mock={"ok": True})
                st.success(f"Пользователь {new_email} добавлен ({new_role})")
    with tab_b:
        st.markdown("**Назначение ролей** — `POST /api/v1/admin/roles`")
    with tab_c:
        st.markdown("**Доступ к датасетам** — `POST /api/v1/admin/dataset_access`")


def tab_dashboard():
    st.subheader("Дашборд / Мониторинг")

    # CEO read-only view
    if _role() == "CEO":
        st.markdown("### 🛡️ Статус защищённости (CEO view)")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Моделей в проде", 1, delta="+1 за неделю")
        col2.metric("Открытых инцидентов", 3, delta="+1", delta_color="inverse")
        col3.metric("Gate PASS rate", "87%", delta="-3%", delta_color="inverse")
        col4.metric("Запросов/мин", "~120", delta="+20%", delta_color="inverse")
        st.success("✅ Основные системы защиты работают штатно")
        st.warning("⚠ 3 находки требуют внимания MLSecOps")
        return

    # Полный дашборд для DS/MLSecOps
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Моделей в реестре", len(MOCK_MODELS))
    col2.metric("Открытых findings", len([f for f in MOCK_FINDINGS if f["status"] == "open"]))
    col3.metric("Events сегодня", len(MOCK_EVENTS))
    col4.metric("Ожидают HITL", len([m for m in MOCK_MODELS if m["status"] == "pending_hitl"]))

    st.divider()

    # PSI / Drift
    st.markdown("### 📊 Мониторинг дрейфа (G6)")
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Population Stability Index (PSI)**")
        mock_psi = {"amount": 8.88, "age": 0.03}
        for col, psi in mock_psi.items():
            color = "🔴" if psi > 0.25 else "🟢"
            st.markdown(f"{color} `{col}`: PSI = **{psi:.2f}** {'← DRIFT!' if psi > 0.25 else '(норма)'}")
        st.error("⚠ DRIFT DETECTED: amount PSI=8.88 > 0.25 (порог)")
        st.caption("Источник: data/prod_traffic_drifted.csv vs train_m1_clean.csv")

    with col_b:
        st.markdown("**Детект подмены модели (G6)**")
        st.success("✓ credit_scoring@1.0.0 — SHA совпадает")
        st.warning("⚠ transaction_risk — не запущен в проде (pending_hitl)")

    st.divider()

    # Rate-limit / Attack traffic
    st.markdown("### 🚦 G7 Runtime метрики")
    mock_stats = {"total_req": 1240, "rate_429": 87, "rate_422": 12, "rate_200": 1141}
    col_r1, col_r2, col_r3 = st.columns(3)
    col_r1.metric("429 (rate-limit)", mock_stats["rate_429"], help="Model Stealing / DoS #5/#6")
    col_r2.metric("422 (validation err)", mock_stats["rate_422"], help="Evasion attempts #11")
    col_r3.metric("200 (OK)", mock_stats["rate_200"])
    pct_429 = mock_stats["rate_429"] / max(mock_stats["total_req"], 1) * 100
    if pct_429 > 5:
        st.warning(f"⚠ {pct_429:.1f}% запросов заблокировано rate-limit — возможная атака (#5/#6)")

    st.divider()
    st.markdown("### 🔒 Gate статистика (последние 24ч)")
    gate_stats = [
        {"gate": "G1", "runs": 12, "pass": 10, "fail": 2},
        {"gate": "G2", "runs": 8,  "pass": 7,  "fail": 1},
        {"gate": "G3", "runs": 8,  "pass": 6,  "fail": 2},
        {"gate": "G4", "runs": 5,  "pass": 5,  "fail": 0},
        {"gate": "G5", "runs": 3,  "pass": 2,  "fail": 1},
    ]
    for g in gate_stats:
        rate = g["pass"] / max(g["runs"], 1) * 100
        bar_icon = "🟢" if rate >= 80 else "🟡" if rate >= 60 else "🔴"
        st.markdown(f"{bar_icon} **{g['gate']}**: {g['runs']} прогонов, "
                    f"{g['pass']} PASS / {g['fail']} FAIL ({rate:.0f}% pass rate)")


# ── Main render ───────────────────────────────────────────────────────────── #

def render():
    st.set_page_config(page_title="MLSecOps Platform", layout="wide", page_icon="🛡️")
    st.title("🛡️ MLSecOps Platform")

    # Role selector (debug) or from auth
    if APP_DEBUG:
        st.sidebar.warning("⚙️ DEBUG: demo-переключатель ролей (выключен в проде)")
        role = st.sidebar.selectbox("Роль (demo)", ["DS", "MLSecOps", "CEO"], index=0)
        st.session_state["role"] = role
        st.sidebar.caption(f"GATEKEEPER: {API}")
    # В проде: роль берётся из X-Authenticated-User (сервер)

    role = _role()
    role_icon = {"DS": "👨‍💻", "MLSecOps": "🔐", "CEO": "👔"}.get(role, "👤")
    st.sidebar.markdown(f"**Роль:** {role_icon} {role}")

    # Вкладки (часть скрыта по роли)
    tab_names = ["🔍 Верификация", "📋 Паспорт", "📦 Реестр",
                 "📜 История", "🚨 Находки", "🛠 Инструменты",
                 "🚀 Деплой / Approve", "👥 Доступы", "📊 Дашборд"]
    tabs = st.tabs(tab_names)

    renderers = [tab_verify, tab_passport, tab_registry, tab_events,
                 tab_findings, tab_scanners, tab_deploy, tab_admin, tab_dashboard]
    for tab, renderer in zip(tabs, renderers):
        with tab:
            try:
                renderer()
            except Exception as e:  # noqa: BLE001
                st.error(f"Ошибка загрузки вкладки: {e}")


if _HAS_STREAMLIT:
    render()
