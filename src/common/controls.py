"""Каталог контролей безопасности — единый источник «угроза → контроль → тест → покрытие».

Это GRC-обвязка (как «Карта покрытия» у эталонных платформ): каждая угроза привязана к
контролю, каждый контроль — к гейту/слою и к конкретным тестам, и имеет статус:
  - live     — реализован и покрыт тестом (B/C),
  - planned  — инфраструктурный, зона A (Vault/Keycloak/Caddy/PKI/Prometheus),
  - accepted — остаточный риск принят через RiskAcceptance (GRC exception).

Используется в UI (вкладка «Карта покрытия») и может проверяться тестами на консистентность.
ID контролей в стиле SUP-/DATA-/CODE-/RT-/DOS-/ACC-/CRED-/EXF-/MON-/VIS-/GOV-/CI-.
"""
from __future__ import annotations

# layer: build | data | code | runtime | identity | infra | grc
CONTROLS: list[dict] = [
    # ── Supply chain / артефакт модели ──
    {"id": "SUP-01", "title": "Вредоносный артефакт модели", "threats": ["#3"],
     "gate": "G4", "layer": "build", "status": "live",
     "tests": ["model_gate.weights_scan", "ci:model-gate bad-fixture"],
     "std": {"ATLAS": "AML.T0010.003", "OWASP": "ML06", "NIST": "MANAGE-2.2", "FSTEC": "СП.1"}},
    {"id": "SUP-07", "title": "Небезопасный формат критичной модели", "threats": ["#3"],
     "gate": "G4", "layer": "build", "status": "live",
     "tests": ["model_gate.weights_format", "demo:model_unsafe.pkl→FAIL"],
     "std": {"ATLAS": "AML.T0010", "OWASP": "ML06", "NIST": "MANAGE-2.2", "FSTEC": "СП.1-2"}},
    {"id": "SUP-03", "title": "Уязвимая зависимость (CVE)", "threats": ["#8"],
     "gate": "G2", "layer": "build", "status": "live",
     "tests": ["code_gate.cve_deps (pip-audit)", "ci:code-gate"],
     "std": {"ATLAS": "AML.T0016", "OWASP": "ML06", "NIST": "MANAGE-2.1", "FSTEC": "СП.1"}},
    {"id": "SUP-04", "title": "Подмена артефакта перед деплоем", "threats": ["#4"],
     "gate": "G4", "layer": "build", "status": "live",
     "tests": ["model_gate.integrity_sha256", "monitor.check_model_substitution"],
     "std": {"ATLAS": "AML.T0010", "OWASP": "ML06", "NIST": "MANAGE-2.2", "FSTEC": "УБИ.222"}},
    {"id": "SUP-09", "title": "Typosquatting зависимостей", "threats": ["#9"],
     "gate": "G3", "layer": "build", "status": "live",
     "tests": ["dependency_gate.name_allowlist", "demo:pytirch→FAIL"],
     "std": {"ATLAS": "AML.T0010.003", "OWASP": "ML06", "NIST": "MANAGE-2.1", "FSTEC": "СП.1-2"}},
    {"id": "SIG-01", "title": "Подпись артефакта/образа перед прод", "threats": ["#26"],
     "gate": "G4", "layer": "build", "status": "live",
     "tests": ["model_gate.signature_cosign", "deploy.yml:cosign sign+verify"],
     "std": {"ATLAS": "—", "OWASP": "ML06", "NIST": "MANAGE-2.2", "FSTEC": "СП.2"}},
    # ── Данные ──
    {"id": "DATA-01", "title": "Недоверенный источник / отравление данных", "threats": ["#1"],
     "gate": "G1", "layer": "data", "status": "live",
     "tests": ["data_gate.class_balance", "ci:data-gate poisoned→FAIL"],
     "std": {"ATLAS": "AML.T0020", "OWASP": "ML02", "NIST": "MAP-2.3", "FSTEC": "УБИ.221"}},
    {"id": "DATA-02", "title": "Утечка ПДн в обучающей выборке", "threats": ["#2"],
     "gate": "G1", "layer": "data", "status": "live",
     "tests": ["data_gate.pii", "demo:email-колонка→FAIL"],
     "std": {"ATLAS": "—", "OWASP": "ML03", "NIST": "GOVERN-1.1", "FSTEC": "152-ФЗ"}},
    {"id": "DATA-03", "title": "Indirect prompt injection (RAG)", "threats": ["#15"],
     "gate": "G1", "layer": "data", "status": "planned",
     "tests": ["data_gate.prompt_injection (частично)"],
     "std": {"ATLAS": "AML.T0051", "OWASP": "LLM01", "NIST": "MAP-1.1", "FSTEC": "СП.2"}},
    # ── Код ──
    {"id": "CODE-01", "title": "Небезопасный паттерн в коде (SAST)", "threats": ["#10"],
     "gate": "G2", "layer": "code", "status": "live",
     "tests": ["code_gate.sast (bandit/semgrep)", "demo:shell=True→FAIL"],
     "std": {"ATLAS": "—", "OWASP": "ML06", "NIST": "MANAGE-2.1", "FSTEC": "СП.4"}},
    {"id": "ACC-06", "title": "Утёкший секрет в коде", "threats": ["#10"],
     "gate": "G2", "layer": "code", "status": "live",
     "tests": ["code_gate.secrets (gitleaks)", "demo:leaky.py→FAIL"],
     "std": {"ATLAS": "—", "OWASP": "ML06", "NIST": "GOVERN-1.2", "FSTEC": "СП.4"}},
    {"id": "CI-01", "title": "Отравленный коммит / шаг пайплайна", "threats": ["#4"],
     "gate": "G2", "layer": "code", "status": "live",
     "tests": ["ci:G2 первым шагом перед обучением", "train.yml порядок"],
     "std": {"ATLAS": "AML.T0016", "OWASP": "ML06", "NIST": "MANAGE-2.1", "FSTEC": "СП.1"}},
    {"id": "GOV-01", "title": "Shadow AI / нет паспорта-lineage", "threats": ["#20", "#23"],
     "gate": "G5", "layer": "code", "status": "live",
     "tests": ["registry_gate.card_completeness", "registry_gate.lineage"],
     "std": {"ATLAS": "—", "OWASP": "ML08", "NIST": "GOVERN-1.1", "FSTEC": "ГОСТ Р 71539"}},
    {"id": "SKEW-01", "title": "Training-serving skew", "threats": ["#19"],
     "gate": "G4", "layer": "code", "status": "live",
     "tests": ["tests/test_consistency.py (21)", "train.yml consistency step"],
     "std": {"ATLAS": "—", "OWASP": "ML09", "NIST": "MEASURE-2.3", "FSTEC": "—"}},
    # ── Identity / доступ (часть — зона A, infra) ──
    {"id": "ACC-01", "title": "Действие вне роли / IDOR", "threats": ["#22"],
     "gate": "G0", "layer": "identity", "status": "planned",
     "tests": ["RBAC require_role (UI demo: 403)", "zero-trust object-level (A)"],
     "std": {"ATLAS": "—", "OWASP": "ML08", "NIST": "GOVERN-2.1", "FSTEC": "УПД"}},
    {"id": "CRED-01", "title": "Невалидный/поддельный токен", "threats": ["#22"],
     "gate": "G0", "layer": "identity", "status": "planned",
     "tests": ["OIDC fail-closed (Keycloak — зона A)"],
     "std": {"ATLAS": "—", "OWASP": "ML08", "NIST": "GOVERN-2.1", "FSTEC": "ИАФ"}},
    {"id": "GATE-01", "title": "Gated promotion критичной модели (HITL)", "threats": ["#25"],
     "gate": "G6", "layer": "grc", "status": "live",
     "tests": ["UI Approve (только MLSecOps)", "deploy.yml HITL-gate"],
     "std": {"ATLAS": "—", "OWASP": "ML08", "NIST": "GOVERN-1.1", "FSTEC": "—"}},
    # ── Runtime ──
    {"id": "RT-01", "title": "Extraction модели в рантайме", "threats": ["#5"],
     "gate": "G7", "layer": "runtime", "status": "live",
     "tests": ["serve rate-limit→429", "attack_sim.py"],
     "std": {"ATLAS": "AML.T0024", "OWASP": "ML05", "NIST": "MANAGE-2.3", "FSTEC": "УБИ.218"}},
    {"id": "RT-03", "title": "Output-reduction (анти-инверсия)", "threats": ["#13"],
     "gate": "G7", "layer": "runtime", "status": "live",
     "tests": ["serve.reduce_output (decision вместо proba)"],
     "std": {"ATLAS": "AML.T0024", "OWASP": "ML05", "NIST": "MANAGE-2.3", "FSTEC": "УБИ.219"}},
    {"id": "RT-05", "title": "Валидация входа (evasion)", "threats": ["#11", "#6"],
     "gate": "G7", "layer": "runtime", "status": "live",
     "tests": ["serve Pydantic→422", "serve payload-limit→413"],
     "std": {"ATLAS": "AML.T0015", "OWASP": "ML01", "NIST": "MEASURE-2.5", "FSTEC": "УБИ.220"}},
    {"id": "RT-02", "title": "OOD / adversarial вход", "threats": ["#11"],
     "gate": "G7", "layer": "runtime", "status": "live",
     "tests": ["serve.ood_check → suspect + Finding"],
     "std": {"ATLAS": "AML.T0043", "OWASP": "ML01", "NIST": "MEASURE-2.7", "FSTEC": "УБИ.220"}},
    {"id": "DLP-01", "title": "Утечка ПДн в логах инференса", "threats": ["#12"],
     "gate": "G7", "layer": "runtime", "status": "live",
     "tests": ["serve dlp_mask / audit.log_feature"],
     "std": {"ATLAS": "—", "OWASP": "ML03", "NIST": "GOVERN-1.1", "FSTEC": "152-ФЗ"}},
    {"id": "DOS-01", "title": "Распределённый флуд (load-shedding)", "threats": ["#6"],
     "gate": "G7", "layer": "runtime", "status": "live",
     "tests": ["serve global-semaphore→503"],
     "std": {"ATLAS": "—", "OWASP": "ML04", "NIST": "MANAGE-2.3", "FSTEC": "СП.7"}},
    {"id": "DOW-01", "title": "Исчерпание бюджета (cost/token quota)", "threats": ["#21"],
     "gate": "G7", "layer": "runtime", "status": "live",
     "tests": ["serve cost-quota→429"],
     "std": {"ATLAS": "—", "OWASP": "LLM10", "NIST": "MANAGE-2.3", "FSTEC": "СП.7"}},
    {"id": "MON-01", "title": "Дрейф данных", "threats": ["#14"],
     "gate": "G6", "layer": "runtime", "status": "live",
     "tests": ["monitor.compute_psi (PSI>0.25)", "demo:prod_traffic_drifted"],
     "std": {"ATLAS": "—", "OWASP": "ML09", "NIST": "MEASURE-2.4", "FSTEC": "—"}},
    {"id": "MON-03", "title": "Вывод из эксплуатации (decommission)", "threats": ["#25"],
     "gate": "G6", "layer": "runtime", "status": "live",
     "tests": ["UI retire (MLSecOps) → снятие alias"],
     "std": {"ATLAS": "—", "OWASP": "ML08", "NIST": "GOVERN-1.1", "FSTEC": "—"}},
    {"id": "EXF-01", "title": "Инсайдерская эксфильтрация", "threats": ["#12", "#5"],
     "gate": "G7", "layer": "runtime", "status": "planned",
     "tests": ["детект объёма выгрузки (план)", "data_export RBAC"],
     "std": {"ATLAS": "AML.T0024", "OWASP": "ML05", "NIST": "MANAGE-2.3", "FSTEC": "УБИ.218"}},
    {"id": "NET-01", "title": "Сетевая сегментация (per-service creds)", "threats": ["#22"],
     "gate": "G7", "layer": "infra", "status": "planned",
     "tests": ["serving→MLflow/MinIO по отдельным кредам (зона A/infra)"],
     "std": {"ATLAS": "—", "OWASP": "ML08", "NIST": "GOVERN-1.2", "FSTEC": "ЗСВ"}},
    # ── Сквозные ──
    {"id": "VIS-02", "title": "Триаж сработок / фолзы (False Positive)", "threats": ["#24"],
     "gate": "—", "layer": "grc", "status": "live",
     "tests": ["UI Находки: причина/FP/перезапуск"],
     "std": {"ATLAS": "—", "OWASP": "ML08", "NIST": "MEASURE-3.1", "FSTEC": "—"}},
    {"id": "AUD-01", "title": "Целостность Audit Trail (hash-chain)", "threats": ["#24"],
     "gate": "—", "layer": "grc", "status": "live",
     "tests": ["db.verify_chain", "UI: проверка цепочки хешей"],
     "std": {"ATLAS": "T1070", "OWASP": "ML08", "NIST": "GOVERN-1.2", "FSTEC": "РСБ"}},
]

# Принятые остаточные риски (GRC exception). В реале — таблица в БД (A); тут демо-сид.
RISK_ACCEPTED: dict[str, dict] = {}


def set_accepted(control_id: str, who: str, reason: str) -> None:
    RISK_ACCEPTED[control_id] = {"by": who, "reason": reason}


def effective_status(c: dict) -> str:
    return "accepted" if c["id"] in RISK_ACCEPTED else c["status"]


def coverage() -> dict:
    """Сводка покрытия: всего/live/accepted/planned + процент закрытия."""
    total = len(CONTROLS)
    live = sum(1 for c in CONTROLS if effective_status(c) == "live")
    accepted = sum(1 for c in CONTROLS if effective_status(c) == "accepted")
    planned = total - live - accepted
    closed = live + accepted  # accepted считаем закрытым (риск осознанно принят)
    return {"total": total, "live": live, "accepted": accepted, "planned": planned,
            "closed": closed, "pct": round(closed / total * 100) if total else 0}


def by_layer() -> dict:
    out: dict[str, list] = {}
    for c in CONTROLS:
        out.setdefault(c["layer"], []).append(c)
    return out
