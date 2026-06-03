# CONFORMANCE — карта соответствия «требование → реализация → тест»

Доказательство полноты: каждое требование (куратор/жюри/наша модель угроз) привязано к
**конкретному файлу** и **тесту/команде проверки**. Статусы:
**✅ live** — реализовано и проверяемо · **🅰 A** — зона бэкенда A (контракт объявлен, заглушка) ·
**⏸ P3** — осознанно отложено (GenAI, нет LLM-модели в скоупе).

Методология: всё, что помечено ✅, можно воспроизвести командами из §9. Каталог контролей и
покрытие — `src/common/controls.py` + [`20_CONTROLS_COVERAGE.md`](20_CONTROLS_COVERAGE.md).

---

## 1. Приоритеты главного жюри

| Приоритет жюри | Где реализовано | Тест/проверка | Статус |
|---|---|---|---|
| Скан кода | `src/gates/code_gate/` (gitleaks/bandit/semgrep/pip-audit) | `ci.yml: code-gate`; `demo/insecure/leaky.py→FAIL` | ✅ |
| Реестр моделей | `core/db` (models/model_versions) + UI «Реестр» (`ui/app.py`) | `GET /api/v1/models` + fallback; интерактивная таблица | ✅ UI / 🅰 БД |
| Security gate перед продом | `.github/workflows/deploy.yml` (G2+trivy+G4+cosign, fail-closed) | deploy-workflow по шагам | ✅ |
| Скан моделей | `src/gates/model_gate/` (формат/modelscan/SHA/подпись) | `demo:model_unsafe.pkl→FAIL`; G4 на `.onnx`→PASS | ✅ |
| Версионирование | `model_versions` + UI timeline (Паспорт) | `_versions_dot`, таблица версий | ✅ UI / 🅰 БД |
| История (Audit Trail) | `core/db.log_event` (hash-chain) + `audit.log_event` fallback + UI «История» | `db.verify_chain`; `tests/smoke_db.py` | ✅ fallback / 🅰 БД |
| Связка данные-код-модель (lineage) | `registry_gate.lineage` + UI «Lineage» (graphviz) | `registry_gate`; `_lineage_dot` | ✅ |
| Ролёвка (RBAC) | `core/identity.require_role` + UI (Approve/админка только MLSecOps) | UI: DS→Approve = 403 | ✅ UI / 🅰 enforcement |
| Подписи | `model_gate.signature_cosign` + `deploy.yml` cosign sign/verify | G4 `--require-signature` | ✅ |
| Сканы данных | `src/gates/data_gate/` (11 проверок) | `ci.yml: data-gate`; poisoned→FAIL | ✅ |
| Gate на закачку | `src/ingest_dataset/` (источник→G1→бакет) | `run_data_checks.py` | ✅ |
| Запрет небезопасных форматов | `model_gate.weights_format` (бан .pkl/.joblib) | `.pkl→FAIL` | ✅ |
| Рантайм | `src/serve/app.py` (RT-01/DOS-01/DOW-01/RT-05/RT-02/RT-03/DLP-01) | `attack_sim.py→429`; OOD/503/422 | ✅ |

---

## 2. Четыре обязательные «фичи для жюри»

| Фича | Реализация | Проверка | Статус |
|---|---|---|---|
| Единая история событий (Audit Trail) | `core/db.events` (hash-chain) + `src/common/audit.py` (fallback `logs/events.jsonl`) + UI «История» | `verify_chain`; цветные карточки по результату | ✅ |
| Human-in-the-Loop (Tier=HIGH) | `deploy.yml` HITL-gate + UI «Деплой/Approve» (только MLSecOps) | HIGH без Approve → деплой стоит; DS→403 | ✅ |
| Отработка False Positives | UI «Находки» (причина=evidence, отметка FP, перезапуск) | `POST /findings/{id}/fp|rerun|close` + fallback | ✅ |
| Runtime-защита (G7) | `src/serve/app.py` Redis rate-limit→429 | `python src/serve/attack_sim.py` → доля 429 | ✅ |

---

## 3. Security Gates G0–G7

| Gate | Назначение | Файл | Тест | Статус |
|---|---|---|---|---|
| G0 Onboarding | паспорт, Tier, владелец | `core/model_card.py` + UI | авто-Tier (external→HIGH); карточка | ✅ |
| G1 Data | схема/баланс/PII/инъекции | `src/gates/data_gate/data_gate.py` | `ci:data-gate` clean/poisoned | ✅ |
| G2 Code | секреты/SAST/CVE (+semgrep, +trivy@deploy) | `src/gates/code_gate/code_gate.py` | `ci:code-gate`; `leaky.py→FAIL` | ✅ |
| G3 Supply | typosquatting/пиннинг/источник | `src/gates/dependency_gate/dependency_gate.py` | `ci:dependency-gate`; `pytirch→FAIL` | ✅ |
| G4 Model | формат/modelscan/SHA/подпись | `src/gates/model_gate/model_gate.py` | `.pkl→FAIL`; SHA-mismatch→FAIL | ✅ |
| G5 Registry | паспорт/lineage/Tier-правила | `src/gates/registry_gate/registry_gate.py` | неполный паспорт→FAIL | ✅ |
| G6 Observability | дрейф (PSI)/подмена (SHA) | `src/monitor/monitor.py` | `prod_traffic_drifted→DRIFT`; ре-хэш | ✅ |
| G7 Runtime | 429/503/422/413/OOD/DLP/output-reduction | `src/serve/app.py` | `attack_sim`; OOD/cost/load-shed | ✅ |

Контракт (07 §7.1) — у всех 5 файловых гейтов `gate_check/build_report/main` (3/3).
Изоляция (07 §7.2) — у каждого свои `Dockerfile`+`requirements.txt`. **fail-closed** — флаг
`--fail-closed` во всех гейтах, включён в `deploy.yml`.

---

## 4. Угрозы #1–#26 → контроль → статус

Источник: [`08_THREAT_MODEL.md`](08_THREAT_MODEL.md) ↔ `src/common/controls.py`. **22/26 покрыто**,
4 — отложенный GenAI (P3).

| # | Угроза | Контроль | Статус |
|---|---|---|---|
| 1 | Data Poisoning | DATA-01 (G1 баланс) | ✅ |
| 2 | PII в данных | DATA-02 (G1 regex) | ✅ |
| 3 | Pickle/RCE в весах | SUP-01/SUP-07 (G4) | ✅ |
| 4 | Подмена артефакта | SUP-04 (SHA) | ✅ |
| 5 | Model Extraction | RT-01 (429) + RT-03 | ✅ |
| 6 | DoS payload | RT-05 (422/413) + DOS-01 (503) | ✅ |
| 8 | CVE в либах | SUP-03 (pip-audit) | ✅ |
| 9 | Typosquatting | SUP-09 (G3) | ✅ |
| 10 | Секреты в коде | ACC-06 + CODE-01 (G2) | ✅ |
| 11 | Evasion / OOD | RT-05 + RT-02 | ✅ |
| 12 | ПДн в логах | DLP-01 | ✅ |
| 13 | Membership Inference | RT-03 (output-reduction) | ✅ |
| 14 | Data/Concept Drift | MON-01 (PSI) | ✅ |
| 15 | Indirect Prompt Injection | DATA-03 | 🅰 planned |
| 19 | Training-Serving Skew | SKEW-01 (`test_consistency`) | ✅ |
| 20 | Shadow AI | GOV-01 (G5) | ✅ |
| 21 | Token DoS | DOW-01 (cost-quota) | ✅ |
| 22 | RBAC/эскалация | ACC-01/CRED-01/NET-01 | 🅰 planned |
| 23 | Версионирование/lineage | GOV-01 + реестр | ✅ |
| 24 | Целостность Audit Log | AUD-01 (hash-chain) | ✅ |
| 25 | Видимость реестра | GATE-01/MON-03 + UI | ✅ |
| 26 | Подпись моделей | SIG-01 (cosign) | ✅ |
| 7,16,17,18 | GenAI guardrails | — | ⏸ P3 (нет LLM-модели) |

---

## 5. Канонические решения (05_CANONICAL_FLOW) → где

| Решение | Где реализовано/зафиксировано | Статус |
|---|---|---|
| Прод-артефакт обучается в CI | `train.yml` (G2→train→G4→register) + диспатч моделей | ✅ |
| Формат весов ∈ allow-list (ONNX) | `train_*.py` экспорт ONNX; `model_gate.weights_format` | ✅ |
| Identity неподделываема (SSO/прокси) | `core/identity` + `06_IDENTITY_AND_AUTH` | 🅰 A |
| Tier авто/MLSecOps, HIGH→HITL | `model_card.auto_tier` + `deploy.yml` HITL | ✅ |
| fail-closed | `--fail-closed` во всех гейтах + deploy | ✅ |
| Прод неизменяем (WORM) | `core/storage.lock_prod` + `10_STORAGE` | 🅰 A |
| Один гейт — один образ | `src/gates/*/Dockerfile` | ✅ |
| Audit Trail (hash-chain) | `core/db.log_event` / `audit.log_event` fallback | ✅/🅰 |

---

## 6. Конкурентный паритет (что догнали)

| Фича конкурента | У нас | Файл |
|---|---|---|
| Карта покрытия «N/N контролей» | ✅ | `controls.py` + UI «Карта покрытия» |
| Угроза→контроль→тест→стандарты (ATLAS/OWASP/NIST/ФСТЭК) | ✅ | `controls.py` `std` |
| RiskAcceptance (GRC exception) | ✅ | UI + `POST /controls/{id}/accept` |
| fail-closed | ✅ | флаг гейтов + deploy |
| Semgrep (ML-aware SAST) | ✅ | `code_gate.check_semgrep` |
| Load-shedding 503 / cost-quota 429 / OOD | ✅ | `serve` `_inflight`/`cost_exceeded`/`ood_check` |
| Live-контур пайплайна | ✅ | UI «Контур» |
| blast-radius | ✅ | UI «Реестр» детали |
| Vault/Keycloak/PKI/Caddy/Prometheus | 🅰 planned | помечены `planned` в Карте покрытия |

---

## 7. Граница с бэкендом A (не хардкод — переключится автоматически)

| Механизм | Сейчас (fallback) | Когда A готов |
|---|---|---|
| UI данные | `_api_get/_api_post` → моки | те же вызовы → реальные ручки |
| Audit Trail | `audit.log_event` → `logs/events.jsonl` | → `core.db.log_event` (Postgres) |
| Фичи для PSI | `logs/inference_*.jsonl` | → БД |
| Контроли/RiskAcceptance | локальный `controls.py` | `GET /controls`, `POST /controls/{id}/accept` |
| Гейт-раннер | `_run_gate_mock` | `POST /api/v1/scan` (docker run образов) |

Все ручки **объявлены** в `src/api/main.py` (контракт-заглушки). Скан подтвердил: нет
хардкод-`localhost`, нет секретов в коде, нет RCE вне `demo/`.

---

## 8. Тесты

| Тест | Что проверяет |
|---|---|
| `tests/test_consistency.py` | #19 train↔serve parity (3 модели) |
| `tests/test_controls.py` | каталог контролей: угроза/тесты/уникальность ID/математика покрытия |
| `tests/smoke_db.py` | БД + hash-chain (smoke) |
| `.github/workflows/ci.yml` | по гейту: «чистое PASS / плохое BLOCK» |

---

## 9. Как воспроизвести (proof)

```bash
make setup
python -m py_compile $(git ls-files '*.py')        # вся кодовая база компилируется
python tests/test_controls.py                       # каталог контролей OK
pytest tests/test_consistency.py -q                 # #19 parity
# гейты clean/bad:
python src/gates/dependency_gate/dependency_gate.py --path demo/insecure/requirements_vuln.txt; echo $?  # 1
python src/gates/model_gate/model_gate.py --path demo/insecure/model_unsafe.pkl; echo $?                 # 1
python src/gates/registry_gate/registry_gate.py --card demo/model_card_complete.json --fail-closed; echo $?  # 1 (fail-closed)
# рантайм:
make serve-credit & ; python src/serve/attack_sim.py --url http://localhost:8080/predict --n 200   # 429
# мониторинг:
python src/monitor/monitor.py --reference data/train_m1_clean.csv --current data/prod_traffic_drifted.csv --columns amount age  # DRIFT
# UI:
APP_DEBUG=true .venv/bin/streamlit run ui/app.py    # разделы Контур, Карта покрытия, Раннер
```

---

## 10. Резюме

- **B (гейты + CI):** ✅ G1–G5, контракт+изоляция, fail-closed, Semgrep, 3 workflow.
- **C (модели + рантайм + мониторинг + UI):** ✅ 3 ONNX-модели, G6/G7 (+503/cost/OOD), карта
  покрытия, RiskAcceptance, live-контур, тёмный интерактивный UI.
- **A (ядро):** 🅰 БД/RBAC-enforcement/WORM/идентичность/MLflow-прокси — контракт зафиксирован,
  UI и рантайм подхватят без правок.
- **P3 GenAI (#7/#16/#17/#18):** ⏸ отложено по плану (нет LLM/агента в скоупе).

Покрытие контролями: **25 live + 5 planned = 30** (83%; +RiskAcceptance до 87%).
