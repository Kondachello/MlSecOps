# IMPLEMENTATION PLAN — подробный план реализации для агента

> Читай ПЕРЕД работой: [`00_INDEX.md`](00_INDEX.md) и [`05_CANONICAL_FLOW.md`](05_CANONICAL_FLOW.md)
> (канон). Здесь — что и в каком порядке кодить, с критериями приёмки и Definition of Done.
> Не изобретай новых структур: повторяй паттерн гейтов. **Никаких закладок/RCE/секретов.**

## 0. Принципы исполнения

- **Сначала минимум сквозного флоу, потом расширения.** Не начинай фазу, пока предыдущая не
  даёт рабочий результат.
- **Один гейт — одна папка** `src/gates/<gate>/`: `<gate>.py` + `__init__.py` + `Dockerfile` +
  `requirements.txt`. Единый контракт `gate_check/build_report/main` (exit 0/1). См. [`07_SECURITY_GATES.md`](07_SECURITY_GATES.md).
- **Гейт сам в БД не пишет** — пишет оркестратор (Gatekeeper/ingest), парся stdout-JSON.
- **Graceful degradation:** нет инструмента/сети/БД → `SKIP`, не падать.
- **Каждое действие → `log_event(...)`** (hash-chain). `result ∈ {ok,blocked,pending,error}`.
- **RBAC** на привилегированных действиях (`require_role`). **Личность — серверная** (из прокси).
- **CI:** каждая гейт-джоба = «чистое проходит / плохое блокируется» (фикстуры в `demo/`).
- После изменений: `python -m py_compile <файлы>`, обновить `syntax`-job, держать CI зелёным.
- DoD каждой задачи — см. §«Definition of Done» в конце.

## Definition of Done (для каждой задачи)
1. Код в своей папке, контракт гейта соблюдён. 2. `py_compile` проходит, добавлен/обновлён
CI-job (clean/bad). 3. Действия пишут `findings`+`events`, причина блока видна в UI.
4. RBAC применён к привилегированным действиям. 5. Нет секретов/RCE; demo-«плохое» — в `demo/`.
6. Обновлены релевантные доки. 7. Локальный прогон демо-сценария задачи успешен.

---

## ФАЗА 0 — Инфраструктура и фундамент

**T0.1 docker-compose стенд.** Поднять: Postgres, MinIO, Redis, MLflow (backend=Postgres,
artifact=MinIO bucket `mlflow`), auth-прокси, бэкенд (FastAPI), UI (Streamlit), self-hosted
GitHub Actions runner. Один `docker compose up --build`.
*Приёмка:* все сервисы стартуют; MLflow UI открывается **через прокси**; MinIO доступен.

**T0.2 Схема БД** (`infra/init.sql`) — таблицы из [`09_DATA_MODEL.md`](09_DATA_MODEL.md): `events`,
`datasets`, `verified_datasets`, `models`, `model_versions`, `findings`, `users`, `roles`,
`dataset_access`. Отозвать UPDATE/DELETE на `events` для роли приложения.
*Приёмка:* `tests/smoke_db.py` создаёт записи, `verify_chain()` зелёный.

**T0.3 Audit Trail.** `core/db.log_event()` с hash-chain (`prev_hash`/`row_hash`, genesis) +
`verify_chain()`. Единственная точка записи в `events`.
*Приёмка:* подделка строки руками → `verify_chain()` находит разрыв (демо #24).

**T0.4 Хранилище.** `core/storage.py`: бакеты `datasets/quarantine/models`, upload/download,
`available()`, `lock_prod()` (MinIO Object Lock/WORM на `prod/*`).
*Приёмка:* объект под `prod/*` нельзя перезаписать/удалить.

**T0.5 MinIO seed + демо-данные.** `data/make_datasets.py`: чистые датасеты + приманки
(`*_poisoned.csv` с дисбалансом и PII; `prod_traffic_drifted.csv`).

---

## ФАЗА 1 — Identity, RBAC, реестр (фундамент безопасности)

**T1.1 Auth-прокси + identity.** MLflow за прокси; `core/identity.py`: `current_user(request)`
из `X-Authenticated-User` (серверный штамп), `require_role(role)`. Per-user токены для MLflow-SDK.
*Приёмка:* запрос без валидного токена в MLflow отклонён; личность нельзя подменить клиентом.

**T1.2 Bootstrap + demo-режимы.** Сид первого MLSecOps (из `.env`). UI demo-переключатель
ролей за `APP_DEBUG`. В боевом конфиге — роль только из аутентификации.
*Приёмка:* при `APP_DEBUG=false` переключатель скрыт; роль берётся из auth.

**T1.3 RBAC-хелперы и админка.** `core/db`: `grant_access`, `assign_role`, `register_user`.
Эндпоинты `/api/v1/admin/*` (MLSecOps). Любой отказ → `403` + `event(access_denied)`.
*Приёмка:* DS жмёт Approve → 403 + событие.

**T1.4 G0 Onboarding + паспорт.** `core/model_card.py` (pydantic): owner, Tier, источник,
назначение; авто-Tier правила (external→HIGH, PII→HIGH, не-CI→HIGH, дефолт HIGH). Вкладка
«Паспорт» в UI; регистрация в `models.card`.
*Приёмка:* модель без owner/Tier не регистрируется; Tier авто-выставляется.

**T1.5 Реестр + видимость.** UI вкладки «Реестр», «История», «Находки» (фильтры, «Показать
причину» = JSON evidence). `GET /findings /events /registry`.
*Приёмка:* видно статусы/Tier/owner; находки по активу и по системе.

---

## ФАЗА 2 — Гейты (P0/P1)

> На каждый гейт: папка + `Dockerfile` + `requirements.txt`; образ `mlsec-gate-<name>`; CI-job
> clean/bad; находки/события пишет оркестратор.

**T2.1 G1 Data Gate** (`src/gates/data_gate/`): формат, схема, типы, баланс, пропуски,
дубликаты, диапазоны, константы, PII (regex/Presidio), prompt-инъекции. CLI exit 0/1.
*Приёмка:* `*_poisoned.csv` → FAIL (balance + PII); чистый → PASS.

**T2.2 ingest_dataset** (`src/ingest_dataset/`): приём `local`/`s3://`/`http(s)://`, прогон G1,
бакет `datasets|quarantine`, запись в `datasets`/`verified_datasets`, findings+events. Fast-path
по хэшу. Запрет обновления `prod_locked`.
*Приёмка:* поток из [`05_CANONICAL_FLOW.md`](05_CANONICAL_FLOW.md) §5.3 (data-часть) работает из UI/CLI.

**T2.3 G2 Code Gate** (`src/gates/code_gate/`): gitleaks + bandit + pip-audit; `--stage ci|deploy`
(trivy только на `deploy`); источник `--path` или `--mlflow-uri`.
*Приёмка:* секрет/CVE → FAIL; чистый → PASS.

**T2.4 G3 Dependency/Supply Gate** (`src/gates/dependency_gate/`): allow-list имён (анти-
typosquatting `pytirch`/`tenserflew`), пиннинг (`--require-hashes`/lock), доверенный источник.
Отдельная CI-джоба `dependency-gate`.
*Приёмка:* чистый requirements PASS; фикстура с опечаткой/незапиненным → FAIL.

**T2.5 G4 Model Gate** (`src/gates/model_gate/`): allow-list форматов (анти-pickle), modelscan/
picklescan, SHA-256 ↔ реестр, cosign-verify, consistency train↔serve (pytest).
*Приёмка:* `.pkl` → FAIL; подменённый артефакт → FAIL по hash.

**T2.6 G5 Registry/Compliance Gate** (`src/gates/registry_gate/`): полнота карточки
(`validate_card`), lineage (dataset_version+git_sha+sha256+run_id), уникальность версии.
Интеграция в `register_model`/verify (блок при FAIL).
*Приёмка:* модель без owner/Tier/lineage не регистрируется.

---

## ФАЗА 3 — Gatekeeper (FastAPI) и связка с MLflow

**T3.1 Пакет `src/api/`** (FastAPI), сервис в compose (8000), эндпоинты из [`11_BACKEND_API.md`](11_BACKEND_API.md).

**T3.2 `POST /api/v1/verify`** по контракту §11.3: ветка external (G3+G4+G5 на замороженном
артефакте) и ветка своя-модель (G5+G2+G3 на коде → триггер train.yml → G4 на CI-артефакте).
findings/events/статус; Tier→HITL.
*Приёмка:* валидный run → PASS+статус; «плохой» → FAIL+quarantine+видимая причина.

**T3.3 MLflow-глю.** `register_model` пишет И в Postgres, И в MLflow Registry; артефакт в
`models` с прод-префиксом; aliases. `GET /models /runs` из `mlflow.client`.
*Приёмка:* одна регистрация → запись в обоих; выпадашки приходят из MLflow.

**T3.4 Кнопка «Просканировать ресурс всеми применимыми образами».** UI → бэкенд → запуск всех
применимых гейт-образов (или workflow через dispatch) → отчёт по джобам/шагам в UI.
*Приёмка:* нажатие гоняет применимые гейты, виден прогресс и итог.

---

## ФАЗА 4 — CI обучения и деплоя (стадии 5–6)

**T4.1 `train.yml`** ([`12_CICD.md`](12_CICD.md) §train): G2(ci) → `src/train/train.py` →
G4 на CI-артефакте → MLflow `log_model` (alias=candidate) + `models/...` → `register_model`
(lineage, `trained_in_ci=true`).
*Приёмка:* RUN из UI/CI создаёт версию модели с lineage; артефакт = выход CI.

**T4.2 `deploy.yml`** ([`12_CICD.md`](12_CICD.md) §deploy): G2(deploy)+trivy + G4(SHA) + cosign
sign → копия в `models/prod/*` (WORM) → проверка подписи+SHA перед `docker run` → alias=production.
HITL для Tier=HIGH (стоит до Approve).
*Приёмка:* HIGH не уходит без Approve; подмена артефакта в MinIO → «hash mismatch».

**T4.3 Замена/откат/retire** ([`05_CANONICAL_FLOW.md`](05_CANONICAL_FLOW.md) §5.6): blue-green,
alias `production`/`previous`, rollback, retire — только MLSecOps, с reason, в events.
*Приёмка:* промоут новой версии + откат на предыдущую работают; всё в истории.

---

## ФАЗА 5 — Runtime (G7) и мониторинг (G6)

**T5.1 G7 инференс** (`src/serve/`): FastAPI, Redis rate-limit(→429), Pydantic(→422),
лимит payload(→413), output-reduction, DLP логов. Минимум 3 модели (по микросервису).
`attack_sim.py`.
*Приёмка:* спам → 429; мусор → 422; ПДн в логах замаскированы.

**T5.2 G6 мониторинг** (`src/monitor/`): drift/PSI (evidently), детект подмены (ре-хэш),
алерты в events/дашборд.
*Приёмка:* `prod_traffic_drifted.csv` → DRIFT (PSI>0.25); ре-хэш ловит подмену.

**T5.3 Дашборд** в UI: runtime-метрики, дрейф, всплески 429, статус защищённости; CEO read-only.

---

## ФАЗА 6 — Полировка и демо

**T6.1** Прогон всех 4 демо-сценариев из [`16_DEMO_SCENARIOS.md`](16_DEMO_SCENARIOS.md) одной
командой; «красивый» единый флоу в UI.
**T6.2** Причесать паспорт модели угроз ([`08_THREAT_MODEL.md`](08_THREAT_MODEL.md)) под факт.
**T6.3** Проверка целостности лога в UI; маппинг инструмент→угроза на вкладке «Сканеры».
**T6.4** (P3, по остатку) GenAI/агент как отдельный сервис: guardrails/output-DLP/квоты/HITL-tools.

---

## Порядок и дисциплина

```
ФАЗА 0 → 1 → 2 → 3 → 4  (это сквозной MVP, нужен для демо)
затем 5 (runtime/monitoring) → 6 (полировка) → P3 (GenAI, если время есть)
```

Соответствие приоритетам жюри: скан кода (G2, Ф2) → реестр (Ф1) → gate перед продом + HITL
(Ф4) → скан моделей (G4, Ф2) → версии/история/lineage (Ф0–1) → ролёвка (Ф1) → подписи (Ф4) →
сканы данных (G1, Ф2) → gate на закачку (G3, Ф2) → запрет небезопасных форматов (G4) →
рантайм (Ф5).

## Чего НЕ делать
- Не класть запись в БД внутрь `gate_check` (ломает CI без БД).
- Не удалять заблокированные артефакты (только `quarantine`).
- Не заливать артефакты в прод руками — только через CI/aliases.
- Не давать доступ к датасету без регистрации и назначенного доступа.
- Не оставлять demo-переключатель ролей включённым в боевом конфиге.
- Не публиковать MLflow наружу мимо auth-прокси.
- Не менять схему результата гейта/таблиц БД без обновления всех потребителей.
- Не хардкодить секреты, не добавлять RCE/закладки.
