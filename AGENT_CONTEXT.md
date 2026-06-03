# AGENT_CONTEXT — ориентир по проекту alfa_case_2

> **Назначение:** единая шпаргалка для агента и координации работ с пользователем.  
> **Источник правды по поведению системы:** `docs/05_CANONICAL_FLOW.md` (канон). При противоречии — прав канон, не этот файл.  
> **План кодинга:** `docs/IMPLEMENTATION_PLAN.md` (фазы 0→6).  
> **Полная документация:** `docs/00_INDEX.md`.

---

## 1. Суть проекта (одним абзацем)

**Secure MLOps / MLSecOps-платформа** для хакатона/кейса Альфа: слой безопасности поверх MLOps. Не «патчим после инцидента», а встраиваем проверки в жизненный цикл ML: реестр моделей и датасетов, Audit Trail, Security Gates **G0–G7**, HITL для критичных моделей, RBAC, runtime-защита инференса. Всё поднимается **`docker compose -f infra/docker-compose.yml up --build`**. CI — **GitHub Actions на self-hosted runner** в compose.

**Девиз:** MLOps делает надёжным, MLSecOps — неуязвимым.

---

## 2. Канон (нельзя нарушать при реализации)

| # | Решение |
|---|---------|
| 1 | **Прод-артефакт только из CI** (`train.yml`). Локальное обучение в MLflow — эксперимент, в прод не идёт. |
| 2 | **Внешние веса (HF/Kaggle):** заморозка SHA при ingest → гейты G3/G4/G5 → **Tier=HIGH** → **HITL обязателен**. |
| 3 | **Identity серверная:** MLflow за auth-прокси; клиент не подделывает `actor`. Заголовок `X-Authenticated-User`. |
| 4 | **Два входа данных:** DS через MLflow-код (за прокси); не-кодеры через UI → бэкенд логирует **их** личность. |
| 5 | **Статусы в Postgres**, не «перекладывание» файлов по бакетам ради статуса. MinIO: `datasets` / `quarantine` / `models`; прод — **WORM** на `prod/*`. |
| 6 | **Любое изменение данных → G1 с нуля.** Fast-path только при **бит-в-бит** том же SHA в `verified_datasets`. |
| 7 | **Каждое действие → `events`** через `log_event()` (hash-chain, append-only). |
| 8 | **Гейт не пишет в БД** — только JSON в stdout; пишет оркестратор (ingest / Gatekeeper). |
| 9 | **Заблокированное не удаляем** — версионируем в `quarantine`. |
| 10 | **Никаких секретов/RCE/закладок** в коде; «плохое» только в `demo/`. |

---

## 3. Архитектура (компоненты)

```
Пользователи (DS, DE, MLSecOps, Product, CEO)
    → Auth-прокси (oauth2-proxy, :4180) — SSO + X-Authenticated-User
    → Streamlit UI (:8501) → FastAPI Gatekeeper (:8000)
         ↔ PostgreSQL (реестр, audit, RBAC)
         ↔ MinIO (datasets, quarantine, models, mlflow)
         ↔ Redis (rate-limit G7)
         ↔ MLflow (:5000 внутри сети, только через прокси)
    → GitHub Actions (self-hosted ci-runner) → гейты (Docker) → train/deploy
    → Inference FastAPI (:8080) + monitor (G6/G7)
```

| Сервис | Порт (хост) | Файл |
|--------|-------------|------|
| UI | 8501 | `ui/app.py` |
| Gatekeeper | 8000 | `src/api/main.py` |
| MLflow (внутри) | — | `infra/Dockerfile.mlflow` |
| Auth proxy | 4180 | `infra/authproxy/` (TODO конфиг) |
| Inference | 8080 | `src/serve/app.py` |
| Postgres | 5432 | `infra/init.sql` |
| MinIO | 9000/9001 | — |
| Redis | 6379 | — |

---

## 4. Канонический поток (стадии)

```
0. Bootstrap MLSecOps
1. Подготовка данных (Jupyter) — без гейтов
2. Загрузка датасета → G0 + G1
3. Эксперименты MLflow — песочница
4. POST /api/v1/verify → G5 + G2(ci) + G3
5. train.yml → G2(ci) → train.py → G4 → register (candidate)
6. deploy.yml + HITL (HIGH) → G2(deploy)+trivy → G4 SHA → cosign → WORM → inference
7. Runtime G7 (429, 422, DLP, output-reduction)
8. Monitor G6 (drift PSI, re-hash подмены)
9. Blue-green / rollback / retire (только MLSecOps)
```

**Поток A:** свой код + данные → обучение в CI → G4 на **CI-артефакте**, не на черновике из ноутбука.  
**Поток B:** внешние веса → ingest + freeze SHA → G3/G4/G5 → `pending_hitl` → Approve → deploy.

**Зависимость статусов:** модель зависит от данных и кода; данные/код от модели — нет. FAIL данных → модель blocked.

---

## 5. Security Gates (краткий каталог)

| Гейт | Где | Папка | Суть |
|------|-----|-------|------|
| **G0** | Регистрация актива | `core/model_card.py` + UI | Паспорт (owner, Tier, источник); fail-safe Tier=HIGH |
| **G1** | Загрузка датасета | `src/gates/data_gate/` | Схема, баланс, PII, инъекции |
| **G2** | CI/verify/deploy | `src/gates/code_gate/` | gitleaks, bandit, pip-audit; trivy только `--stage deploy` |
| **G3** | Зависимости / HF | `src/gates/dependency_gate/` | allow-list, пиннинг, источник |
| **G4** | Артефакт модели | `src/gates/model_gate/` | anti-pickle, modelscan, SHA, cosign |
| **G5** | Реестр/lineage | `src/gates/registry_gate/` | model card, связь data↔git↔model |
| **G6** | Прод мониторинг | `src/monitor/monitor.py` | evidently/PSI, re-hash |
| **G7** | Инференс API | `src/serve/app.py` | Redis rate-limit, Pydantic, DLP |

**Контракт каждого гейта:** `gate_check()` → `build_report()` → `main()` (JSON stdout, exit 0/1).  
**Запуск:** `docker run --rm --network none -v artifact:/in:ro mlsec-gate-<name> --json`

---

## 6. Роли (RBAC — кто что делает)

| Роль | Ключевое |
|------|----------|
| **DS** | Датасеты, эксперименты, verify, RUN в CI; **не** Approve своей модели |
| **DE** | Датасеты, доступы по выдаче |
| **MLSecOps** | Админ: роли, Tier, Approve, deploy, rollback, retire, FP |
| **Product / CEO** | Read-only реестр/история/дашборд |

Проверка: `core/identity.py` — `current_user(request)`, `require_role()`.  
Demo-переключатель ролей в UI — **только** `APP_DEBUG=true`.

---

## 7. Модель данных (PostgreSQL)

Таблицы в `infra/init.sql`, описание в `docs/09_DATA_MODEL.md`:

- **`events`** — audit, hash-chain (`prev_hash`, `row_hash`), append-only для app-роли
- **`datasets`**, **`verified_datasets`** — реестр + fast-path по SHA
- **`models`**, **`model_versions`** — паспорт, Tier, статусы, lineage (`trained_in_ci`, `git_sha`, `run_id`)
- **`findings`** — сработки гейтов (evidence JSON, FP)
- **`users`**, **`roles`**, **`dataset_access`** — RBAC

Статусы модели: `registered → quarantine | pending_hitl → approved → prod | previous | retired`.

**Единственная точка записи в events:** `core/db.log_event()`.

---

## 8. Структура репозитория

```
alfa_case_2/
├── AGENT_CONTEXT.md          ← этот файл
├── core/                     # БД, MinIO, MLflow, identity, model_card
├── src/
│   ├── api/main.py           # Gatekeeper REST
│   ├── gates/<gate>/         # G1–G5 (по образу на гейт)
│   ├── ingest_dataset/       # G0+G1 онбординг
│   ├── train/train.py        # обучение в CI
│   ├── serve/                # G7 + attack_sim.py
│   └── monitor/              # G6
├── ui/app.py                 # Streamlit вкладки
├── infra/                    # compose, init.sql, Dockerfiles, seed_admin
├── data/make_datasets.py     # чистые + poisoned + drift демо
├── demo/insecure/            # секреты, pytirch, leaky.py — только для CI-демо
├── tests/smoke_db.py         # hash-chain smoke
└── .github/workflows/        # ci.yml, train.yml, deploy.yml
```

---

## 9. API Gatekeeper (контракт)

Базовый URL: `http://backend:8000`. Детали: `docs/11_BACKEND_API.md`.

| Метод | Путь | Кто | Назначение |
|-------|------|-----|------------|
| POST | `/api/v1/datasets/ingest` | DS/DE/MLSecOps | Онбординг датасета |
| POST | `/api/v1/verify` | DS+ | Deep audit → CI train |
| POST | `/api/v1/train` | DS/MLSecOps | dispatch train.yml |
| POST | `/api/v1/deploy/{model}/{version}` | MLSecOps | deploy.yml |
| POST | `/api/v1/deploy/.../approve` | MLSecOps | HITL |
| POST | `/api/v1/prod/.../rollback`, `retire` | MLSecOps | прод-операции |
| POST | `/api/v1/scan/{type}/{id}` | — | все применимые гейты |
| POST | `/api/v1/findings/{id}/false_positive` | MLSecOps | FP |
| GET | `/api/v1/findings`, `/events`, `/registry`, `/models`, `/runs` | read | видимость |
| POST | `/api/v1/admin/*` | MLSecOps | users, roles, access |

---

## 10. CI/CD

| Workflow | Триггер | Содержание |
|----------|---------|------------|
| `ci.yml` | PR, `workflow_dispatch`, `repository_dispatch` | syntax, data-gate, code-gate, dependency-gate, db-smoke |
| `train.yml` | dispatch `train` | G2(ci) → train.py → G4 → register |
| `deploy.yml` | dispatch deploy | G2(deploy)+trivy → G4 SHA → cosign → WORM → run |

Раннер: `runs-on: [self-hosted]`, сервис `ci-runner` в compose (нужен `GITHUB_TOKEN`).

UI кнопки → `repository_dispatch` / `workflow_dispatch` через бэкенд.

---

## 11. Приоритеты жюри (порядок работ)

```
скан кода (G2) → реестр → gate перед продом + HITL → скан моделей (G4) →
версионирование → история → lineage → RBAC → подписи → сканы данных (G1) →
gate на закачку (G3) → запрет unsafe форматов → runtime (G7)
```

**Четыре обязательные фичи для жюри:**
1. Единая история (`events` + UI)
2. HITL для Tier=HIGH
3. False Positives (причина блока = JSON гейта)
4. Runtime 429 (attack_sim)

---

## 12. Текущий статус реализации (на момент ознакомления)

| Область | Статус |
|---------|--------|
| **Документация** `docs/` | ✅ Полная (00–17 + IMPLEMENTATION_PLAN) |
| **Схема БД** `init.sql` | ✅ SQL есть |
| **`core/db.py`, `storage.py`, `mlflow_utils.py`, `identity.py`** | ⚠️ Скелет + `NotImplementedError` / TODO |
| **`src/api/main.py`** | ⚠️ Маршруты объявлены, логика TODO |
| **`ui/app.py`** | ⚠️ Вкладки-заглушки |
| **G1 data_gate** | ✅ Рабочая логика (pandas, PII, balance); CI clean/bad |
| **G2 code_gate, G3 dependency_gate** | ⚠️ Частично; gitleaks/trivy TODO в CI |
| **G4 model_gate, G5 registry_gate** | ⚠️ Скелет + TODO |
| **ingest, train, serve, monitor** | ⚠️ Скелет |
| **docker-compose** | ✅ Сервисы описаны; authproxy/runner — TODO конфиг |
| **Workflows** | ⚠️ ci.yml частично рабочий; train/deploy — TODO шаги register/cosign |

**Порядок фаз по плану:** 0 (инфра+БД+audit+MinIO) → 1 (identity, RBAC, G0, реестр UI) → 2 (гейты+ingest) → 3 (Gatekeeper+verify) → 4 (train/deploy/HITL) → 5 (G7+G6) → 6 (демо-полировка).

Перед любой задачей: свериться с **IMPLEMENTATION_PLAN** §фаза и DoD (py_compile, CI clean/bad, events, RBAC, без секретов в коде).

---

## 13. Демо (что показываем пользователю)

`docs/16_DEMO_SCENARIOS.md` — 4 сценария (~10–15 мин):

1. **G1 + FP:** clean vs `train_m1_poisoned.csv` → quarantine → перезапуск
2. **Verify + train:** gitleaks/`pytirch` → FAIL → fix → train.yml + lineage
3. **Deploy + HITL + RBAC:** DS Approve → 403; MLSecOps Approve; hash mismatch; `.pkl` blocked
4. **Runtime:** `attack_sim.py` → 429; мусор → 422; DLP в логах; опц. drift PSI

Данные: `python data/make_datasets.py` после поднятия стенда.

---

## 14. Куда смотреть при типовой задаче

| Задача | Читать | Трогать |
|--------|--------|---------|
| Поток/бизнес-правило | `05_CANONICAL_FLOW.md` | — |
| Новый гейт | `07_SECURITY_GATES.md` | `src/gates/<name>/` + CI job + оркестратор |
| БД/события | `09_DATA_MODEL.md` | `core/db.py`, `init.sql` |
| API | `11_BACKEND_API.md` | `src/api/main.py` |
| UI экран | `14_FRONTEND_UI.md` | `ui/app.py` |
| CI job | `12_CICD.md` | `.github/workflows/` |
| Угроза/демо | `08_THREAT_MODEL.md`, `16_DEMO_SCENARIOS.md` | `demo/` только |
| Инфра | `04_ARCHITECTURE.md`, `15_TECH_STACK.md` | `infra/` |

---

## 15. Ограничения для агента при работе с пользователем

- **Минимум сквозного флоу сначала** — не уходить в GenAI/P3, пока фазы 0–4 не дают демо.
- **Один гейт = одна папка** — не смешивать тулчейны.
- **Не менять схему БД/JSON гейта** без синхронного обновления UI, API, ingest, docs.
- **Не коммитить** без явной просьбы пользователя; не класть секреты в репо.
- **Демо-плохое** только из `demo/` — никогда в `src/` как «рабочий» код.
- При сомнении по архитектуре — **канон побеждает** (`05_CANONICAL_FLOW.md`).

---

## 16. Быстрый старт команд

```bash
cp .env.example .env
docker compose -f infra/docker-compose.yml up --build
python data/make_datasets.py
# UI http://localhost:8501  API http://localhost:8000
```

---

*Файл создан для сессии подготовки к дальнейшей разработке alfa_case_2. Обновлять при существенных изменениях архитектуры или завершении фаз IMPLEMENTATION_PLAN.*
