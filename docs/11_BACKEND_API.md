# 11 — Бэкенд / Gatekeeper (FastAPI)

Бэкенд — единая точка: REST API, запуск гейтов (deep audit), согласование с реестром/историей,
RBAC, интеграция с MLflow. Пакет `src/api/` (+ слой `core/`). Сервис в compose, порт 8000.

## 11.1 Аутентификация

Все эндпоинты — за auth-прокси (SSO). Личность приходит из проверенного заголовка
`X-Authenticated-User` (см. [`06_IDENTITY_AND_AUTH.md`](06_IDENTITY_AND_AUTH.md)). Клиент её не задаёт.
Привилегированные эндпоинты обёрнуты `require_role(...)`.

## 11.2 Эндпоинты (минимум)

| Метод | Путь | Роль | Назначение |
|---|---|---|---|
| `GET` | `/api/v1/models` | любой | список моделей (из MLflow + реестр) — для выпадашек |
| `GET` | `/api/v1/runs?model=<name>` | любой | список Run ID модели (MLflow client) |
| `POST` | `/api/v1/datasets/ingest` | DS/DE/MLSecOps | онбординг датасета (обёртка над `ingest_dataset`) |
| `POST` | `/api/v1/datasets/{name}/{version}/update` | DS/DE | обновление датасета (→ перезапуск G1 с нуля; запрет если `prod_locked`) |
| `POST` | `/api/v1/verify` | DS/DE/MLSecOps | **главная ручка** — deep audit |
| `POST` | `/api/v1/train` | DS/MLSecOps | запустить обучение в CI (RUN) |
| `POST` | `/api/v1/deploy/{model}/{version}` | MLSecOps | запустить deploy.yml |
| `POST` | `/api/v1/deploy/{model}/{version}/approve` | MLSecOps | HITL Approve (Tier=HIGH) |
| `POST` | `/api/v1/prod/{model}/rollback` | MLSecOps | откат на `previous` |
| `POST` | `/api/v1/prod/{model}/{version}/retire` | MLSecOps | вывод из эксплуатации |
| `POST` | `/api/v1/findings/{id}/false_positive` | MLSecOps | отметить FP (+reason) |
| `POST` | `/api/v1/scan/{asset_type}/{id}` | DS/DE/MLSecOps | «просканировать ресурс всеми применимыми образами» |
| `GET` | `/api/v1/findings` `/events` `/registry` | любой (CEO read-only) | видимость |
| `POST` | `/api/v1/admin/users` `/roles` `/access` | MLSecOps | RBAC-админка |
| `GET` | `/api/v1/admin/users` | MLSecOps | список пользователей с правами (UI «Пользователи») |
| `GET` | `/api/v1/models/{name}/versions` | любой | версии модели + lineage/гейты (Реестр/Паспорт) |
| `GET` | `/api/v1/datasets/{key}` | по доступу | карточка датасета + отчёт G1 |
| `GET` | `/api/v1/resources` | MLSecOps | ресурсы для раннера гейтов (тип→применимые гейты) |
| `GET` | `/api/v1/events/verify_chain` | любой | проверка целостности Audit Trail (hash-chain) |
| `GET` | `/api/v1/cicd/runs` | MLSecOps | прогоны CI/CD (run→jobs→steps→log) для «CI/CD логи» |
| `POST` | `/api/v1/scan` | MLSecOps | раннер: матрица ресурс×гейт (`{gates, resources, fail_closed}`) |
| `POST` | `/api/v1/findings/{id}/fp` `/rerun` `/close` | MLSecOps | действия над находкой |
| `GET` | `/api/v1/controls` | любой | каталог контролей (карта покрытия), см. `20_CONTROLS_COVERAGE` |
| `POST` | `/api/v1/controls/{id}/accept` | MLSecOps | RiskAcceptance (принять остаточный риск) |

> Все эти ручки уже **объявлены в `src/api/main.py`** как контракт (возвращают TODO-заглушки).
> UI вызывает их через `_api_get/_api_post` с **fallback на моки** — при реализации A
> переключение автоматическое, без правок фронта.

## 11.3 Контракт `POST /api/v1/verify`

Запрос:
```json
{ "model_name": "credit_scoring", "run_id": "run_3_abc123", "git_sha": "a1b2c3d",
  "requested_by": "ivanov", "reason": "релиз v4: новые фичи" }
```

Действия бэкенда (строго по шагам, КАНОН):
1. Через `mlflow.client` получить метаданные Run: теги (`security.*`), `dataset` digest/hash,
   метрики, ссылку на код.
2. Определить путь:
   - **источник = external** (внешние веса) → поток B: скачать+заморозить артефакт, гейты
     **G3 + G4 + G5** на нём; статус `pending_hitl` (Tier=HIGH).
   - **иначе** (своя модель) → поток A: запустить **G5** (lineage/паспорт по карточке+run) +
     **G2** (на коде по `git_sha`) + **G3** (зависимости). Артефакт DS из MLflow **не**
     деплоится — это эксперимент. Если PASS → инициировать `train.yml` (обучение в CI),
     **G4 пойдёт на CI-артефакте**.
3. На каждую FAIL-проверку — `add_finding(...)`; писать `log_event("verify_started/passed/blocked")`.
4. Определить Tier (авто-правила/реестр). PASS + Tier≠HIGH → `approved`; PASS + HIGH → `pending_hitl`;
   любой FAIL → `quarantine` (артефакт-улика в `quarantine`).
5. Вернуть отчёт для UI (видна причина блока = evidence).

Ответ:
```json
{ "passed": false, "status": "quarantine",
  "gate_results": [ {"gate":"G2","check":"secrets","status":"FAIL","evidence":{...}} ],
  "findings_ids": [42], "next_action": "fix secrets and re-run" }
```

> Отличие от старых черновиков: для своей модели verify **не проверяет скачанный артефакт DS** —
> он проверяет код+данные+lineage, а артефакт рождает CI (`train.yml`), и уже его проверяет G4.

## 11.4 Запуск гейтов

Боевой путь — через Docker-образ гейта (контракт §7.2): `docker run --rm ... mlsec-gate-<name> --json`.
Бэкенд парсит stdout-JSON, сам пишет `findings`+`events`. Для офлайн-демо джобы исполняет
self-hosted runner GitHub Actions (см. [`12_CICD.md`](12_CICD.md)); кнопка «просканировать ресурс»
триггерит workflow через `repository_dispatch`/`workflow_dispatch`.

## 11.5 Интеграция с MLflow

- Выпадашки `model_name`/`run_id` — из `mlflow.client.search_runs()` (теги `security.*`,
  `run.inputs.dataset_inputs` для хэша датасета). Кэш на короткое время в Redis.
- Регистрация: при `register_model` пишем И в Postgres `models`/`model_versions`, И в MLflow
  Registry (`core/mlflow_utils.register_model_version`). Источник правды по артефактам —
  MLflow+S3; по безопасности — Postgres; синк по `(name, version)`.
- Релиз — сменой alias (`candidate`→`staging`→`production`) бэкендом/деплоем, не руками.

## 11.6 Хелперы `core/`

- `db.log_event(...)` — единственная запись в `events` (hash-chain).
- `db.add_finding(...)`, `db.register_model(...)`, `db.set_status(...)`, `db.grant_access(...)`.
- `identity.require_role(role)`, `identity.current_user(request)`.
- `storage.upload/download/available()`, `storage.lock_prod(...)` (WORM).
- `mlflow_utils.download_artifacts()`, `register_model_version()`.
- `model_card.validate_card(...)` (G0).
