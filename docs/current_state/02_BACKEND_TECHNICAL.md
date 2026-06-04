# MLSecOps Platform — Техническое описание бэкенда (текущее состояние)

> Дата среза: 2026-06-04. Подробный технический разбор бэкенда «A» (Gatekeeper + ядро `core/`
> + MLflow за auth-прокси + БД). Бизнес-контекст — в [`01_BUSINESS_AND_FEATURES.md`](01_BUSINESS_AND_FEATURES.md),
> фронт — в [`03_FRONTEND_TECHNICAL.md`](03_FRONTEND_TECHNICAL.md).
> Легенда: ✅ реализовано · 🟡 частично/плейсхолдер · 🚧 заглушка (`TODO`/пусто).

---

## 1. Обзор архитектуры

```
                 ┌───────────────────────── BACKEND (A) ─────────────────────────┐
   Браузер       │                                                                │
 (Streamlit UI)──┼──HTTP+JWT──►  FastAPI Gatekeeper  (src/api/main.py)             │
                 │                    │  ├─ auth/RBAC ──────► core/identity.py      │
   Ноутбук DS    │                    │  ├─ БД/аудит/ACL ───► core/db.py            │
 (MLflow SDK)────┼──JWT──► /mlflow ─► auth-прокси (src/api/mlflow_proxy.py)         │
                 │                    │        │  штамп owner + фильтрация видимости │
                 │                    │        ▼                                    │
                 │                    │   MLflow upstream (server-side)  ◄── core/mlflow_utils.py
                 │                    ├─ /ci/trigger ─► gates (src/gates/*) | GitHub Actions
                 │                    └─ security_check (core/security_check.py, плейсхолдер)
                 │                                                                  │
                 │   БД: SQLite (дев) | PostgreSQL (прод)   ·   S3/MinIO: core/storage.py (🚧)
                 └────────────────────────────────────────────────────────────────┘
```

**Суть:** единый FastAPI-сервис (Gatekeeper) — точка входа для UI и для MLflow. Личность
берётся из JWT. MLflow наружу не публикуется — только через наш auth-прокси, который серверно
проставляет личность и фильтрует видимость артефактов. Бэкенд для чтения ходит в MLflow напрямую
(server-side, доверенно).

---

## 2. Технологический стек и зависимости

- **Python 3.11+** (локально 3.13).
- **FastAPI** — бэкенд/Gatekeeper. **uvicorn** — ASGI-сервер.
- **pydantic v2** — модели запросов/валидация.
- **bcrypt** — хэш паролей (напрямую, НЕ через passlib — см. §13 «грабли»).
- **python-jose[cryptography]** — JWT (HS256).
- **httpx** — асинхронный клиент в auth-прокси (проксирование в MLflow).
- **mlflow** — трекинг + Model Registry (server-side клиент).
- **psycopg[binary]** — драйвер PostgreSQL (прод-режим).
- **requests** — синхронные вызовы (например, GitHub `repository_dispatch`).
- **boto3** — S3/MinIO (в `core/storage.py`, пока 🚧).
- **redis** — для рантайм-слоя (rate-limit), в текущем стенде бэка не используется.

`requirements.txt` (корневой) содержит всё перечисленное + `streamlit` (UI) + `pytest`.
У каждого гейта (`src/gates/*`) свой `requirements.txt` (изоляция образов).

---

## 3. Структура каталогов (бэкенд)

```
core/
  db.py             ✅ слой БД: схема, Audit Trail (hash-chain), RBAC, artifact ACL; реестр — 🚧
  identity.py       ✅ пароли (bcrypt), JWT, current_user, RBAC, клиренс, политика видимости
  mlflow_utils.py   🟡 server-side доступ к MLflow (раны/модели); часть функций — 🚧
  security_check.py 🟡 security check артефакта (ПЛЕЙСХОЛДЕР, всегда PASS)
  model_card.py     🟡 паспорт модели (pydantic) + auto_tier + validate_card (не подключён к ручке)
  storage.py        🚧 MinIO/S3 (бакеты, WORM) — контракты есть, реализация TODO
src/api/
  main.py           ✅/🚧 FastAPI Gatekeeper: эндпоинты (auth/admin/artifacts/events реальны; verify/deploy/... заглушки)
  mlflow_proxy.py   ✅ auth-прокси перед MLflow (штамп owner + фильтрация видимости)
src/gates/          (работа «B») data_gate, code_gate, dependency_gate, model_gate, registry_gate
infra/
  seed_admin.py     ✅ bootstrap первого MLSecOps-админа
  init.sql          ✅ схема PostgreSQL
  start.cmd/stop.cmd/run_local.ps1   ✅ локальный запуск (Windows)
  docker-compose.yml + Dockerfile.*  ✅ целевой стенд (Postgres+MinIO+Redis+MLflow+authproxy+backend+ui)
```

---

## 4. Конфигурация (переменные окружения)

| Переменная | Дефолт | Назначение |
|---|---|---|
| `DB_BACKEND` | `sqlite` | `sqlite` (дев) или `postgres` (прод/compose) |
| `SQLITE_PATH` | `<repo>/mlsec_dev.db` | путь к файлу SQLite |
| `POSTGRES_HOST/PORT/DB/USER/PASSWORD` | localhost/5432/mlsec/mlsec_app/'' | подключение к Postgres |
| `JWT_SECRET` | `dev-insecure-change-me` | секрет подписи JWT (HS256) — **сменить в проде** |
| `TOKEN_TTL_HOURS` | `8` | срок жизни токена |
| `AUTH_PROXY_HEADER` | `X-Authenticated-User` | имя заголовка доверенной личности от прокси |
| `TRUST_PROXY_HEADER` | `false` | доверять ли `X-Authenticated-User` (вкл. только если бэк реально за прокси) |
| `APP_DEBUG` | `false` | дев-режим (в т.ч. демо-роль через `X-Demo-Role`, в текущем UI не используется) |
| `MLFLOW_UPSTREAM_URL` | `http://127.0.0.1:5000` | адрес внутреннего MLflow (server-side и для прокси) |
| `MLFLOW_TRACKING_URI` | `http://authproxy:4180/mlflow` | URI MLflow для сниппета ноутбука (`/auth/token`) |
| `MLFLOW_HTTP_REQUEST_TIMEOUT` | `5` | fail-fast таймаут MLflow-клиента (ставится в `mlflow_utils` до импорта mlflow) |
| `MLFLOW_HTTP_REQUEST_MAX_RETRIES` | `1` | fail-fast ретраи MLflow-клиента |
| `GITHUB_TOKEN` / `GITHUB_REPO` / `GITHUB_REF` | ''/''/`sasha` | для `repository_dispatch` в `/ci/trigger` |
| `BOOTSTRAP_ADMIN_USER/EMAIL/PASSWORD` | msecops/msecops@example.com/admin-pass | сид первого админа |
| `MINIO_*` | (см. storage.py) | бакеты MinIO (datasets/quarantine/models/mlflow) — 🚧 |

---

## 5. Слой БД — `core/db.py` ✅ (реестр/находки — 🚧)

### 5.1 Два бэкенда
- `get_conn()` — `sqlite3` или `psycopg` по `DB_BACKEND`.
- `init_db()` — создаёт схему для SQLite (в Postgres схему ставит `infra/init.sql` через docker-entrypoint).
- `_sql()` — транслирует плейсхолдеры `?` → `%s` для Postgres.
- `_json_param()` / `_json_load()` — JSON-поля: `Jsonb` в pg, JSON-строка (TEXT) в sqlite.
- `_tx(commit=False)` — контекст-менеджер с курсором; соединение всегда закрывается.

### 5.2 Таблицы (общие для sqlite/pg; см. `init.sql` / `_SQLITE_SCHEMA`)

| Таблица | Назначение | Ключевые поля |
|---|---|---|
| `events` | Audit Trail (append-only, hash-chain) | id, ts, actor, role, action, asset, result∈{ok,blocked,pending,error}, reason, details(JSON), prev_hash, row_hash |
| `users` | пользователи | id, username (unique), email, password_hash (bcrypt; NULL для чисто-SSO) |
| `roles` | роли пользователя | (user_id, role∈{DS,DE,MLSecOps,Product,CEO}) |
| `dataset_access` | доступ к датасету | (user_id, dataset_name, dataset_version), can_export, granted_by |
| `datasets` | реестр датасетов | name+version (unique), sha256, source_type, status, bucket, owner |
| `verified_datasets` | прошедшие проверку | sha256 (PK), name, version, signed |
| `models` | реестр моделей | name+version (unique), tier∈{LOW,MED,HIGH}, status, source∈{ci_trained,external}, sha256, signed, owner, approved_by, card(JSON) |
| `model_versions` | lineage версий | model_name+version, dataset_*, git_sha, run_id, mlflow_version, trained_in_ci, sha256, status |
| `findings` | сработки гейтов | gate, asset_type, asset, rule, severity, evidence(JSON), status∈{open,false_positive,fixed}, marked_by, run_no |
| `experiment_owner` | владелец MLflow-эксперимента | experiment_id (PK), owner |
| `artifact_acl` | ACL рана (сессии) | run_id (PK), experiment_id, owner, session_name, check_status∈{none,pending,passed,failed}, check_detail(JSON), share_status∈{private,shared}, share_level(int), share_roles(JSON), shared_by |

### 5.3 Функции
**Audit:** `log_event(actor, role, action, *, asset, result, reason, details)` (единственная точка
записи), `list_events(limit)` (новые сверху), `verify_chain()` → `{ok, broken_at, count}`.

**RBAC/users:** `register_user`, `get_user`, `set_password`, `list_users` (с ролями), `assign_role`,
`revoke_role`, `get_roles(username)→set`, `grant_access`, `has_dataset_access`.

**Artifact ACL (приватность/шаринг):** `set_experiment_owner`, `get_experiment_owner`,
`list_owned_experiments`, `upsert_artifact`, `upsert_artifacts_bulk` (пакетно, одной транзакцией —
ради производительности ленивой регистрации), `get_artifact_acl`, `list_artifact_acls(run_ids|None)`,
`list_shared_acls`, `set_check_status`, `share_artifact(level XOR roles)`, `unshare_artifact`.

**Реестр/находки 🚧 (NotImplementedError):** `register_dataset`, `register_model`,
`add_model_version`, `set_status`, `add_finding`, `mark_false_positive`.

**Самопроверка:** `python core/db.py` — демо на чистой SQLite (регистрация → роль → доступ →
события → проверка цепочки → имитация подделки → ACL/шаринг/видимость).

### 5.4 Audit Trail — алгоритм hash-chain
```
canonical = json({actor,role,action,asset,result,reason,details}, sort_keys, ensure_ascii=False, compact)
row_hash  = sha256(prev_hash + canonical)        # prev для первой записи = "0"*64 (genesis)
```
`verify_chain()` идёт по `events ORDER BY id`, пересчитывает `expected = sha256(prev + canonical)`
и сверяет `prev_hash`/`row_hash`. Любое расхождение → `{ok:false, broken_at:<id>}`. В Postgres
у роли приложения отзываются UPDATE/DELETE на `events` (append-only, строка-комментарий в `init.sql`).

---

## 6. Идентичность / JWT / RBAC — `core/identity.py` ✅

- **Пароли:** `hash_password` / `verify_password` (bcrypt; пароль режется до 72 байт — лимит bcrypt).
- **JWT:** `create_token(username, roles, ttl_hours)` (payload: sub, roles, iat, exp; HS256),
  `decode_token` (проверка подписи/срока → `AuthError`).
- **Логин:** `authenticate(username, password)` → `{username, roles}` или `AuthError`.
- **Личность из запроса** `current_user(request)`, приоритет:
  1. `X-Authenticated-User` — **только если** `TRUST_PROXY_HEADER=true` (бэк реально за прокси);
  2. `Authorization: Bearer <jwt>` → `sub`.
  По умолчанию `TRUST_PROXY_HEADER=false` — клиент не может подделать личность заголовком.
- **Роли:** `get_roles(username)` — **из БД** (источник правды); `token_roles(request)` — из JWT
  (без БД, вспомогательно). `require_role(request, role)` → username или `AuthError` (роль из БД,
  чтобы отзыв действовал сразу).
- **Демо-роль:** `effective_role(request)` учитывает `X-Demo-Role` **только при `APP_DEBUG`**.
  В текущем UI не используется (выбрана модель «только реальный логин»).
- **Константы:** `ROLES = {DS, DE, MLSecOps, Product, CEO}`, `ROLE_LEVEL = {DS:1, DE:1, Product:2, MLSecOps:3, CEO:4}`.
- **Клиренс/видимость:** `clearance(roles)` = макс. уровень; `can_view_artifact(acl, user, roles)` —
  чистая политика:
  ```
  владелец → видит всегда
  не shared → только владельцу
  share_roles задан → любой пересекающийся в roles
  иначе → clearance(roles) >= share_level   (read-down)
  ```

Самопроверка: `python -m core.identity`.

---

## 7. Доступ к MLflow — `core/mlflow_utils.py` 🟡

- **Fail-fast:** в начале модуля (ДО импорта mlflow) ставятся `MLFLOW_HTTP_REQUEST_TIMEOUT=5`,
  `MLFLOW_HTTP_REQUEST_MAX_RETRIES=1` — иначе при недоступном MLflow клиент ретраит ~2 минуты и
  вешает ручки UI.
- `_client()` — `MlflowClient` на `MLFLOW_UPSTREAM_URL` (server-side, минуя наш прокси).
- `list_recent_runs(limit)` ✅ — раны по всем экспериментам, плоские dict (`run_id, experiment_id,
  experiment, run_name, owner, user, status, start_time, metrics, params`). При недоступном MLflow → `[]`.
- `get_run(run_id)` ✅ — метаданные одного рана или None.
- `list_models()` ✅ — `[{name, latest_versions:[...]}]` из MLflow Model Registry.
- `_run_to_dict()` — владелец = серверный тег `OWNER_TAG="mlsecops.owner"` → fallback `mlflow.user` → `user_id`.
- 🚧 `list_runs(model)`, `get_run_metadata(run_id)`, `download_artifacts`, `register_model_version`,
  `set_alias` — `NotImplementedError` (нужны для verify/реестра).

---

## 8. MLflow auth-прокси — `src/api/mlflow_proxy.py` ✅

Роут `@router.api_route("/mlflow/{path:path}", methods=[...])`. Логика:

1. **Аутентификация:** `current_user(request)` из JWT; без токена → `401`.
2. **Сбор апстрим-запроса:** читается тело; на `runs/create` в тело вписывается неподделываемый
   тег владельца `_stamp_owner_in_body` (`mlsecops.owner = user`, клиентский тег с тем же ключом
   удаляется). Заголовки фильтруются (`_DROP_HEADERS` — hop-by-hop + authorization), добавляется
   `X-Authenticated-User = quote(user)` (URL-кодирование — заголовки latin-1, не-ASCII логин ломал бы).
3. **Проксирование:** `httpx.AsyncClient` → `MLFLOW_UPSTREAM_URL/{path}`. Недоступен → `502`.
4. **Фиксация владения** (`_record_create`) на `200` для `runs/create` (→ `set_experiment_owner` +
   `upsert_artifact(owner, session_name)`) и `experiments/create` (→ `set_experiment_owner`).
   Читается ОТВЕТ MLflow (не тело запроса) — работает независимо от кодировки клиента.
5. **Фильтрация видимости** (`_apply_visibility`) на `200` для чтений:
   - `runs/search` → `_filter_runs`: оставить только видимые (`can_view_artifact` по ACL из БД,
     либо синтетический приватный ACL с owner из тегов);
   - `experiments/search`/`list` → `_filter_experiments`: видим, если эксперимент не отслеживается
     (legacy/Default — **fail-open**, не прячем), либо им владеет user, либо в нём есть расшаренный ран;
   - `runs/get` → чужой приватный → `403 PERMISSION_DENIED`;
   - `experiments/get` → чужой приватный без расшаренных ранов → `403`.
   При перезаписи тела дропается `content-encoding` (`_DROP_ON_REWRITE`) — отдаём уже
   декодированный/перекодированный JSON.
6. Иначе — ответ MLflow возвращается как есть (без hop-by-hop заголовков).

**Ограничения (задокументированы):** не фильтруются artifact-эндпоинты (скачивание весов) и
ajax-api нативного MLflow Web UI; fail-open для нетрекаемых экспериментов.

---

## 9. Security check — `core/security_check.py` 🟡 ПЛЕЙСХОЛДЕР

`run_artifact_check(run_id, run_meta) → dict`. Контракт стабилен:
```json
{"passed": true, "run_id": "...", "checks": [{"check","status","detail"}],
 "placeholder": true, "debug": {experiment_id, owner, run_name, n_params, n_metrics, note}}
```
4 «как будто»-проверки (все PASS): `model_format` (G4: нет .pkl/.joblib/.bin), `secret_scan`,
`pii_markers`, `lineage`. Печатает дебаг-вывод `[security_check] ...` в консоль бэка. Точки
расширения (TODO) перечислены в docstring — сюда подключать настоящие гейты. Запуск **только** по
кнопке из ЛК (не из IDE). Самопроверка: `python core/security_check.py`.

---

## 10. Паспорт модели — `core/model_card.py` 🟡

- `ModelCard` (pydantic): name, version, owner, `tier` (дефолт **HIGH** — fail-safe), `source`
  (ci_trained/external), purpose, data_source + lineage-поля (dataset_version, git_sha, run_id,
  sha256, trained_in_ci — проставляет CI/сервер, не клиент).
- `auto_tier(source, pii_found, trained_in_ci, data_criticality)` — детерминированные правила:
  external / PII / не-в-CI / high-criticality → **HIGH**; иначе MED/LOW. Принцип «подозревай худшее».
- `validate_card(card)` → список результатов в формате гейта (PASS/FAIL по обязательным полям).

Модуль готов, но к HTTP-ручке (G0/реестр) ещё не подключён.

---

## 11. Хранилище S3/MinIO — `core/storage.py` 🚧

Контракты зафиксированы, реализация — TODO. Бакеты: `datasets`, `quarantine` (заблокированное
НЕ удаляем — улика), `models`, `mlflow`. Ключ объекта: `<name>/<version>/<sha12>_<filename>`.
`upload/download/available/lock_prod` (WORM/Object Lock на проде) — `NotImplementedError`.

---

## 12. API — `src/api/main.py`

При старте: `db.init_db()` + подключение `mlflow_proxy.router`.

### 12.1 RBAC-хелперы
- `_require(request, role)` — `401` без личности; `403` + событие `access_denied` без роли; иначе username.
- `_current_user(request)` — `401` без личности (для не-RBAC ручек).
- `_primary_role(username)` — первая роль (для логов).
- `_ensure_artifact(run_id)` → `(acl, run_meta)`; лениво регистрирует владение по данным MLflow.

### 12.2 Эндпоинты (полная карта)

**Auth ✅**
| Метод | Путь | Доступ | Делает |
|---|---|---|---|
| POST | `/api/v1/auth/register` | все | саморег без роли |
| POST | `/api/v1/auth/login` | все | пароль → JWT `{access_token, roles}` |
| GET | `/api/v1/auth/me` | Bearer | личность + роли из БД |
| POST | `/api/v1/auth/token` | Bearer | свежий JWT + Python-сниппет для MLflow SDK |

**Артефакты MLflow (приватность/шаринг) ✅**
| Метод | Путь | Доступ | Делает |
|---|---|---|---|
| GET | `/api/v1/artifacts` | Bearer | `{mine, shared_with_me, my_clearance}`; ленивая регистрация владения батчем |
| POST | `/api/v1/artifacts/{run_id}/check` | владелец | security check (плейсхолдер) → check_status + событие |
| POST | `/api/v1/artifacts/{run_id}/share` | владелец | требует check=passed (иначе 409); roles=null→по клиренсу, roles=[..]→кастом |
| POST | `/api/v1/artifacts/{run_id}/unshare` | владелец | снова private |

**MLflow/модели ✅**
| Метод | Путь | Доступ | Делает |
|---|---|---|---|
| GET | `/api/v1/models` | все | модели из MLflow Registry `{models:[{name, latest_versions}]}` |
| GET | `/api/v1/mlflow/runs?limit=` | Bearer | последние раны |
| GET | `/api/v1/runs?model=` | — | 🚧 `{runs:[]}` |
| ANY | `/mlflow/{path}` | Bearer | auth-прокси (см. §8) |

**Audit ✅**
| Метод | Путь | Доступ | Делает |
|---|---|---|---|
| GET | `/api/v1/events?limit=` | все | история (новые сверху) |
| GET | `/api/v1/events/verify_chain` | все | целостность hash-chain `{ok, broken_at, count}` ← **новая ручка** |

**CI / файлы ✅**
| Метод | Путь | Доступ | Делает |
|---|---|---|---|
| POST | `/api/v1/ci/trigger` | все | гейт data/code/dependency: GitHub Actions (если токен) или локально in-process |
| POST | `/api/v1/upload` | — | загрузка CSV в `data/` |
| GET | `/api/v1/files` | — | список CSV в `data/` |

**Админка (RBAC: MLSecOps) ✅**
| Метод | Путь | Делает |
|---|---|---|
| POST | `/api/v1/admin/users` | создать пользователя (+роли) |
| GET | `/api/v1/admin/users` | список юзеров с ролями |
| POST | `/api/v1/admin/roles` | назначить роль |
| POST | `/api/v1/admin/access` | выдать доступ к датасету (+can_export) |

**Заглушки 🚧 (возвращают `{"status":"TODO"}` / пусто):**
`POST /verify`, `POST /train`, `POST /deploy/{model}/{version}`, `POST /deploy/.../approve`,
`POST /prod/{model}/rollback`, `POST /prod/{model}/{version}/retire`,
`POST /scan/{asset_type}/{asset_id}`, `POST /findings/{id}/false_positive`,
`GET /findings`, `GET /registry`, `POST /datasets/ingest`.

Контракт будущего `/verify` (главная ручка): по `run_id` тянуть метаданные из MLflow, определять
ветку (своя модель / external), гонять гейты, писать `findings`+`events`, ставить статус
(approved / pending_hitl / quarantine).

### 12.3 Демо/самопроверка
`python -X utf8 -m src.api.main` — TestClient прогоняет поток регистрации → выдачи роли → токена
→ аудита (на временной SQLite).

---

## 13. Интеграция с CI и гейтами

`POST /api/v1/ci/trigger {check_type, target}`, где `check_type ∈ {data_gate, code_gate, dependency_gate}`:
- **GitHub Actions путь:** если заданы `GITHUB_TOKEN`+`GITHUB_REPO` → POST
  `repos/{repo}/dispatches` (`event_type=run-security-scan`, payload с check_type/target/ref).
  `204` → `{status:ok, mode:github_actions, repo}`. Минус: fire-and-forget (результат обратно не
  возвращается).
- **Локальный fallback:** импортирует гейт и зовёт его in-process:
  - `data_gate`: `gate_check(target_path)` (+ генерит датасет, если файла нет), `build_report`;
  - `code_gate`: `gate_check(repo_root, stage="ci")`;
  - `dependency_gate`: `gate_check(repo_root)`.
  Возвращает `{status:ok, mode:local, report}`.

**Гейты (`src/gates/*`, работа «B»)** — единый контракт `gate_check(...) → [results]`,
`build_report(target, results) → {gate, asset, passed, checks, failed_checks}`, `main()` (CLI,
exit 0/1). Реализованы все пять (data/code/dependency/model/registry), но кнопкой из бэка
подключены только G1/G2/G3; G4/G5 — для CI/`verify` (🚧).

---

## 14. Запуск и порты

**Локально (Windows, без Docker):**
```
infra\start.cmd     # сид админа + 3 окна: MLflow :5000, backend :8200, UI :8501
infra\stop.cmd      # гасит слушателей 8200/5000/8501
```
- Сид первого админа: `python -m infra.seed_admin` (msecops/admin-pass, роль MLSecOps).
- Бэкенд вручную: `python -X utf8 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8200`.

> **Почему порт 8200, а не 8000.** На Windows с Hyper-V/WSL2/Docker Desktop служба `winnat`
> резервирует динамические TCP-диапазоны (напр. **7904–8003**), и 8000 часто попадает внутрь.
> Нативный процесс (uvicorn) тогда падает на bind с `WinError 10013` («доступ запрещён»), хотя
> слушателя нет. 8200 — в свободной полосе 8104–14088. Проверка диапазонов:
> `netsh int ipv4 show excludedportrange protocol=tcp`. **В Docker остаётся 8000** (внутри
> контейнеров резерв хоста не действует; `docker-compose.yml` и `Dockerfile.backend` не менялись).

**Через Docker (целевой стенд):** `docker compose -f infra/docker-compose.yml up --build` —
поднимает postgres, minio, redis, mlflow (за authproxy:4180), backend:8000, ui:8501, inference:8080,
ci-runner. UI получает `GATEKEEPER_URL=http://backend:8000` (контейнерная сеть).

---

## 15. Ключевые решения по безопасности (не переделывать без причины)

1. **Локальный JWT-issuer** (HS256), не внешний Keycloak. Один JWT для API и MLflow.
2. **Личность неподделываема:** при работе с MLflow её ставит сервер (прокси штампует
   `X-Authenticated-User` и тег владельца); `X-Authenticated-User` от клиента доверяется только
   при `TRUST_PROXY_HEADER=true`.
3. **Роли для RBAC — из БД** (а не из токена): отзыв роли действует мгновенно.
4. **Любой отказ → `403` + событие `access_denied`** в Audit Trail.
5. **Audit Trail append-only + hash-chain:** подделка ловится `verify_chain()`.
6. **MLflow не публикуется наружу** — только через auth-прокси с пер-юзер фильтрацией видимости.
7. **Приватность артефактов по умолчанию**, шаринг — явное контролируемое действие после security check.
8. **Tier по умолчанию HIGH** (fail-safe), авто-правила «подозревай худшее».
9. **bcrypt напрямую** (НЕ passlib: passlib 1.7.4 несовместим с bcrypt 5.0).

---

## 16. Что НЕ реализовано в бэке (сводка TODO)

- `POST /verify` (deep audit, главный оркестратор гейтов).
- Реестр в БД: `register_model`, `add_model_version`, `set_status`, `/registry`, `/models/{name}/versions`.
- Находки: `add_finding`, `mark_false_positive`, `GET /findings`, `/findings/{id}/false_positive`.
- Прод-операции: `/train`, `/deploy`, `/approve` (HITL), `/rollback`, `/retire`.
- Назначение Tier через ручку; онбординг датасетов (`/datasets/ingest`).
- `mlflow_utils`: `list_runs`, `get_run_metadata`, `download_artifacts`, `register_model_version`, `set_alias`.
- `core/storage.py`: весь MinIO/S3 + WORM.
- Реальная логика `security_check` (сейчас плейсхолдер).
- Возврат статусов/логов CI обратно в бэкенд; матричный `/scan`.
- Прогон всего на `DB_BACKEND=postgres` + полный compose (Postgres+MinIO+MLflow за прокси).
- Валидация username при регистрации (`[a-z0-9_.-]`).
