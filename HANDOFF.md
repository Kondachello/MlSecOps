# MLSecOps Platform — Handoff / Состояние бэкенда (промпт для следующего агента)

---
## СЕССИЯ X — «реестр/дашборд/прод/версионирование» (последние изменения)

> Что сделано в этой сессии (всё проверено e2e против реального MLflow 3.13 + бэкенда).

**0. Корневая причина «пустого реестра» (диагноз).** Логика бэкенда корректна: при доступном
MLflow раны → реестр → security check → зоны → выкатка → прод работают (проверено). Реестр пуст
ТОЛЬКО когда `mlflow_utils.list_recent_runs()` ловит исключение и МОЛЧА отдаёт `[]`. Две причины
сделаны видимыми и устранены:
- **`core/mlflow_utils.py`**: больше не глотаем ошибку тихо — логируем; добавлен `mlflow_status()`
  (диагностика) и `_LAST_ERROR`. Добавлен `_ensure_no_proxy_for_upstream()` — хост внутреннего
  MLflow добавляется в `NO_PROXY`, иначе системный/корпоративный прокси перехватывал локальный
  запрос к MLflow → `[]` → пустой реестр. `list_models()` переписан под MLflow 3 (через
  `search_model_versions`, +`n_versions`).
- **`src/api/mlflow_proxy.py`**: `httpx.AsyncClient(trust_env=False)` — прокси к внутреннему MLflow
  больше не уходит через системный прокси (это и ломало логирование на части машин).
- **`src/api/main.py`**: новый `GET /api/v1/mlflow/health` (UI показывает ПРИЧИНУ пустоты).
- **`ui/app.py`**: `_mlflow_notice()` — при пустом реестре/артефактах показывает, жив ли MLflow и
  почему пусто, вместо молчаливого «Реестр пуст».

**1. «Мои артефакты» — группировка по экспериментам + ручная загрузка.** UI: список экспериментов,
внутри — раны-сессии (`_render_session`). Новый `POST /api/v1/artifacts/manual` (+`mlflow_utils.
create_manual_run`) — подгрузка отдельного артефакта без связи с экспериментом (создаёт ран в личном
`{user}_manual`-эксперименте, штампует владельца). Доступно DS/DE/MLSecOps.

**2. Дашборд / мониторинг рантайма.** Новый `GET /api/v1/monitoring/models` — карточки моделей
(prod/выкатка/прошли проверку) с метриками обучения, тегами паспорта (`model.name`/`model.description`,
плейсхолдер) и ПЛЕЙСХОЛДЕР-инференс-метриками (p95 latency / throughput / error-rate / запросы-24ч,
детерминированы по run_id). HITL-очередь (`/approvals/pending`) переписана DB-driven (только pending-раны,
без скана 200 ранов) — больше не «моргает» ошибкой при медленном MLflow; UI устойчив к недоступности.

**3. Страница ПРОД (новая, `ui/app.py page_prod`).** Раздел «Прод» (MLSecOps/CEO/Product). Текущий
прод, кандидаты (approved), предыдущие. Кнопки: откат / вывод / в прод (replace) / вернуть в прод
(restore). Новый `POST /api/v1/artifacts/{run_id}/restore` (previous/approved/retired → prod, вытесняя
текущий). CI/CD — ФИКТИВНЫЙ (`_fake_cicd` анимация шагов).

**4. Реестр — кнопка «в прод» по роли уже была; добавлено:** реестр теперь показывает и DB-only
артефакты (без живого MLflow-рана) — ручные сиды/демо-инциденты видны в зоне «не прошли», даже если
MLflow недоступен.

**5. Инциденты.** `python -m infra.seed_demo_incidents` засеян в `mlsec_dev.db` (2 заваленных
артефакта: G1 class_balance / G2 secrets) — видно в «Инциденты» и в реестре (зона «не прошли»).

**6. Пример `examples/dev_train_mock.py` — переписан проще,** наглядное ВЕРСИОНИРОВАНИЕ: одна модель
`demo_model` обучается 3 раза (C=0.01/0.1/1.0) → 3 версии в Model Registry; данные версионируются через
`log_input` (digest). `log_model` совместим с MLflow 2.x и 3.x. В конце печатает список версий.

**7. MLflow backend store → НАША БД (контроль/безопасность).**
- compose: MLflow `--backend-store-uri` = **отдельная БД `mlflow` на нашем Postgres** (создаётся
  `infra/init_mlflow_db.sql`), артефакты — наш MinIO. ВАЖНО: отдельная БД, т.к. схемы MLflow и наша
  обе содержат таблицы `datasets` и `model_versions` — в одной БД был бы конфликт.
- дев (`infra/start.cmd`): store = **`%REPO%\mlsec_mlflow.db`** (в репо, под нашим контролем; НЕ
  mlsec_dev.db — из-за того же конфликта имён). Артефакты — на диске (чистый путь).
- `.env.example`: `MLFLOW_BACKEND_STORE_URI`. `core/db.py`: `busy_timeout` (без WAL — WAL ломается на
  части ФС). `.gitignore`: `mlsec_mlflow.db`, `*.db-wal/shm`.

**Временные диагност-скрипты в репо (можно удалить):** `_tmp_diag.py`, `examples/_e2e_check.py` —
не смог удалить из песочницы (права на маунт); удали вручную, в гит не коммить.

---

# MLSecOps Platform — Handoff (исходный)

> Этот файл — подробное саммари реализованного. Используй как контекст-промпт.
> Дата среза: реализованы шаги 1–5 (аутентификация, RBAC, личный кабинет, MLflow-интеграция)
> + **приватность и контролируемый шаринг артефактов MLflow** (см. подробный §9 в конце файла)
> + запуск стенда одной командой `infra\start.cmd` (§9.10).

---

## 0. Что это за проект

Платформа **MLSecOps** — слой управления и безопасности над MLOps. Полная документация — в
папке `docs/` (читай при необходимости): `04_ARCHITECTURE.md`, `06_IDENTITY_AND_AUTH.md`,
`09_DATA_MODEL.md`, `11_BACKEND_API.md`, `18_MLFLOW.md`, `03_PERSONAS_AND_ROLES.md`.

Суть: разработчики (DS/DE) экспериментируют в MLflow под своим аккаунтом, затем «пушат»
лучшую модель/датасет в реестр через кнопку → запускаются security-гейты (G0–G7) → если ОК,
артефакт попадает в чистую зону / прод. MLSecOps — админ, выдаёт роли/доступы, делает HITL-Approve.

**Стек:** Python 3.11+ (локально 3.13), FastAPI (бэкенд), Streamlit (UI), PostgreSQL (прод) /
SQLite (дев), MinIO (S3, прод), MLflow (трекинг+реестр), Redis, Docker compose, GitHub Actions.

---

## 1. Ключевые архитектурные решения (ВАЖНО, не переделывай без причины)

1. **Локальный JWT-issuer в бэкенде** (HS256, python-jose), НЕ внешний Keycloak. Один JWT
   действителен и для нашего API, и (через auth-прокси) для MLflow. Секрет — `JWT_SECRET` из env.
2. **Пароли — библиотека `bcrypt` напрямую** (НЕ passlib: passlib 1.7.4 несовместим с bcrypt 5.0,
   падает на `detect_wrap_bug`). Bcrypt-лимит 72 байта режем явно.
3. **БД с двумя бэкендами через env `DB_BACKEND`:** `sqlite` (дев, по умолчанию, файл `mlsec_dev.db`
   в корне репо) и `postgres` (прод/compose). В SQL пишем плейсхолдеры `?`, для pg транслируем в `%s`.
   JSON-поля через `_json_param`/`_json_load` (TEXT в sqlite, JSONB в pg).
4. **Саморегистрация без роли** (`/auth/register` создаёт юзера без роли); роль выдаёт только
   MLSecOps через `/admin/roles`. До выдачи роли юзер логинится, но ничего привилегированного не может.
5. **Личность (`current_user`)** берётся из `Bearer`-токена. Заголовок `X-Authenticated-User`
   доверяется ТОЛЬКО при `TRUST_PROXY_HEADER=true` (иначе клиент мог бы подделать личность).
6. **RBAC:** в `require_role` роли берутся из БД (а не из токена) — чтобы отзыв роли действовал сразу.
   Любой отказ → HTTP 403 + событие `access_denied` в Audit Trail.
7. **MLflow за auth-прокси.** MLflow OSS не имеет пер-юзер RBAC, поэтому наружу не публикуется.
   Единственный вход — наш роут `/mlflow/{path}`: валидирует JWT → штампует `X-Authenticated-User`
   → проксирует во внутренний MLflow. Бэкенд для ЧТЕНИЯ ходит в MLflow напрямую (server-side).
8. **Audit Trail с hash-chain:** `events.row_hash = sha256(prev_hash + canonical_payload)`,
   genesis = `'0'*64`. `verify_chain()` ловит подделку. Единственная точка записи — `log_event()`.

---

## 2. Что РЕАЛИЗОВАНО (по файлам)

### `core/db.py` — слой БД, аудит, RBAC ✅
- `get_conn()` — SQLite или psycopg по `DB_BACKEND`.
- `init_db()` — создаёт схему для SQLite (в Postgres схему ставит `infra/init.sql`).
- `_sql()`, `_json_param()`, `_json_load()`, `_tx()` — хелперы (трансляция плейсхолдеров, JSON, транзакции).
- **Audit:** `log_event(actor, role, action, *, asset, result, reason, details)`,
  `verify_chain() -> {ok, broken_at, count}`, `list_events(limit)`.
- **RBAC:** `register_user(username, email, password_hash)`, `get_user(username)`,
  `set_password`, `list_users()`, `assign_role`, `revoke_role`, `get_roles(username) -> set`,
  `grant_access`, `has_dataset_access`.
- **Реестр (НЕ реализовано, TODO-заглушки с NotImplementedError):** `register_dataset`,
  `register_model`, `add_model_version`, `set_status`, `add_finding`, `mark_false_positive`.
- Демо-самопроверка в `if __name__ == "__main__"`: `python core/db.py`.

### `core/identity.py` — пароли, JWT, RBAC ✅
- `hash_password`, `verify_password` (bcrypt).
- `create_token(username, roles, ttl_hours)`, `decode_token(token)` (JWT HS256).
- `authenticate(username, password) -> {username, roles}` (сверка с БД).
- `current_user(request) -> username` (из Bearer; X-Authenticated-User только при TRUST_PROXY_HEADER).
- `token_roles`, `get_roles`, `require_role(request, role)`, `effective_role(request)`.
- `AuthError`, константа `ROLES = {DS, DE, MLSecOps, Product, CEO}`.
- Демо: `python -m core.identity`.

### `core/mlflow_utils.py` — доступ к MLflow (частично) ✅/TODO
- `_client()` — MlflowClient на `MLFLOW_UPSTREAM_URL` (server-side, напрямую).
- `list_recent_runs(limit)` — раны по всем экспериментам (для UI).
- `list_models()` — зарегистрированные модели из MLflow Registry.
- **TODO:** `list_runs(model)`, `get_run_metadata(run_id)`, `download_artifacts`,
  `register_model_version`, `set_alias` (нужны для `/verify` и реестра).

### `src/api/main.py` — FastAPI Gatekeeper ✅ (auth) / TODO (домен)
При старте: `db.init_db()` + подключает `mlflow_proxy.router`.
**Реализованные эндпоинты:**
| Метод | Путь | Доступ | Назначение |
|---|---|---|---|
| POST | `/api/v1/auth/register` | все | саморегистрация (без роли) |
| POST | `/api/v1/auth/login` | все | логин → JWT `{access_token, roles}` |
| GET  | `/api/v1/auth/me` | Bearer | кто я + роли |
| POST | `/api/v1/auth/token` | Bearer | свежий токен + сниппет для MLflow SDK |
| GET  | `/api/v1/models` | все | модели из MLflow Registry |
| GET  | `/api/v1/mlflow/runs` | Bearer | последние раны из MLflow |
| GET  | `/api/v1/events` | все | Audit Trail (новые сверху) |
| POST | `/api/v1/admin/users` | MLSecOps | создать юзера (+роли) |
| GET  | `/api/v1/admin/users` | MLSecOps | список юзеров с ролями |
| POST | `/api/v1/admin/roles` | MLSecOps | назначить роль |
| POST | `/api/v1/admin/access` | MLSecOps | выдать доступ к датасету (+can_export) |
| POST | `/api/v1/ci/trigger` | все | запуск гейта (GitHub Actions dispatch или локально) |
| POST | `/api/v1/upload`, GET `/api/v1/files` | все | загрузка/список CSV |

**Заглушки (возвращают `{"status":"TODO"}` или пустоту):** `/verify`, `/train`,
`/deploy/...`, `/deploy/.../approve`, `/prod/.../rollback`, `/prod/.../retire`,
`/scan/...`, `/datasets/ingest`, `/findings`, `/findings/.../false_positive`,
`/registry`, `/runs?model=`.
**Хелпер `_require(request, role)`** — 401 если нет личности, 403 + `access_denied` если нет роли.
Демо (TestClient): `python -X utf8 -m src.api.main`.

### `src/api/mlflow_proxy.py` — auth-прокси перед MLflow ✅ (+ приватность/шаринг артефактов)
- Роут `/mlflow/{path}` (все методы). Валидирует JWT → ставит `X-Authenticated-User`
  (URL-кодированный через `quote()` — иначе не-ASCII логины ломают latin-1 заголовок) →
  проксирует на `MLFLOW_UPSTREAM_URL` (по умолч. `http://127.0.0.1:5000`) через httpx.
- Без токена → 401. Upstream недоступен → 502.
- **Штамп владельца:** на `runs/create` вписывает в тело неподделываемый тег `mlsecops.owner`
  = личность из токена (заменяя клиентский, если был) и фиксирует владение в БД
  (`set_experiment_owner`, `upsert_artifact`); на `experiments/create` — `set_experiment_owner`.
- **Фильтрация видимости:** на `runs/search`/`experiments/search` вырезает из ответа MLflow то,
  что пользователь видеть не должен; на `runs/get`/`experiments/get` чужое приватное → 403.
  Политика — `core.identity.can_view_artifact`. При перезаписи тела дропаем `content-encoding`.
  Не отслеживаемые (legacy/Default) эксперименты НЕ прячем (fail-open) — задокументированный предел.

### Приватность + контролируемый шаринг артефактов MLflow ✅ (НОВОЕ)
Требование: артефакты разработчика приватны по умолчанию; чтобы расшарить — пройти security check;
видны только ролям с таким же клиренсом или выше (read-down) либо явному списку ролей.
- **Единица владения** — эксперимент на разработчика; **единица шаринга** — ран (= «сессия
  разработки»: data+код+модель в одном ноутбуке). Владелец = серверный штамп прокси.
- **Клиренс ролей** (`core/identity.py` `ROLE_LEVEL`): DS/DE=1, Product=2, MLSecOps=3, CEO=4.
  `clearance(roles)` + `can_view_artifact(acl, user, roles)` — чистая политика видимости.
- **БД** (`core/db.py`, таблицы `experiment_owner`, `artifact_acl`): `set_experiment_owner`,
  `get_experiment_owner`, `list_owned_experiments`, `upsert_artifact`, `get_artifact_acl`,
  `list_artifact_acls`, `list_shared_acls`, `set_check_status`, `share_artifact`, `unshare_artifact`.
- **Security check** (`core/security_check.py`) — **ПЛЕЙСХОЛДЕР**: реальной логики гейтов нет,
  есть стабильный контракт результата + дебаг-вывод. Запуск ТОЛЬКО по кнопке из ЛК (не из IDE).
- **Ручки бэка** (`src/api/main.py`): `GET /api/v1/artifacts` (мои + расшаренные мне),
  `POST /api/v1/artifacts/{run_id}/check` (владелец, плейсхолдер),
  `POST .../share` (после check; `roles=null` → по клиренсу, `roles=[...]` → кастомно),
  `POST .../unshare`. Всё пишет `log_event` (`artifact_security_check`/`artifact_shared`/...).
- **UI** (`ui/app.py`): вкладка «Мои артефакты» — список сессий, кнопки «Запустить security check»,
  «Поделиться» (с мультиселектом кастомных ролей), «Снять шаринг» + блок «Доступно мне».
- **Хелперы** `core/mlflow_utils.py`: `get_run(run_id)`, `_run_to_dict` (+`experiment_id`,`owner`),
  константа `OWNER_TAG="mlsecops.owner"`.

### `ui/app.py` — Streamlit UI ✅
- Экран входа/регистрации (токен в `st.session_state`).
- Сайдбар: имя, роли, «Выйти».
- Вкладки (по ролям): **Личный кабинет** (/me + кнопка «Получить MLflow-токен» со сниппетом),
  **MLflow раны** (таблица из `/api/v1/mlflow/runs` + ссылка на MLflow UI),
  **Сканеры** (`/ci/trigger`), **История событий** (`/events`),
  **Админка** (только MLSecOps: назначение ролей, создание юзеров, выдача доступа).
- Все запросы с `Authorization: Bearer`. Дефолт `GATEKEEPER_URL=http://localhost:8200`.

### `infra/seed_admin.py` — bootstrap первого админа ✅
- Создаёт `msecops` + роль MLSecOps (идемпотентно). Пароль из `BOOTSTRAP_ADMIN_PASSWORD` (дефолт `admin-pass`).
- Запуск: `python -m infra.seed_admin`.

### `infra/run_local.ps1` — запуск всего дев-стенда (Windows) ✅
- Поднимает в 3 окнах: MLflow (:5000), backend (:8200), Streamlit (:8501) + сидит админа.
- MLflow-данные кладёт в `%USERPROFILE%\mlsec_mlflow` (ВНЕ репо — см. урок ниже).

### Тесты / примеры ✅
- `tests/mlflow_smoke.py` — e2e: логин → MLflow через прокси → чтение обратно.
- `examples/dev_train_mock.py` — «ноутбук разработчика»: логин → токен → реальное ML-исследование
  (sklearn на `load_breast_cancer`, sweep из 4 сессий) → `mlflow.log_*` через прокси (с префлайтом и
  fail-fast таймаутами). **argparse убран**, креды (`DEV_USER`/`DEV_PASSWORD`) хардкодом вверху файла.
  Подробно — §9.9.

### Конфиги
- `infra/init.sql` — схема Postgres (добавлена колонка `users.password_hash`).
- `requirements.txt` — добавлены `bcrypt`, `python-jose[cryptography]`, `httpx`.
- `.env.example` — добавлены `MLFLOW_UPSTREAM_URL`, `DB_BACKEND`, `JWT_SECRET`, `BOOTSTRAP_ADMIN_PASSWORD`.
- `.gitignore` — добавлены `*.db`, `mlartifacts/`.

---

## 3. Модель данных (таблицы, общие для sqlite/pg)

`events` (audit, hash-chain: prev_hash, row_hash), `users` (+password_hash), `roles` (user_id, role),
`dataset_access`, `datasets`, `verified_datasets`, `models`, `model_versions`, `findings`.
Полные определения — `docs/09_DATA_MODEL.md` и `infra/init.sql`. Роли: DS, DE, MLSecOps, Product, CEO.

---

## 4. Как запустить и протестировать

### Запуск (Windows, локально, без Docker)
```powershell
.\infra\start.cmd          # РЕКОМЕНДУЕТСЯ: ASCII-батник, без ExecutionPolicy (см. §9.10)
# либо старый способ:
powershell -ExecutionPolicy Bypass -File infra\run_local.ps1
```
Поднимет: MLflow :5000, backend :8200 (`/docs` — Swagger), UI :8501. Остановить: `.\infra\stop.cmd`.
Админ по умолчанию: **msecops / admin-pass**.
> Порт бэка локально — **8200**, НЕ 8000: на Windows с Hyper-V/WSL2/Docker порт 8000 часто
> попадает в зарезервированный winnat-диапазон (7904–8003) → uvicorn падает с `WinError 10013`.
> В Docker остаётся 8000 (внутри контейнеров резерв хоста не действует).

### Запуск вручную (3 терминала)
```powershell
# 0) один раз — админ
$env:BOOTSTRAP_ADMIN_PASSWORD="admin-pass"; python -m infra.seed_admin
# 1) MLflow (ВАЖНО: file:/// URI и путь без пробелов/кириллицы!)
python -X utf8 -m mlflow server --backend-store-uri "sqlite:///C:/Users/<USER>/mlsec_mlflow/mlflow.db" `
  --artifacts-destination "file:///C:/Users/<USER>/mlsec_mlflow/artifacts" --host 127.0.0.1 --port 5000 --workers 1
# 2) backend
$env:DB_BACKEND="sqlite"; $env:MLFLOW_UPSTREAM_URL="http://127.0.0.1:5000"
python -X utf8 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8200
# 3) UI
python -X utf8 -m streamlit run ui/app.py --server.port 8501
```

### Сценарий теста (полный, проверен)
1. UI → войти `msecops`/`admin-pass`.
2. Зарегать разраба (вкладка Регистрация), напр. `vasya`/`pw123`.
3. Админ → Админка → назначить `vasya` роль `DS`.
4. `vasya` входит → Личный кабинет → «Получить MLflow-токен».
5. `python examples\dev_train_mock.py --user vasya --password pw123` — логирует run в MLflow через прокси.
6. Результат виден: UI вкладка «MLflow раны» + MLflow UI (:5000).

### Где данные
- Наша БД (дев): `mlsec_dev.db` (SQLite, корень репо) — открывать DB Browser/DBeaver.
- MLflow стор: `%USERPROFILE%\mlsec_mlflow\mlflow.db` + `\artifacts`.

---

## 5. Уроки/грабли (НЕ наступай снова)

1. **passlib ✗ с bcrypt 5.0** — используем `bcrypt` напрямую.
2. **MLflow на Windows + артефакты:** `--artifacts-destination` ДОЛЖЕН быть `file:///C:/...`-URI
   (raw-путь `C:/...` MLflow принимает за схему `c:` → 500). Путь репо содержит пробел+кириллицу
   («Новая папка») → ломает file://-URI, поэтому MLflow-данные держим в `%USERPROFILE%\mlsec_mlflow`.
3. **Зомби-процессы MLflow:** `mlflow server` плодит воркеры, которые наследуют сокет :5000 и
   переживают убийство родителя. Если порт занят — `Get-NetTCPConnection -LocalPort 5000`,
   убивать воркеры по командной строке (CIM/taskkill). Для дева используем `--workers 1`.
4. **Не-ASCII логин ломал прокси:** `X-Authenticated-User` — HTTP-заголовок (latin-1), httpx падал
   UnicodeEncodeError → 500. Фикс: `quote(user, safe="")`. Всё, что в заголовках — ASCII-safe.
5. **FastAPI без `--reload`** — после правок бэкенда его надо перезапускать вручную.
6. **Вывод кириллицы в консоль Windows** — запускать с `python -X utf8`.

---

## 6. Что НЕ сделано (следующие шаги, по приоритету)

1. **`POST /api/v1/verify`** (ГЛАВНАЯ ручка, docs/11 §11.3): по `run_id` тянуть из MLflow
   метаданные (security.* теги, dataset hash, git_sha), определять ветку (своя модель / external),
   запускать гейты, писать `findings`+`events`, ставить статус (approved/pending_hitl/quarantine).
   Нужны хелперы `mlflow_utils.get_run_metadata`, `download_artifacts`.
2. **Реестр моделей:** реализовать `db.register_model`, `db.add_model_version`, `db.set_status`,
   `mlflow_utils.register_model_version`, `set_alias`; wired `/api/v1/registry`.
3. **Находки:** `db.add_finding`, `db.mark_false_positive`, `/findings`, `/findings/.../false_positive`.
4. **Прод-операции:** `/train`, `/deploy`, `/approve` (HITL для Tier=HIGH), `/rollback`, `/retire`
   — все за `require_role("MLSecOps")` (кроме train: DS/MLSecOps), с обязательным `reason` + событием.
5. **Назначение Tier** (авто-правила + ручное MLSecOps), docs/06 §6.5.
6. **Онбординг датасетов:** `/datasets/ingest` (обёртка над `src/ingest_dataset/`).
7. **Неподделываемая личность в MLflow-ране:** ✅ частично — прокси штампует серверный тег
   `mlsecops.owner` на `runs/create` (см. приватность/шаринг). Остаётся при желании переписывать
   и сам `mlflow.user` из JWT для единообразия отображения в нативном MLflow UI.
   Также НЕ закрыто: фильтрация артефакт-эндпоинтов (`get-artifact`, скачивание весов) и
   ajax-api нативного MLflow Web UI — изоляция там опирается на тот же штамп, но не фильтруется.
8. **Postgres-режим:** прогнать всё на `DB_BACKEND=postgres` + Docker compose (Postgres+MinIO+MLflow за прокси).
9. **Валидация username** при регистрации (разрешить `[a-z0-9_.-]`, чтобы избегать проблем с SSO/MLflow/заголовками).

---

## 7. GitHub Actions (статус)

Репо `Kondachello/MlSecOps`, дефолтная ветка **`sasha`**. `repository_dispatch` РАБОТАЕТ
(`scan.yml` триггерится на sasha). Раны падают, т.к. `code_gate` на `target='.'` ловит bandit-issues
в `demo/insecure/` (exit 1) + gitleaks не установлен (SKIP). Это «работает как задумано», не баг интеграции.
Минус: `repository_dispatch` — fire-and-forget, результат гейта обратно в бэкенд не возвращается.

---

## 8. Env-переменные (основные)
`DB_BACKEND` (sqlite|postgres), `SQLITE_PATH`, `POSTGRES_*`, `JWT_SECRET`, `TOKEN_TTL_HOURS`,
`AUTH_PROXY_HEADER`, `TRUST_PROXY_HEADER`, `APP_DEBUG`, `MLFLOW_UPSTREAM_URL`, `MLFLOW_TRACKING_URI`,
`GATEKEEPER_URL` (UI→backend), `BOOTSTRAP_ADMIN_USER/EMAIL/PASSWORD`, `GITHUB_TOKEN/REPO/REF`,
`MLFLOW_HTTP_REQUEST_TIMEOUT` / `MLFLOW_HTTP_REQUEST_MAX_RETRIES` (fail-fast серверного MLflow-клиента,
см. §9.11), `BOOTSTRAP_ADMIN_PASSWORD` (для `start.cmd`/seed_admin).

---

# 9. СЕССИЯ «Приватность + контролируемый шаринг артефактов MLflow» — ПОДРОБНО

> Этот раздел дописан целиком по итогам отдельной рабочей сессии. Он самодостаточен:
> здесь и бизнес-постановка (что и зачем), и точная техническая реализация (как),
> и диагностика/фиксы, и новые грабли. Если читаешь только ради этой фичи — читай §9.

## 9.0 Бизнес-логика и постановка (что обсуждали вначале, дословно по смыслу)

**Исходное требование пользователя:**
«Артефакты, разрабатываемые разными разработчиками и сохраняемые в MLflow, должны быть
**доступны только им** (приватны по умолчанию). Чтобы их **расшарить**, разработчик должен
**пройти security check**. После шаринга артефакты **видны только ролям с таким же уровнем
доступа или ниже** (в нашей реализации — см. ниже про read-down)».

**Уточнения, которые мы согласовали (важно — это зафиксированные продуктовые решения):**

1. **Единица владения = эксперимент на разработчика.** У каждого DS/DE свой MLflow-эксперимент
   («его аккаунт»). Всё, что он туда логирует, по умолчанию приватно и видно только ему.
2. **Единица шаринга = MLflow run = «сессия разработки».** Сессия — это data+код+модель в одном
   ноутбуке (через MLflow: `log_input` датасета для lineage, `log_param/metric`, артефакты модели).
   Наш сервис подтягивает раны из MLflow и показывает их как «сессии».
3. **Уровни доступа (клиренс) ролей + кастомный шаринг.** По умолчанию видимость определяется
   клиренсом роли (read-down, см. §9.4). НО должна быть возможность задать **кастомный шаринг** —
   явно указать конкретные роли, которым артефакт виден, переопределяя клиренс.
4. **Security check — НЕ реализуем логику сейчас.** Пользователь явно попросил: на этом шаге
   сделать только **ручки бэка + минимальный пример + дебаг-вывод + плейсхолдеры**, чтобы видеть,
   что поток работает. Реальные гейты подключим позже.
5. **Триггер security check — ТОЛЬКО кнопка из ЛК нашего сервиса** (не из IDE). Разработчик
   работает в IDE/ноутбуке через MLflow; из MLflow артефакты подгружаются в наш сервис; и уже
   там, в личном кабинете, есть кнопка «Запустить проверку на безопасность».
6. **Изоляция как принцип.** Дословно: «есть отдельный акк разраба в MLflow, и всё, что
   происходит в нём, происходит в нём. А дальше шаринг между друг другом должен происходить
   контролируемо». → каждый эксперимент изолирован; шаринг — явное контролируемое действие.

**Бизнес-смысл (зачем это для MLSecOps-платформы):** это закрывает класс угроз «утечка/кража
наработок и непроверенных артефактов между командами» и «попадание непроверенного артефакта в
общий доступ». Артефакт не может стать видимым другим, пока владелец явно не прогнал проверку и
не нажал «Поделиться»; видимость ограничена клиренсом (least privilege) либо явным allow-list ролей;
каждое действие (проверка/шаринг/снятие шаринга/отказ доступа) пишется в неподделываемый Audit Trail.

## 9.1 Концептуальная модель (итоговая)

```
MLflow эксперимент  ──владелец(серверный штамп)──►  один DS/DE
   └── run (сессия: data+код+модель)  ──►  единица приватности/шаринга
         ├─ check_status: none → pending → passed/failed   (security check, плейсхолдер)
         └─ share_status: private (дефолт) → shared
                shared может быть:
                  • по клиренсу (share_level)         → read-down (см. §9.4)
                  • по кастомным ролям (share_roles)  → явный allow-list ролей
```

- **Источник правды по владению/видимости/проверкам = наш Postgres/SQLite** (таблицы
  `experiment_owner`, `artifact_acl`). MLflow остаётся источником правды по самим артефактам/ранам.
- **Личность владельца неподделываема:** её ставит auth-прокси из проверенного JWT, а не клиент.

## 9.2 Уровни доступа ролей (клиренс) — `core/identity.py`

```python
ROLE_LEVEL = {"DS": 1, "DE": 1, "Product": 2, "MLSecOps": 3, "CEO": 4}

def clearance(roles) -> int:        # макс. уровень среди ролей пользователя, 0 если ролей нет
    return max((ROLE_LEVEL.get(r, 0) for r in roles), default=0)
```

Обоснование порядка: DS/DE — базовый рабочий уровень (1); Product — продуктовый (2); MLSecOps —
безопасность/надзор (3); CEO — максимум (4). Порядок можно менять в одном месте (`ROLE_LEVEL`).

## 9.3 Модель данных (новые таблицы) — `core/db.py` (sqlite) и `infra/init.sql` (pg)

### `experiment_owner` — кто владеет экспериментом
```
experiment_id TEXT PK     -- MLflow experiment_id
owner         TEXT        -- первый писатель = владелец (штамп прокси), не перезаписывается
created_at    TS
```

### `artifact_acl` — ACL рана (сессии): владение + статус проверки + параметры шаринга
```
run_id        TEXT PK     -- MLflow run id
experiment_id TEXT
owner         TEXT        -- кто залогировал ран (штамп прокси из X-Authenticated-User)
session_name  TEXT        -- человекочитаемое имя (run_name)
check_status  TEXT        -- none | pending | passed | failed   (DEFAULT none)
check_detail  TEXT/JSONB  -- результат security check (плейсхолдер; JSON)
share_status  TEXT        -- private | shared                    (DEFAULT private)
share_level   INT         -- клиренс-уровень видимости (NULL пока приватный/кастомный)
share_roles   TEXT/JSONB  -- кастомный список ролей (переопределяет share_level), NULL = по клиренсу
shared_by     TEXT
created_at, updated_at TS
```

### Новые функции `core/db.py`
- `set_experiment_owner(experiment_id, owner)` — фикс первого писателя (идемпотентно, ON CONFLICT DO NOTHING).
- `get_experiment_owner(experiment_id) -> str|None`.
- `list_owned_experiments(owner) -> set[experiment_id]`.
- `upsert_artifact(run_id, experiment_id, owner, session_name=None)` — регистрация рана; владелец
  НЕ перезаписывается (ON CONFLICT обновляет только session_name через COALESCE).
- `upsert_artifacts_bulk(rows)` — **пакетная** регистрация ОДНОЙ транзакцией (`executemany`); добавлена
  ради производительности ленивой регистрации (см. §9.11, иначе N×commit = таймаут на Windows).
- `get_artifact_acl(run_id) -> dict|None`, `list_artifact_acls(run_ids|None) -> {run_id: acl}` (батч),
  `list_shared_acls() -> [acl]` (все расшаренные — для вычисления видимых экспериментов на прокси).
- `set_check_status(run_id, status, detail=None)` — записать результат проверки.
- `share_artifact(run_id, *, level, roles, shared_by)` — пометить shared (level XOR roles).
- `unshare_artifact(run_id)` — вернуть в private (обнуляет level/roles).

## 9.4 Политика видимости (чистая функция) — `core/identity.can_view_artifact`

```python
def can_view_artifact(acl, username, roles) -> bool:
    if acl.get("owner") == username:            # владелец всегда видит своё
        return True
    if acl.get("share_status") != "shared":     # приватное — только владельцу
        return False
    custom = acl.get("share_roles")
    if custom:                                   # кастомный шаринг: явный allow-list ролей
        return any(r in custom for r in roles)
    return clearance(roles) >= (acl.get("share_level") or 0)   # иначе read-down по клиренсу
```

**ВАЖНО про «таким же или ниже» vs реализованный read-down.** Пользователь сформулировал «видны
ролям с таким же уровнем или ниже». Мы реализовали практичную модель допуска (как в системах
секретности): артефакту при дефолтном шаринге присваивается **уровень = клиренс владельца**
(`share_level`), и его видят роли с **clearance ≥ share_level** — то есть владелец и все, кто
**равны или СТАРШЕ** (read-down: старший видит наработки младшего). Это осознанное решение
(старшие роли/безопасность видят расшаренное младшими, но не наоборот). Если бизнес-смысл нужен
буквально «равные или младше» — поменять сравнение в одной строке. Кастомный шаринг (`share_roles`)
полностью переопределяет клиренс явным списком ролей.

## 9.5 Прокси: штамп владельца + фильтрация видимости — `src/api/mlflow_proxy.py`

Точка входа `/mlflow/{path}` (как и раньше валидирует JWT и ставит `X-Authenticated-User`).
Добавлено:

- **`_action(path)`** — нормализует путь MLflow в action: `api/2.0/mlflow/runs/search` → `runs/search`
  (split по `mlflow/`), работает и для `ajax-api/...`.
- **Штамп владельца в тело `runs/create`** (`_stamp_owner_in_body`): вписывает/заменяет тег
  `mlsecops.owner = <user из токена>` (неподделываем; клиентский тег с тем же ключом удаляется).
- **Фиксация владения из ОТВЕТА** (`_record_create`): на `runs/create` → `set_experiment_owner` +
  `upsert_artifact(owner=user, session_name=run_name)`; на `experiments/create` → `set_experiment_owner`.
  Это работает независимо от кодировки запроса клиента (читаем ответ, а не тело запроса).
- **Фильтрация ответов чтения** (`_apply_visibility`, возвращает `(status, bytes)` или `None`):
  - `runs/search`, `experiments/search`/`experiments/list` — вырезает невидимые элементы;
  - `runs/get`, `experiments/get` — чужое приватное → **403** (`PERMISSION_DENIED`);
  - при перезаписи тела ответа дропаем `content-encoding` (`_DROP_ON_REWRITE`), т.к. отдаём
    уже декодированный/перекодированный JSON.
- **`_synth_acl(run, db_acls)`** — берёт ACL рана из БД; если строки нет — синтезирует приватный
  ACL с owner из тега `mlsecops.owner` → fallback `mlflow.user` → `user_id`.
- **Предел (fail-open):** эксперименты без записи `experiment_owner` (legacy/Default) НЕ прячем —
  чтобы не ломать существующие данные. Это задокументированный компромисс.

## 9.6 Ручки бэкенда — `src/api/main.py`

Хелперы: `_current_user(request)` (→401), `_primary_role(username)`, `_ensure_artifact(run_id)`
(лениво регистрирует ран в ACL по данным MLflow, возвращает `(acl, run_meta)`; `(None,None)` если
рана нет в MLflow).

| Метод | Путь | Доступ | Назначение |
|---|---|---|---|
| GET  | `/api/v1/artifacts` | Bearer | `{mine, shared_with_me, my_clearance}`. Тянет раны из MLflow, мёржит с ACL, делит на «мои»/«доступные мне» по `can_view_artifact`. Ленивая регистрация владения — **батчем** (`upsert_artifacts_bulk`). |
| POST | `/api/v1/artifacts/{run_id}/check` | владелец | Запуск security check (ПЛЕЙСХОЛДЕР). Не владелец → 403 + `access_denied`. Пишет `check_status` (`pending`→`passed/failed`) и событие `artifact_security_check`. |
| POST | `/api/v1/artifacts/{run_id}/share` | владелец | Тело `ShareRequest{roles?: [..], reason?}`. Требует `check_status=='passed'` (иначе **409**). `roles=null` → шаринг по клиренсу владельца (`share_level=clearance`); `roles=[..]` → кастомный список (валидируется по `identity.ROLES`). Событие `artifact_shared`. |
| POST | `/api/v1/artifacts/{run_id}/unshare` | владелец | Вернуть в private. Событие `artifact_unshared`. |

Новые `action` в Audit Trail: `artifact_security_check`, `artifact_shared`, `artifact_unshared`
(+ существующий `access_denied` при попытке не-владельца).

## 9.7 Security check (ПЛЕЙСХОЛДЕР) — `core/security_check.py`

- `run_artifact_check(run_id, run_meta=None) -> dict` — возвращает стабильный контракт:
  `{passed, run_id, checks: [{check, status, detail}], placeholder: True, debug: {...}}`.
- Сейчас 4 «как будто»-проверки, все PASS: `model_format` (G4: нет .pkl/.joblib/.bin),
  `secret_scan` (секреты в тегах/параметрах), `pii_markers` (PII в датасете), `lineage`
  (git_sha/dataset_hash/trained_in_ci).
- **Печатает дебаг-вывод** в консоль бэкенда (`[security_check] ...`) — видно, что проверка
  реально запускалась.
- В файле перечислены **точки расширения** (TODO), куда подключать реальные гейты.
- Демо модуля: `python core/security_check.py`.

## 9.8 UI — `ui/app.py`, вкладка «Мои артефакты»

- `tab_artifacts()` + хелпер `_share_badge(acl)` (🔒 приватный / 🔗 роли:.. / 🔗 клиренс ≥ N).
- Раздел «Мои артефакты»: по каждой сессии — `run_id`, эксперимент, метрики, и кнопки:
  **«Запустить security check»** → показывает результат (PASS/FAIL + JSON);
  **«Поделиться»** (активна только при `check==passed`) с мультиселектом кастомных ролей
  (пусто → шаринг по клиренсу); **«Снять шаринг»**.
- Раздел «📥 Доступно мне» — таблица расшаренных другими ранов.
- Вкладка добавлена в `tabs_spec` между «Личный кабинет» и «MLflow раны».

## 9.9 Пример «ноутбук разработчика» — `examples/dev_train_mock.py` (переписан)

- **argparse УБРАН.** Логин/пароль к нашему сервису заданы **хардкодом** вверху файла:
  `DEV_USER`, `DEV_PASSWORD` (этот юзер должен быть зарегистрирован и иметь роль DS),
  `EXPERIMENT = f"{DEV_USER}_research"`.
- Реальное (но лёгкое) **ML-исследование**: встроенный датасет `load_breast_cancer` (бинарная
  классификация), `mlflow.data.from_pandas(..., targets="target")` для lineage (Data Digest);
  **sweep из 4 сессий**: LogisticRegression×2 (в пайплайне со `StandardScaler`) и
  RandomForest×2. На каждый ран: `log_input` (lineage), `log_params`, метрики
  (accuracy/precision/recall/f1/roc_auc), ИБ-теги `security.*`, артефакты-отчёты
  `confusion_matrix.json` и `model_card.json`. **Pickle НЕ пишем** (его блокирует G4).
- Сохранены: ранний выставленный `MLFLOW_HTTP_REQUEST_TIMEOUT/MAX_RETRIES` (до import mlflow),
  `login()` и `preflight()` (fail-fast если бэкенд/прокси недоступны).
- Запуск: `python examples\dev_train_mock.py`. В конце печатает понятный гайд «что дальше».

## 9.10 Запуск стенда одной командой — `infra/start.cmd` и `infra/stop.cmd` (НОВОЕ)

Причина появления: пользователю не подходит `powershell -ExecutionPolicy Bypass -File ...`
(ExecutionPolicy блокирует). `.cmd`-батники ExecutionPolicy НЕ касается — запускаются и из
PowerShell, и из cmd, и двойным кликом.

- **`infra\start.cmd`** — сид админа + три окна: MLflow `:5000`, backend `:8200`, Streamlit `:8501`.
  Между MLflow и остальными `timeout /t 3`. MLflow-данные → `%USERPROFILE%\mlsec_mlflow`
  (чистый путь; `file:///`-URI с прямыми слэшами через `set "X=%VAR:\=/%"`). Env (DB_BACKEND,
  MLFLOW_UPSTREAM_URL, GATEKEEPER_URL, APP_DEBUG, BOOTSTRAP_ADMIN_PASSWORD) ставится в родителе,
  дочерние окна наследуют. Запуск: `.\infra\start.cmd`.
- **`infra\stop.cmd`** — гасит слушателей на портах 8200/5000/8501 (`netstat -ano | findstr` →
  `taskkill /F /PID`). Запуск: `.\infra\stop.cmd`.
- **КРИТИЧНО — оба файла ЧИСТО ASCII, без BOM** (см. урок §9.12.1). `run_local.ps1` оставлен как есть.

## 9.11 Диагностика и фиксы этой сессии (почему «артефакты не отображались»)

Симптом 1: при первом запуске примера — `MlflowException: Could not find a source information
resolver for the specified dataset source: synthetic://...`.
- **Причина:** `mlflow.data.from_pandas(source="synthetic://...")` — у MLflow нет резолвера такого URI.
- **Фикс:** убрали аргумент `source` (from_pandas сам считает digest) и перешли на `load_breast_cancer`.
- Заодно `ConvergenceWarning` у LogisticRegression → обернули в `make_pipeline(StandardScaler(), …)`.

Симптом 2: «Не удалось получить артефакты: Read timed out (30s)» / артефакты не видны.
Диагностировали по шагам, нашли ДВЕ независимые причины:
- **(а) Бэкенд крутил устаревший код:** `GET /api/v1/artifacts` отдавал `404` (процесс uvicorn без
  `--reload`, поднят до правок). → Лечится перезапуском бэкенда (или `start.cmd`).
- **(б) MLflow на :5000 был выключен:** серверный MLflow-клиент в `core/mlflow_utils._client()`
  при недоступном MLflow **ретраил ~2 минуты** (грабли из §5.3) → `/artifacts` висел дольше
  таймаута UI (30с). Старые наблюдения «owner=Kolya / тег пуст» — это мусорные раны от старого
  прокси (без штампа), они подмешивались в выдачу и сбивали с толку.
- **Фиксы в коде (чтобы это не вешало UI впредь):**
  1. `core/mlflow_utils.py` — в начале модуля `os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT","5")`
     и `MLFLOW_HTTP_REQUEST_MAX_RETRIES="1"` ДО первого импорта mlflow. Теперь при выключенном
     MLflow `list_recent_runs()` отдаёт `[]` за ~8с, а не висит ~120с (замерено).
  2. `core/db.py` + `main.py` — ленивая регистрация владения теперь **одной транзакцией**
     (`upsert_artifacts_bulk`), а не до 200 отдельных `connect+commit` (на Windows это был бы
     следующий таймаут, когда MLflow поднимется с кучей ранов).

**Доказательство, что фича работает (прогнали в этой сессии):**
- Через TestClient против живого MLflow и через временный бэкенд на `:8010`:
  владелец видит свои раны; другой DS НЕ видит приватные (и в `/artifacts`, и в прокси-`runs/search`),
  `runs/get` чужого приватного → 403; после `check`(PASS)→`share` второй DS и CEO видят ран;
  `unshare` снова скрывает. Кастомный шаринг ролям работает (Product видит, DS нет).
- Сырой `runs/create`/`experiments/create` через прокси: `mlsecops.owner=<user>` штампуется,
  `experiment_owner`/`artifact_acl` записываются сервером. Реальный MLflow-клиент в новом
  эксперименте: `experiment_owner=user`, `artifact_acl.owner=user`, тег `mlsecops.owner=user` — ✅.
- Пример `dev_train_mock.py`: 4 сессии логируются, roc_auc ~0.99, `/artifacts` показывает их «мои».

## 9.12 Новые грабли этой сессии (НЕ наступай снова)

1. **Кириллица в `.cmd` ломает cmd.exe.** `.cmd`/`.bat` файлы парсятся cmd побайтно; UTF-8
   многобайтные символы (русские комментарии/echo) сбивают разбор строк — куски команд утекают как
   «'thon' is not recognized», «'tp:' is not recognized» и т.п. **Батники держим строго ASCII**
   (комментарии/echo — латиницей), без BOM. `chcp 65001` это НЕ лечит надёжно.
2. **Серверный MLflow-клиент без таймаутов вешает ручки.** При недоступном MLflow дефолтные
   ретраи ~2 мин. Всегда ставить `MLFLOW_HTTP_REQUEST_TIMEOUT/MAX_RETRIES` (мы — в `mlflow_utils`).
3. **N отдельных SQLite-коммитов на Windows медленные.** Ленивые upsert'ы в цикле по сотням ранов
   → таймаут. Батчить одной транзакцией (`executemany`).
4. **`mlflow.data.from_pandas` требует резолвимый `source`** (или вовсе без него). Кастомные
   `scheme://...` без зарегистрированного резолвера → исключение.
5. **Не путать «бэкенд не перезапущен» с багом.** FastAPI без `--reload` (§5.5): после правок
   `404` на новой ручке = старый процесс. Проверять перезапуском прежде, чем чинить код.

## 9.13 Точные команды запуска/проверки (этой фичи)

```powershell
# поднять всё одной командой (ASCII-батник, без ExecutionPolicy):
.\infra\start.cmd
# остановить:
.\infra\stop.cmd

# залогировать 4 сессии-исследования (после выдачи DEV_USER роли DS в админке):
python examples\dev_train_mock.py

# офлайн-самопроверки (без поднятого стенда):
python core\db.py               # ACL/шаринг/видимость на чистой sqlite (раздел 6 демо)
python core\security_check.py   # плейсхолдер-проверка + дебаг
python -X utf8 -m src.api.main  # TestClient: auth-поток
```
UI-сценарий: войти `kolya1` → «Мои артефакты» → по сессии «Запустить security check» →
«Поделиться» (или выбрать кастомные роли) → вторым DS-юзером проверить «Доступно мне».

## 9.14 Что осталось/пределы именно по этой фиче (см. также §6 п.7)
- Не фильтруются **artifact-эндпоинты** (`get-artifact`, скачивание весов) и **ajax-api нативного
  MLflow Web UI** — изоляция там опирается на штамп владельца, но ответы не режутся.
- **Fail-open для нетрекаемых экспериментов** (legacy/Default без `experiment_owner`).
- `share_level` хранит число; человекочитаемую подпись делает UI. При желании — отдельный энум.
- Security check — плейсхолдер; подключить реальные гейты (точки расширения в `security_check.py`).
- В Postgres-режиме новые таблицы добавлены в `infra/init.sql`, но на pg ещё не прогонялись.
