# MLSecOps Platform — Техническое описание бэкенда (текущее состояние)

> Дата среза: 2026-06-04 (артефакто-центричный рефакторинг). Бэкенд «A»: FastAPI Gatekeeper +
> ядро `core/` + MLflow за auth-прокси + БД + конфиг-driven цепочка гейтов. Бизнес — в
> [`01_BUSINESS_AND_FEATURES.md`](01_BUSINESS_AND_FEATURES.md), фронт — в [`03_FRONTEND_TECHNICAL.md`](03_FRONTEND_TECHNICAL.md).
> Легенда: ✅ реализовано · 🟡 частично/плейсхолдер · 🚧 заглушка (`not_implemented`).

---

## 1. Обзор

Единый FastAPI-сервис (Gatekeeper, `src/api/main.py`) — точка входа для UI и (через
`/mlflow`-прокси) для MLflow. Личность — из JWT. MLflow наружу не публикуется. Артефакт (MLflow
run) — центральная сущность; «Реестр» строится из MLflow-ранов + таблицы `artifact_acl`, без
отдельной таблицы артефактов.

```
UI ──Bearer──► FastAPI Gatekeeper ──► core.identity (JWT/RBAC/clearance)
ноутбук ──JWT──► /mlflow ──► mlflow_proxy (штамп owner + фильтрация видимости) ──► MLflow upstream
                          ├─ core.db (Audit hash-chain, RBAC, artifact_acl, findings, registry)
                          ├─ core.security_check ──► core.gates_pipeline ──► config/gates.yml
                          └─ core.mlflow_utils (server-side чтение MLflow)
```

---

## 2. Стек
Python 3.11+ · FastAPI · uvicorn · pydantic v2 · bcrypt · python-jose (JWT HS256) · httpx
(прокси) · mlflow · psycopg (pg) · **pyyaml** (конфиг гейтов) · requests · boto3 (MinIO, 🚧) ·
redis (рантайм, не в текущем стенде). Зависимости — `requirements.txt`; у каждого гейта свой.

---

## 3. Структура
```
config/gates.yml      ✅ YAML-конфиг цепочки гейтов (G1..G5; result: pass)
core/
  db.py               ✅ БД: Audit(hash-chain), RBAC, artifact_acl(+lifecycle), findings, registry
  identity.py         ✅ пароли/JWT/RBAC/clearance/can_view_artifact
  gates_pipeline.py   ✅ загрузка YAML + прогон гейтов-плейсхолдеров (PASS + логи)
  security_check.py   🟡 прогон цепочки на артефакте + авто-Tier (плейсхолдер-логика)
  mlflow_utils.py     ✅ server-side доступ к MLflow (раны/модели/реестр/артефакты)
  model_card.py       🟡 паспорт модели (pydantic) + auto_tier + validate_card
  storage.py          🚧 MinIO/S3 + WORM (контракты, реализация TODO)
src/api/
  main.py             ✅/🚧 эндпоинты (auth/artifacts/registry/lifecycle/incidents/admin реальны; verify/train/scan/ingest — 🚧)
  mlflow_proxy.py     ✅ auth-прокси (штамп owner + фильтрация видимости)
src/gates/*           гейты B (data/code/dependency/model/registry) — для /ci/trigger и CI
infra/                seed_admin · init.sql · start/stop.cmd · docker-compose
```

---

## 4. Конфиг гейтов — `config/gates.yml` + `core/gates_pipeline.py` ✅
- **`config/gates.yml`**: `pipeline: [{id, name, description, enabled, severity, threats, result}]`.
  Сейчас все `result: pass`. Путь переопределяется env `GATES_CONFIG`.
- **`gates_pipeline.py`**: `load_pipeline()` (YAML → list; fallback на встроенный дефолт, если нет
  PyYAML/файла), `run_gate(gate, meta)` (ПЛЕЙСХОЛДЕР: исход из конфига + текстовые логи; **точка
  расширения** под реальную логику), `run_pipeline(meta, only=None)` → `{passed, gates:[...]}`,
  `run_single(gate_id, meta)`. Самопроверка: `python core/gates_pipeline.py`.

## 5. Security check — `core/security_check.py` 🟡
- `run_artifact_check(run_id, run_meta, only=None)` → `{passed, run_id, tier, gates:[{id,name,
  description,status,severity,threats,detail,logs}], placeholder, debug}`. Использует
  `gates_pipeline.run_pipeline`. `only=[id]` — для перезапуска одного гейта.
- `compute_tier(meta)` — **плейсхолдер-эвристика**: HIGH, если имя рана/эксперимента/параметры
  содержат `_HIGH_TIER_HINTS = (credit, fraud, scoring, loan, kyc, antifraud, risk)`, иначе MED.
  (Точка расширения: реальный Tier — из паспорта/бизнес-критичности.) HIGH → требует HITL Approve.

## 6. БД — `core/db.py` ✅ (схема в `infra/init.sql` для pg, `_SQLITE_SCHEMA` для дев)

Таблицы: `events` (Audit, hash-chain, append-only), `users`/`roles`/`dataset_access` (RBAC),
`datasets`/`verified_datasets`/`models`/`model_versions` (реестр), `findings` (инциденты),
`experiment_owner`, **`artifact_acl`**.

**`artifact_acl`** (ACL рана + жизненный цикл) — ключевая таблица артефакто-центричной модели:
```
run_id PK · experiment_id · owner (штамп прокси) · session_name
check_status: none|pending|passed|failed · check_detail JSON (цепочка гейтов с логами)
share_status: private|shared · share_level INT · share_roles JSON · shared_by
tier: LOW|MED|HIGH                         ← проставляется на security check
stage: none|pending_approve|approved|prod|previous|retired   ← жизненный цикл выкатки
approved_by · deployed_by · created_at · updated_at
```
Колонки `tier/stage/approved_by/deployed_by` добавляются и для существующих БД через
`_ACL_MIGRATIONS` (ALTER в `init_db`, идемпотентно).

**Функции (реализованы ✅):**
- Audit: `log_event` (единственная точка записи), `list_events`, `verify_chain → {ok,broken_at,count}`.
- RBAC: `register_user/get_user/set_password/list_users/assign_role/revoke_role/get_roles/grant_access/has_dataset_access`.
- Artifact ACL: `set_experiment_owner/get_experiment_owner/upsert_artifact/upsert_artifacts_bulk/
  get_artifact_acl/list_artifact_acls/list_shared_acls/set_check_status/share_artifact/unshare_artifact`.
- **Жизненный цикл (новое):** `set_artifact_tier`, `set_artifact_stage(stage, approved_by=, deployed_by=)`,
  `demote_prod_artifacts(experiment_id, except_run_id)` (прежний прод → previous).
- **Инциденты на `findings` (новое):** `add_finding`, `list_findings(status=, asset=)`,
  `clear_findings_for_asset`, `mark_false_positive`.
- **Реестр БД:** `register_dataset`, `register_model`, `add_model_version`(🟡), `set_status`, `list_models`.

**Audit hash-chain:** `row_hash = sha256(prev_hash + canonical(event))`, genesis `0×64`;
`verify_chain` ловит подделку; в pg отзываются UPDATE/DELETE на `events`.

## 7. Идентичность/RBAC — `core/identity.py` ✅
bcrypt-пароли; JWT HS256 (`create_token/decode_token`); `authenticate`; `current_user` (Bearer;
`X-Authenticated-User` только при `TRUST_PROXY_HEADER`); `get_roles` (из БД), `require_role`;
`ROLES`, `ROLE_LEVEL={DS:1,DE:1,Product:2,MLSecOps:3,CEO:4}`, `clearance`, `can_view_artifact`
(владелец / shared по ролям / read-down по клиренсу).

## 8. MLflow — `core/mlflow_utils.py` ✅ / `src/api/mlflow_proxy.py` ✅
- **mlflow_utils** (server-side, fail-fast таймауты): `list_recent_runs`, `get_run`, `list_models`,
  `list_runs(model)`, `get_run_metadata` (security.* теги, dataset digest, git_sha),
  `download_artifacts`, `register_model_version`, `set_alias`. `_run_to_dict` теперь включает
  **`tags`** (security.*/research.*/mlsecops.owner) — для авто-Tier и фильтра по тегам в реестре.
- **mlflow_proxy** `/mlflow/{path}`: JWT → штамп `X-Authenticated-User` + тег `mlsecops.owner` на
  `runs/create`; фиксация владения; **фильтрация видимости** на search/get (чужое приватное
  вырезается / 403). Пределы: не фильтруются artifact-эндпоинты; fail-open для legacy-экспериментов.

## 9. API — `src/api/main.py`

**Хелперы:** `_require(role)` (403+событие), `_current_user`, `_ensure_artifact(run_id)→(acl,meta)`,
**`_artifact_zone(acl)`** (draft/failed/ok/deploying/prod/previous/retired по check_status+stage),
**`_registry_visible(acl,user,roles)`** (владелец; MLSecOps видит сабмиченные `check!=none`; иначе
shared), **`_enrich_artifact(run,acl)`** (карточка: +zone +tags), **`_sync_incidents(run_id,gates)`**
(пересоздать инциденты из FAIL-гейтов).

**Эндпоинты:**

Auth ✅ — `/auth/register|login|me|token`.

Артефакты (приватность/шаринг) ✅ — `GET /artifacts` (`{mine, shared_with_me, my_clearance}`);
`POST /artifacts/{id}/check` (владелец; цепочка гейтов → check_status+tier, инциденты из FAIL);
`/share` (после passed; по клиренсу или ролям); `/unshare`.

Страница артефакта + жизненный цикл ✅/🟡 —
`GET /artifacts/{id}` (карточка: `check_detail.gates`, `incidents`, `is_owner`, `can_act`, `zone`, `stage`, `tier`);
`POST /artifacts/{id}/gates/{gate}/rerun` (владелец/MLSecOps; перезапуск одного гейта, мёрж в цепочку);
`POST /artifacts/{id}/deploy` (MLSecOps; passed→ HIGH:`pending_approve` / иначе `approved`);
`/approve` (MLSecOps, **не владелец**; pending_approve→approved); `/promote` (approved→prod, прежний прод→previous);
`/rollback` (prod→previous); `/retire` (→retired). **Реальный CI — плейсхолдер; стадии персистятся.**

Реестр/очередь ✅ — `GET /registry` (`{artifacts[], zones{}, my_clearance, storage_note}`, видимость
по `_registry_visible`); `GET /approvals/pending` (MLSecOps; stage=pending_approve).

Инциденты ✅ — `GET /findings` (MLSecOps — все; иначе по своим артефактам); `POST /findings/{id}/false_positive` (MLSecOps).

Реестр моделей в БД ✅ — `POST /deploy/{model}/{version}`, `/approve`, `/prod/{model}/rollback`,
`/prod/{model}/{version}/retire` (над таблицей `models`; параллельный артефакто-центричному потоку).

MLflow/CI/файлы ✅ — `GET /models`, `/mlflow/runs`, `/runs?model=`; `POST /ci/trigger` (G1/G2/G3
локально или GitHub Actions), `/upload`, `GET /files`.

Audit ✅ — `GET /events`, `/events/verify_chain`.

Админка ✅ — `POST /admin/users|roles|access`, `GET /admin/users`.

Заглушки 🚧 (`not_implemented`): `POST /verify` (deep audit внешних весов), `/train` (CI), `/scan`
(матрица — заменена цепочкой гейтов), `/datasets/ingest`.

Самопроверка: `python -X utf8 -m src.api.main` (TestClient: регистрация→роль→токен→аудит).

## 10. Запуск и порты
`infra\start.cmd` → MLflow :5000, backend **:8200**, UI :8501 (env прокидывается дочерним окнам).
**8200, не 8000:** на Windows winnat резервирует 7904–8003 → uvicorn падает `WinError 10013`; в
Docker 8000 ок (контейнер). Сид админа: `python -m infra.seed_admin` (msecops/admin-pass).

## 11. Решения по безопасности
Локальный JWT-issuer; неподделываемая личность (серверный штамп); роли для RBAC из БД (мгновенный
отзыв); 403+`access_denied` в аудит; append-only hash-chain; MLflow только через прокси с пер-юзер
фильтрацией; приватность артефактов по умолчанию; **разделение полномочий** (нельзя одобрить свой
артефакт); Tier fail-safe; bcrypt напрямую.

## 12. TODO (следующий эшелон)
Реальная логика гейтов (вместо PASS); реальный CI-деплой (cosign/WORM/`docker run`) + копирование
в прод-бакет S3; `core/storage.py` (MinIO+WORM); `/verify` (внешние веса), `/train`, `/datasets/ingest`;
рантайм G6/G7 + метрики на дашборд; прогон на Postgres+полный compose; валидация username.
