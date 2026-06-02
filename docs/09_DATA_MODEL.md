# 09 — Модель данных (PostgreSQL)

Реестр + аудит + RBAC живут в Postgres. Источник правды по **артефактам** — MLflow+MinIO;
по **статусам безопасности / Tier / HITL / lineage** — наш Postgres. Синхронизация по `(name, version)`.

> Правило: **не менять схему результата гейта и таблицы БД без обновления всех потребителей**
> (UI, ingest, API).

## 9.1 Таблицы

### `events` — Audit Trail (hash-chain)
```sql
CREATE TABLE events (
  id          BIGSERIAL PRIMARY KEY,
  ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor       TEXT NOT NULL,          -- серверная identity (из auth-прокси), НЕ клиентское поле
  role        TEXT NOT NULL,          -- DS/DE/MLSecOps/Product/CEO
  action      TEXT NOT NULL,          -- dataset_uploaded, gate_passed, gate_blocked, verify_started,
                                       -- train_started, model_registered, approve, deploy,
                                       -- prod_promote, prod_rollback, retire, tier_changed, fp_marked, access_denied ...
  asset       TEXT,                   -- name@version или id актива
  result      TEXT NOT NULL,          -- ok | blocked | pending | error
  reason      TEXT,                   -- обязателен для изменяющих действий (justification)
  details     JSONB,                  -- произвольные детали
  prev_hash   TEXT NOT NULL,          -- хэш предыдущей записи (genesis = '0'*64)
  row_hash    TEXT NOT NULL           -- sha256(prev_hash || canonical_payload)
);
-- Целостность: row_hash считается в log_event(); UPDATE/DELETE отозваны на роли приложения.
```

### `datasets` — реестр датасетов
```sql
CREATE TABLE datasets (
  id            BIGSERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  version       TEXT NOT NULL,
  sha256        TEXT NOT NULL,         -- digest содержимого
  source_type   TEXT NOT NULL,        -- local | internet | corp_storage | verified_id
  status        TEXT NOT NULL,        -- registered | available | quarantine | prod_locked
  bucket        TEXT NOT NULL,        -- datasets | quarantine
  owner         TEXT NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT now(),
  UNIQUE (name, version)
);
```

### `verified_datasets` — fast-path по хэшу
```sql
CREATE TABLE verified_datasets (
  sha256       TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  version      TEXT NOT NULL,
  verified_at  TIMESTAMPTZ DEFAULT now(),
  signed       BOOLEAN DEFAULT false  -- крипто-подпись ИБ активна
);
-- Fast-path засчитывает G1 ТОЛЬКО при бит-в-бит совпадении хэша. Любое изменение → новый хэш → полная проверка.
```

### `models` — реестр моделей (+ паспорт)
```sql
CREATE TABLE models (
  id            BIGSERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  version       TEXT NOT NULL,
  tier          TEXT NOT NULL,        -- LOW | MED | HIGH (дефолт HIGH)
  status        TEXT NOT NULL,        -- registered | quarantine | pending_hitl | approved | prod | previous | retired
  source        TEXT NOT NULL,        -- ci_trained | external
  sha256        TEXT,                 -- хэш артефакта (CI-выход или замороженные внешние веса)
  signed        BOOLEAN DEFAULT false,
  owner         TEXT NOT NULL,
  approved_by   TEXT,                 -- кто сделал HITL Approve (MLSecOps)
  card          JSONB NOT NULL,       -- паспорт модели (G0)
  created_at    TIMESTAMPTZ DEFAULT now(),
  UNIQUE (name, version)
);
```

### `model_versions` — lineage (связка данные↔код↔модель)
```sql
CREATE TABLE model_versions (
  id              BIGSERIAL PRIMARY KEY,
  model_name      TEXT NOT NULL,
  version         TEXT NOT NULL,
  dataset_name    TEXT,
  dataset_version TEXT,
  dataset_sha256  TEXT,
  git_sha         TEXT,
  run_id          TEXT,               -- MLflow run
  mlflow_version  TEXT,               -- версия в MLflow Registry
  trained_in_ci   BOOLEAN NOT NULL,   -- проставляется CI, не клиентом
  sha256          TEXT,               -- хэш итогового артефакта
  status          TEXT NOT NULL,
  created_at      TIMESTAMPTZ DEFAULT now(),
  UNIQUE (model_name, version)
);
```

### `findings` — сработки гейтов (общая сущность)
```sql
CREATE TABLE findings (
  id          BIGSERIAL PRIMARY KEY,
  ts          TIMESTAMPTZ DEFAULT now(),
  gate        TEXT NOT NULL,          -- G0..G7
  asset_type  TEXT NOT NULL,          -- dataset | code | model | dependency | runtime
  asset       TEXT NOT NULL,          -- name@version
  rule        TEXT NOT NULL,          -- какая проверка
  severity    TEXT NOT NULL,          -- critical | high | medium | low
  evidence    JSONB,                  -- причина блока (рендерится в UI «Показать причину»)
  status      TEXT NOT NULL,          -- open | false_positive | fixed
  marked_by   TEXT,                   -- кто отметил FP (MLSecOps)
  run_no      INTEGER                 -- номер прогона скана (для «300 запусков, 5 находок»)
);
```

### RBAC: `users`, `roles`, `dataset_access`
```sql
CREATE TABLE users (
  id          BIGSERIAL PRIMARY KEY,
  username    TEXT UNIQUE NOT NULL,   -- согласован с SSO/MLflow
  email       TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE roles (
  user_id     BIGINT REFERENCES users(id),
  role        TEXT NOT NULL,          -- DS | DE | MLSecOps | Product | CEO
  PRIMARY KEY (user_id, role)
);
CREATE TABLE dataset_access (
  user_id         BIGINT REFERENCES users(id),
  dataset_name    TEXT NOT NULL,
  dataset_version TEXT NOT NULL,
  can_export      BOOLEAN DEFAULT false,  -- право data_export
  granted_by      TEXT NOT NULL,          -- MLSecOps
  ts              TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (user_id, dataset_name, dataset_version)
);
```

## 9.2 Статусы (единый словарь)

| Сущность | Допустимые статусы |
|---|---|
| dataset | `registered` → `available` / `quarantine`; `prod_locked` (под прод-моделью) |
| model | `registered` → `quarantine` / `pending_hitl` → `approved` → `prod` → `previous` / `retired` |
| finding | `open` → `false_positive` / `fixed` |
| event.result | `ok` / `blocked` / `pending` / `error` |

Правила переходов:
- `prod` достижим только из `approved` (а `approved` для HIGH — только после HITL).
- Перевод в `prod` лочит датасет (`prod_locked`) и включает WORM на артефакте.
- Заблокированное (`quarantine`) не удаляется (улика).

## 9.3 Целостность лога (hash-chain)

- `log_event(actor, role, action, asset=, result=, reason=, details=)` — единственная точка
  записи в `events`; считает `row_hash` от `prev_hash` + канонизированного payload.
- Genesis: `prev_hash = '0'*64`.
- `verify_chain()` — проходит таблицу, пересчитывает хэши, находит разрыв (демо #24).
- На БД-роли приложения **отозваны UPDATE/DELETE** на `events` (append-only).
