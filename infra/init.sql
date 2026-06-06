-- init.sql — схема Postgres: реестр + Audit Trail + RBAC.
-- Соответствует docs/09_DATA_MODEL.md. НЕ менять без обновления всех потребителей.

-- ───────────────────────── Audit Trail (hash-chain) ─────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id        BIGSERIAL PRIMARY KEY,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor     TEXT NOT NULL,           -- серверная identity (из auth-прокси)
    role      TEXT NOT NULL,
    action    TEXT NOT NULL,
    asset     TEXT,
    result    TEXT NOT NULL CHECK (result IN ('ok','blocked','pending','error')),
    reason    TEXT,
    details   JSONB,
    prev_hash TEXT NOT NULL,
    row_hash  TEXT NOT NULL
);

-- ───────────────────────── Датасеты ─────────────────────────
CREATE TABLE IF NOT EXISTS datasets (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('local','internet','corp_storage','verified_id')),
    status      TEXT NOT NULL CHECK (status IN ('registered','available','quarantine','prod_locked')),
    bucket      TEXT NOT NULL,
    owner       TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now(),
    UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS verified_datasets (
    sha256      TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    verified_at TIMESTAMPTZ DEFAULT now(),
    signed      BOOLEAN DEFAULT false
);

-- ───────────────────────── Модели + lineage ─────────────────────────
CREATE TABLE IF NOT EXISTS models (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    tier        TEXT NOT NULL CHECK (tier IN ('LOW','MED','HIGH')),
    status      TEXT NOT NULL CHECK (status IN
                  ('registered','quarantine','pending_hitl','approved','prod','previous','retired')),
    source      TEXT NOT NULL CHECK (source IN ('ci_trained','external')),
    sha256      TEXT,
    signed      BOOLEAN DEFAULT false,
    owner       TEXT NOT NULL,
    approved_by TEXT,
    card        JSONB NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now(),
    UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS model_versions (
    id              BIGSERIAL PRIMARY KEY,
    model_name      TEXT NOT NULL,
    version         TEXT NOT NULL,
    dataset_name    TEXT,
    dataset_version TEXT,
    dataset_sha256  TEXT,
    git_sha         TEXT,
    run_id          TEXT,
    mlflow_version  TEXT,
    trained_in_ci   BOOLEAN NOT NULL,    -- проставляет CI, не клиент
    sha256          TEXT,
    status          TEXT NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (model_name, version)
);

-- ───────────────────────── Находки ─────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ DEFAULT now(),
    gate       TEXT NOT NULL,
    asset_type TEXT NOT NULL CHECK (asset_type IN ('dataset','code','model','dependency','runtime')),
    asset      TEXT NOT NULL,
    rule       TEXT NOT NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    evidence   JSONB,
    status     TEXT NOT NULL CHECK (status IN ('open','false_positive','fixed')),
    marked_by  TEXT,
    run_no     INTEGER DEFAULT 1
);

-- ───────────────────────── RBAC ─────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,    -- согласован с SSO/MLflow (логин)
    email         TEXT,
    password_hash TEXT,                    -- bcrypt-хэш (локальный JWT-issuer); NULL для чисто-SSO юзеров
    created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS roles (
    user_id BIGINT REFERENCES users(id),
    role    TEXT NOT NULL CHECK (role IN ('DS','DE','MLSecOps','Product','CEO')),
    PRIMARY KEY (user_id, role)
);

CREATE TABLE IF NOT EXISTS dataset_access (
    user_id         BIGINT REFERENCES users(id),
    dataset_name    TEXT NOT NULL,
    dataset_version TEXT NOT NULL,
    can_export      BOOLEAN DEFAULT false,
    granted_by      TEXT NOT NULL,
    ts              TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (user_id, dataset_name, dataset_version)
);

-- ───────────────────────── Владение и ACL артефактов MLflow ─────────────────────────
-- Приватность по умолчанию + контролируемый шаринг (docs/18_MLFLOW.md).
CREATE TABLE IF NOT EXISTS experiment_owner (
    experiment_id TEXT PRIMARY KEY,        -- MLflow experiment_id
    owner         TEXT NOT NULL,           -- первый писатель = владелец (штамп прокси)
    created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS artifact_acl (
    run_id        TEXT PRIMARY KEY,        -- MLflow run = «сессия разработки»
    experiment_id TEXT NOT NULL,
    owner         TEXT NOT NULL,           -- кто залогировал ран (штамп прокси)
    session_name  TEXT,
    check_status  TEXT NOT NULL DEFAULT 'none'
                  CHECK (check_status IN ('none','pending','passed','failed')),
    check_detail  JSONB,                   -- результат security check (цепочка гейтов)
    tier          TEXT CHECK (tier IS NULL OR tier IN ('LOW','MED','HIGH')),
    stage         TEXT NOT NULL DEFAULT 'none'
                  CHECK (stage IN ('none','pending_approve','approved','prod','previous','retired')),
    approved_by   TEXT,                    -- кто подтвердил (HITL, Tier=HIGH)
    deployed_by   TEXT,                    -- кто инициировал выкатку/перевод в прод
    share_status  TEXT NOT NULL DEFAULT 'private'
                  CHECK (share_status IN ('private','shared')),
    share_level   INTEGER,                 -- клиренс-уровень видимости (NULL пока приватный)
    share_roles   JSONB,                   -- кастомные роли (переопределяют share_level)
    shared_by     TEXT,
    created_at    TIMESTAMPTZ DEFAULT now(),
    updated_at    TIMESTAMPTZ DEFAULT now()
);

-- ───────────────────── История CI / pipeline_runs ─────────────────────────
-- Источник истины для страницы «История CI». Заполняется на каждом запуске
-- цепочки гейтов (артефакт-чек / git-push / manual).
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id            BIGSERIAL PRIMARY KEY,
    ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
    trigger       TEXT NOT NULL CHECK (trigger IN ('artifact','git_push','manual_ui','ci_scheduled')),
    source        TEXT,
    ref           TEXT,
    actor         TEXT NOT NULL,
    gate_ids      TEXT,
    status        TEXT NOT NULL CHECK (status IN ('running','passed','failed','error')),
    passed_count  INTEGER DEFAULT 0,
    failed_count  INTEGER DEFAULT 0,
    skipped_count INTEGER DEFAULT 0,
    duration_ms   INTEGER DEFAULT 0,
    detail        JSONB,
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS pipeline_runs_ts_idx       ON pipeline_runs (ts DESC);
CREATE INDEX IF NOT EXISTS pipeline_runs_trigger_idx  ON pipeline_runs (trigger);
CREATE INDEX IF NOT EXISTS pipeline_runs_status_idx   ON pipeline_runs (status);

-- ───────── Append-only: отозвать UPDATE/DELETE на events у роли приложения ─────────
-- Выполнить ПОСЛЕ создания роли mlsec_app (см. .env / docker-compose):
-- REVOKE UPDATE, DELETE ON events FROM mlsec_app;
