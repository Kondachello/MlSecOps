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
    id         BIGSERIAL PRIMARY KEY,
    username   TEXT UNIQUE NOT NULL,
    email      TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
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

-- ───────── Append-only: отозвать UPDATE/DELETE на events у роли приложения ─────────
-- Выполнить ПОСЛЕ создания роли mlsec_app (см. .env / docker-compose):
-- REVOKE UPDATE, DELETE ON events FROM mlsec_app;
