-- Схема БД платформы (Шаг 2). Выполняется автоматически при первом старте Postgres.
-- 4 таблицы: events (история), datasets, models (реестр), findings (сработки сканеров).

-- ============================================================
-- EVENTS — единая история действий ("никто не забыт").
-- Любой чих платформы пишется сюда через log_event().
-- Защита от подделки: hash-chain (#24) — каждая строка хеширует предыдущую.
-- ============================================================
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    actor       TEXT         NOT NULL,            -- кто (логин)
    role        TEXT         NOT NULL,            -- DS / DE / MLSecOps / Product / CEO
    action      TEXT         NOT NULL,            -- dataset_uploaded, gate_blocked, deploy_approved...
    asset       TEXT,                             -- над каким активом (train.csv, model:v3)
    result      TEXT         NOT NULL,            -- ok / blocked / pending / error
    details     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   TEXT         NOT NULL DEFAULT '',
    row_hash    TEXT         NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts     ON events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_action ON events (action);
CREATE INDEX IF NOT EXISTS idx_events_result ON events (result);

-- ============================================================
-- DATASETS — реестр датасетов.
-- ============================================================
CREATE TABLE IF NOT EXISTS datasets (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT        NOT NULL,
    version     TEXT        NOT NULL,
    sha256      TEXT,
    location    TEXT,                              -- путь в MinIO (s3://...)
    status      TEXT        NOT NULL DEFAULT 'registered', -- registered/available/quarantine
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name, version)
);

-- ============================================================
-- MODELS — реестр моделей (источник правды о проде).
-- Tier = критичность; HIGH требует ручного Approve (HITL).
-- ============================================================
CREATE TABLE IF NOT EXISTS models (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT        NOT NULL,
    version         TEXT        NOT NULL,
    tier            TEXT        NOT NULL DEFAULT 'HIGH',  -- fail-safe: по умолчанию HIGH
    owner           TEXT,
    sha256          TEXT,
    location        TEXT,                          -- путь в MinIO
    status          TEXT        NOT NULL DEFAULT 'registered',
                    -- registered / quarantine / approved / prod / retired
    dataset_version TEXT,                          -- lineage: на каком датасете
    git_commit      TEXT,                          -- lineage: каким кодом
    approved_by     TEXT,                          -- кто нажал Approve (только MLSecOps)
    card            JSONB       NOT NULL DEFAULT '{}'::jsonb,  -- полный model_card (G0)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name, version),
    CHECK (tier IN ('LOW', 'MED', 'HIGH'))
);

-- ============================================================
-- FINDINGS — сработки сканеров/гейтов.
-- Общая сущность "что нашли разные гейты" + отработка False Positives.
-- ============================================================
CREATE TABLE IF NOT EXISTS findings (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    gate        TEXT        NOT NULL,              -- G1..G7
    asset_type  TEXT        NOT NULL,              -- dataset / model / code
    asset_name  TEXT        NOT NULL,
    severity    TEXT        NOT NULL DEFAULT 'medium', -- low/medium/high/critical
    rule        TEXT        NOT NULL,              -- какая проверка сработала
    evidence    JSONB       NOT NULL DEFAULT '{}'::jsonb, -- JSON-отчёт (причина блока)
    status      TEXT        NOT NULL DEFAULT 'open' -- open / false_positive / fixed
);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings (asset_type, asset_name);
CREATE INDEX IF NOT EXISTS idx_findings_gate  ON findings (gate);
