-- init_mlflow_db.sql — создаёт ОТДЕЛЬНУЮ базу `mlflow` на НАШЕМ управляемом Postgres.
--
-- Зачем отдельная БД (а не таблицы в mlsec): схема MLflow содержит таблицы `datasets` и
-- `model_versions` — те же имена, что и в НАШЕМ реестре (infra/init.sql). В одной БД они бы
-- конфликтовали и ломали MLflow-реестр/трекинг. Поэтому MLflow живёт в своей БД `mlflow`, но
-- на ТОМ ЖЕ Postgres-сервере под НАШИМ контролем (единые креды/сеть/доступ; наружу — только
-- через auth-прокси). Так «переносим дефолтный стор MLflow на нашу базу» безопасно и без коллизий.
--
-- Выполняется docker-entrypoint'ом Postgres ДО init.sql (префикс 00_). Идемпотентность —
-- через guard, т.к. у Postgres нет `CREATE DATABASE IF NOT EXISTS`.
SELECT 'CREATE DATABASE mlflow OWNER mlsec_app'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'mlflow')\gexec

GRANT ALL PRIVILEGES ON DATABASE mlflow TO mlsec_app;
