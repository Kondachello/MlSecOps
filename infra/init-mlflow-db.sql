-- Отдельная БД для MLflow (не смешивать с реестром mlsec — там тоже есть model_versions).
CREATE DATABASE mlflow;
GRANT ALL PRIVILEGES ON DATABASE mlflow TO mlsec_app;
