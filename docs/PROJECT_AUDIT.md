# Аудит проекта `main/` — production-oriented

## Стенд (одна команда)

```bash
docker compose -f infra/docker-compose.yml up --build
```

Всегда поднимаются: **Postgres, Redis, MinIO, MLflow, Gatekeeper, UI, Inference**.

## Связи компонентов

| От | К | Как |
|----|---|-----|
| UI | Backend | `GATEKEEPER_URL=http://backend:8000` |
| Backend | Postgres | реестр, events, findings, RBAC |
| Backend | MLflow | `MLFLOW_UPSTREAM_URL=http://mlflow:5000` |
| Backend | MLflow (клиенты) | прокси `GET/POST /mlflow/*` + JWT |
| MLflow | MinIO | артефакты `s3://mlflow/` |
| MLflow | Postgres | backend-store experiments |
| GitHub Actions | Backend | `GATEKEEPER_URL` + `POST /api/v1/ci/ingest-reports` |
| CI scripts | Backend | preflight `GET /api/v1/registry`, register, ingest |
| Inference | Redis | G7 rate-limit |

UI **не** ходит в MLflow напрямую. DS/ноутбук: `MLFLOW_TRACKING_URI=http://<host>:8000/mlflow` + токен с `/api/v1/auth/token`.

## Моки

По умолчанию **выключены**: `APP_DEBUG=false`, `UI_USE_MOCKS=false`. Данные только из API/БД/MLflow.

## GitHub Actions

В `.env` / secrets репозитория:

- `GITHUB_TOKEN`, `GITHUB_REPO`, `GITHUB_REF`
- `GATEKEEPER_URL` (доступен с runner’а)
- `CI_INGEST_TOKEN` (тот же на бэке)

Workflows: `verify.yml`, `train.yml`, `deploy.yml`, `ci.yml` — ingest в конце summary job.

## Оставшиеся TODO (не блокируют compose)

- `rollback` / `retire` API
- SSO authproxy в compose (сейчас JWT + `/mlflow` прокси на бэке)
- Poll GitHub run → автоматический ingest без ручного curl

*Обновлено: 2026-06-04.*
