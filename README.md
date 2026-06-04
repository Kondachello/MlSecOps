# Secure MLOps Platform (MLSecOps)

Платформа управления безопасностью ML поверх MLOps: реестр моделей и датасетов,
единая неподделываемая история событий, Security Gates (G0–G7) в CI/CD,
ручной контроль (HITL) для критичных моделей и runtime-защита прод-инференса.

> **Девиз:** там, где MLOps делает систему надёжной, MLSecOps делает её неуязвимой.

---

## Архитектура (Docker)

```
Streamlit UI :8501
       │
       ▼
Gatekeeper API :8000  ──► Postgres (реестр, events, RBAC)
       │                  Redis (rate-limit)
       ├── /mlflow ─────► MLflow :5000 (tracking + registry)
       │                      └── артефакты в MinIO (S3)
       ├── dispatch ────► GitHub Actions (verify / train / deploy)
       └── ingest ◄────  CI: POST /api/v1/ci/ingest-reports

Inference (G7) :8080 ──► Redis
```

**MLflow наружу не публикуется.** Доступ только через бэкенд: `http://localhost:8000/mlflow`
(JWT с `POST /api/v1/auth/token`). Внутри compose бэкенд ходит в `http://mlflow:5000`.

**GitHub Actions:** после push в `kate_merge` запускается **ci.yml**. Настройка variables/secrets:
**[.github/GITHUB_ACTIONS_SETUP.md](.github/GITHUB_ACTIONS_SETUP.md)**.

---

## Запуск

```bash
cp .env.example .env
# заполни GITHUB_REPO, GITHUB_TOKEN, CI_INGEST_TOKEN
docker compose -f infra/docker-compose.yml up --build
```

| Сервис | URL |
|--------|-----|
| UI | http://localhost:8501 (логин: `msecops` / пароль из `BOOTSTRAP_ADMIN_PASSWORD`) |
| Gatekeeper API | http://localhost:8000/docs |
| MLflow (через прокси) | http://localhost:8000/mlflow |
| MinIO console | http://localhost:9001 |
| Inference G7 | http://localhost:8080/health |

Порты: `UI_HOST_PORT` в `.env`, если `:8501` занят. Redis на хост не пробрасывается.

Self-hosted runner (опционально): `docker compose -f infra/docker-compose.yml --profile ci up -d`

Документация: [docs/00_INDEX.md](docs/00_INDEX.md) · аудит: [docs/PROJECT_AUDIT.md](docs/PROJECT_AUDIT.md)

---

## С чего начать (документация)

**[docs/00_INDEX.md](docs/00_INDEX.md)** · канон: **[docs/05_CANONICAL_FLOW.md](docs/05_CANONICAL_FLOW.md)** ·
CI→UI: **[docs/CI_TO_UI_PIPELINE.md](docs/CI_TO_UI_PIPELINE.md)**
