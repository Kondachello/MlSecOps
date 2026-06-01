# Безопасная MLOps-платформа (MLSecOps)

MVP-каркас: реестр моделей + единая история событий + Security Gates (G0–G7).
Документы: [`docs/threat_model_plan.md`](docs/threat_model_plan.md), [`docs/gates_checklist.md`](docs/gates_checklist.md).

## Что уже есть (Шаги 1–3)

- **Инфраструктура** — Postgres, MinIO, Redis поднимаются одной командой.
- **Схема БД** — таблицы `events`, `datasets`, `models`, `findings` (`infra/init.sql`).
- **Audit Trail** — `platform/db.py::log_event()` с hash-chain (защита от подделки лога, #24).
- **UI** — Streamlit показывает историю событий и проверяет целостность цепочки.

## Запуск

```bash
cp .env.example .env
docker compose -f infra/docker-compose.yml up --build
```

- UI (история событий): http://localhost:8501
- MinIO-консоль: http://localhost:9001 (creds из `.env`)
- Postgres: `localhost:5432`, Redis: `localhost:6379`

Нажми в UI «Сгенерировать тестовое событие» — оно сразу появится в таблице.
Это проверяет весь контур: UI → `log_event` → Postgres → UI.

## Структура

```
platform/   общий код: доступ к БД, log_event, проверка hash-chain
gates/      G1..G7 — скрипты гейтов (добавляются дальше)
models/     ML-решения: train.py / app.py / requirements.txt / model_card.yaml
ui/         Streamlit
infra/      docker-compose, init.sql, Dockerfile.*
docs/       модель угроз, чеклист гейтов
```

## Дальше (Шаги 4–6)

1. **Шаг 4** — `gates/data_gate.py` (G1) + `ingest_dataset.py`: первый сквозной срез на датасете.
2. **Шаг 5** — обучить и зарегистрировать первую модель (lineage + SHA-256).
3. **Шаг 6** — гейты по одному: G2 (gitleaks/pip-audit) → G4 (SHA + блок pickle) → HITL/Tier → G7 (rate-limit).
