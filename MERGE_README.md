# Merge `main` — сборка из трёх веток

Собрано: **2026-06-04**

## Источники

| Компонент | Ветка / папка |
|-----------|----------------|
| Скелет, CI/CD, `scripts/ci`, `core/db` (дополнено), demo-данные | **Rina** (`рина/`) |
| Бэкенд `src/api/`, `mlflow_proxy`, `core/identity`, `core/mlflow_utils`, база `core/db` (auth) | **kolya_gh_api_test** (`коля/`) |
| UI, гейты, docs 00–20, train/serve/monitor/ingest | **sasha1** (`саша/`) |

## Что вручную дополнено при merge

- `core/db.py`: из Коли + **`ingest_gate_report`**, рабочие **`add_finding`** / **`mark_false_positive`**, **`ping`** (из логики Рины)
- `src/api/main.py`: `GITHUB_REF` по умолчанию **`main`**
- `.github/workflows/ci.yml`: push на ветки **`main`** и **`Rina`**

## Структура (кратко)

```
main/
  .github/workflows/   ← Rina (ci, train, deploy)
  scripts/ci/          ← Rina
  src/api/             ← Kolya
  src/gates/           ← sasha1
  ui/                  ← sasha1
  docs/                ← sasha1 + Rina_*.md, IMPLEMENTATION_PLAN
  core/                ← db/mlflow/identity Kolya + патч findings
```

## CI (обновлено)

- **ci.yml** — на `push` в `main`: G1–G5 + Docker gates + ingest (если `vars.GATEKEEPER_URL`).
- **verify.yml** / **train.yml** / **deploy.yml** — `workflow_dispatch` + `repository_dispatch`.
- **Gatekeeper** — dispatch + `POST /api/v1/ci/ingest-reports` + register-model.

Настройка GitHub: **[.github/GITHUB_ACTIONS_SETUP.md](.github/GITHUB_ACTIONS_SETUP.md)**

## Следующие шаги

1. Push `main` → проверить workflow **ci** в Actions.
2. Variables: `GATEKEEPER_URL` (опц.), `REQUIRE_COSIGN=false`; Secret: `CI_INGEST_TOKEN`.
3. На бэке в Docker: `GITHUB_REPO`, `GITHUB_TOKEN`, `CI_INGEST_TOKEN`.
4. `docker compose -f infra/docker-compose.yml up --build` — полный стенд с MLflow.

## Локальный запуск (черновик)

```powershell
cd c:\Users\1\Desktop\neurohelp\alfa-bank\main
copy .env.example .env
# DB_BACKEND=sqlite по умолчанию для dev без Docker
pip install -r requirements.txt
python tests/smoke_db.py
```

Полный план команды: `..\TEAM_TASKS.md`
