# Secure MLOps Platform (MLSecOps)

Платформа управления безопасностью ML поверх MLOps: реестр моделей и датасетов,
единая неподделываемая история событий, Security Gates в CI/CD,
ручной контроль (HITL) для критичных моделей и runtime-защита прод-инференса.

> **Девиз:** там, где MLOps делает систему надёжной, MLSecOps делает её неуязвимой.
> Безопасность — встроенная фича системы, а не патчи поверх инцидентов.

---

## 🚀 Быстрый старт

Подними весь стенд одной командой (Docker Desktop должен быть запущен):

```powershell
docker compose -f infra/docker-compose.yml up -d
```

Поднимутся:
- `postgres` (5432), `minio` (9000/9001), `redis` (6379) — инфра
- `mlflow` (внутри сети, наружу через authproxy на 4180) — tracking + registry
- `backend` (**8200**) — FastAPI / Gatekeeper, JWT-issuer, ручки `/api/v1/...`
- `ui` (**8501**) — Streamlit фронт
- `gates-runner` — долгоживущий контейнер с gitleaks/onnxruntime, исполняет цепочку гейтов
- `inference` (8280) — пример сервиса инференса

Первый раз нужно засеять админа и MinIO-бакет:

```powershell
docker exec -e BOOTSTRAP_ADMIN_PASSWORD=admin-pass infra-backend-1 python -m infra.seed_admin
docker exec infra-minio-1 sh -c 'mc alias set local http://localhost:9000 change_me change_me && mc mb -p local/mlflow'
```

> На Windows используем порт **8200** для backend и **8280** для inference — порты 8000/8080
> попадают в зарезервированный winnat-диапазон (Hyper-V/WSL2). Подробности в HANDOFF §5.

### Куда смотреть, что работает

| Сервис | URL | Креды |
|---|---|---|
| 🌐 **UI (главное окно)** | http://localhost:8501 | `msecops` / `admin-pass` |
| 📜 **Backend Swagger** | http://localhost:8200/docs | Bearer-токен из логина |
| 📦 **MinIO console** | http://localhost:9001 | `change_me` / `change_me` |
| 🧪 **MLflow** | http://localhost:4180 | через JWT (auth-прокси) |

### Проверка end-to-end (демо-сценарии)

Три скрипта в `examples/` показывают как разные модели проходят/валят гейты:

```powershell
# Должен пройти все 5 гейтов
python examples\demo_train_clean.py

# DATA gate FAIL — в CSV номера банковских карт (PII)
python examples\demo_train_poison_data.py

# G5 FAIL — вредоносный pickle с os.system через __reduce__
python examples\demo_train_evil_pickle.py
```

Для каждого скрипта DEV_USER должен существовать в БД и иметь роль DS/DE/MLSecOps:
```powershell
# Создать юзера через UI «Регистрация» → войти админом → выдать роль DS
# или через API:
$T=(Invoke-RestMethod http://localhost:8200/api/v1/auth/login -Method POST -Body '{"username":"msecops","password":"admin-pass"}' -ContentType 'application/json').access_token
Invoke-RestMethod http://localhost:8200/api/v1/admin/users -Method POST -Headers @{Authorization="Bearer $T"} -Body '{"username":"kolya1","password":"123","roles":["DS"]}' -ContentType 'application/json'
```

После запуска `demo_train_clean.py` в UI:
1. Войти как `kolya1` → вкладка **«Мои артефакты»** → раскрыть эксперимент
2. На карточке сессии нажать **«Security check»** → 5 гейтов запустятся в gates-runner
3. Открыть **«История CI»** в сайдбаре → увидеть прогон с разбивкой по гейтам и логам
4. Открыть **«Реестр»** → артефакт переедет в зону «Прошли проверку»
5. Нажать «📄 Открыть в реестре» → детальная страница с кнопками рестарта гейтов и (для MLSecOps) выкатки в прод

### Остановить всё

```powershell
docker compose -f infra/docker-compose.yml down
# или с удалением данных:
docker compose -f infra/docker-compose.yml down -v
```

---

## ⚙️ CI/CD — как устроено и как пользоваться

В платформе **два уровня CI**:

### Уровень 1 — Гейты «на артефакт» (по умолчанию работает)

Когда DS логирует модель в MLflow и нажимает **«Security check»** на ране:
1. Backend вызывает `core.gates_pipeline.run_pipeline(run_id)`
2. Та в свою очередь делает `docker compose exec gates-runner python -m gates.runner --run-id X`
3. gates-runner качает артефакты рана из MLflow → прогоняет цепочку: **DATA → G0 → G5 → G7 → G8**
4. Результат пишется в `artifact_acl.check_detail` рана **И** в журнал `pipeline_runs` (trigger=`artifact`)
5. UI показывает результат на странице артефакта + в **«История CI»**

Контракт:
- `python -m gates.runner --run-id X` — вся цепочка
- `python -m gates.runner --run-id X --only G5` — один гейт (для перезапуска)
- `python -m gates.runner --run-id X --from G5` — рестарт цепочки с точки

Каждый из этих режимов доступен в UI: кнопки «🔁 Перезапустить {ID}» / «⏭ Перезапустить с {ID} до конца» в разворота гейта на странице артефакта.

### Уровень 2 — GitHub Actions на git-push (опционально)

При `git push` в репо запускается workflow [`.github/workflows/gates.yml`](.github/workflows/gates.yml):
1. Self-hosted runner (контейнер `mlsec-ci-runner` в нашем compose) принимает job
2. Делает `docker exec mlsec-gates-runner python -m gates.runner --source-dir /workspace --only DATA,G0`
3. POST-ит результат в `http://backend:8200/api/v1/pipeline_runs` от имени сервисного юзера `ci`
4. Запись появляется в **«История CI»** с `trigger=git_push`, `source=<git_sha>`, `ref=<branch/PR>`

**Запуск раннера** (требует GitHub PAT с правом `repo`):

```powershell
# В .env должны быть:
#   GITHUB_TOKEN=ghp_...               # classic PAT с скоупом repo
#   GITHUB_REPO=Kondachello/MlSecOps
#   CI_USER_PASSWORD=ci-pass
docker exec -e CI_USER_PASSWORD=ci-pass infra-backend-1 python -m infra.seed_ci_user
docker compose --profile ci -f infra/docker-compose.yml --env-file .env up -d ci-runner
```

После регистрации runner появится в **GitHub → Repo Settings → Actions → Runners** со статусом 🟢 Idle и лейблом `mlsecops`.

**На стороне GitHub** добавить Repository Secret:
- **Repo Settings → Secrets and variables → Actions → New repository secret**
- Name: `MLSEC_CI_PASS`, Value: `ci-pass`

Опционально: `MLSEC_BACKEND_URL` (по умолчанию `http://backend:8200`).

**Тест end-to-end:**
```powershell
git commit --allow-empty -m "trigger MLSecOps gates"
git push
```
→ **GitHub → Actions** — увидишь зелёный/красный чек
→ **UI → «История CI»** — появится запись с `trigger=git_push`

### Журнал CI (`pipeline_runs`)

Источник истины для страницы **«История CI»**. Один прогон цепочки = одна запись:

| Поле | Что |
|---|---|
| `trigger` | `artifact` / `git_push` / `manual_ui` / `ci_scheduled` |
| `source` | run_id MLflow (для artifact) или git_sha (для git_push) |
| `ref` | git ref (только для git_push) |
| `actor` | username (или `ci`) |
| `gate_ids` | какие гейты были выбраны (`--only`/`--from`) |
| `status` | `running` → `passed`/`failed`/`error` |
| `passed/failed/skipped_count` | счётчики по гейтам |
| `duration_ms` | сколько шёл прогон |
| `detail` | полный JSON с логами каждого гейта (для drilldown) |

API:
- `GET /api/v1/pipeline_runs?limit=100&trigger=artifact&status=failed` — список
- `GET /api/v1/pipeline_runs/{id}` — детали с логами
- `POST /api/v1/pipeline_runs` — приём результата от внешнего CI (нужна роль MLSecOps или юзер `ci`)

### Все доступные гейты

| ID | Что проверяет | Severity | Триггеры |
|---|---|---|---|
| **DATA** | PII (карты/email/СНИЛС), poison-колонки, null-ratio в CSV | high | artifact + git_push |
| **G0** | Секреты (gitleaks → regex fallback) | critical | artifact + git_push |
| **G5** | Pickle opcode scan (REDUCE/GLOBAL/...) + whitelist форматов | critical | только artifact |
| **G7** | SHA256 manifest + .sig артефакта | medium | только artifact |
| **G8** | ONNX holdout accuracy + degenerate-predictor check | high | только artifact |

Метаданные — `config/gates.yml`. Реализации — `gates/*.py`. Регистрация декоратором `@register_gate`.

---

## 🧪 Канон проекта (одной страницей)

Эти решения зафиксированы и не обсуждаются заново при реализации. Полностью — в
[docs/05_CANONICAL_FLOW.md](docs/05_CANONICAL_FLOW.md).

1. **Прод-артефакт всегда обучается в CI из кода.** Локальное обучение — только
   эксперимент. Если CI-обучение невозможно (внешние веса HF/Kaggle) — артефакт
   замораживается как есть, прогоняется через все применимые гейты и **обязательно**
   требует ручной проверки MLSecOps (HITL).
2. **Идентичность неподделываема.** Единый аккаунт для UI/бэкенда и MLflow.
   MLflow стоит за auth-прокси и наружу не торчит; личность пользователя проставляется
   **серверно**, клиент её задать не может. У каждого свой аккаунт, своя роль.
3. **CI = GitHub Actions через self-hosted runner**, поднятый в `docker compose`
   (профиль `ci`, см. секцию CI/CD выше).
4. **Прод неизменяем.** Прод-модель и её датасет заморожены (WORM). Доработка — только
   на копии, с полным прохождением проверок и контролируемой blue-green заменой.
5. **Каждый гейт работает в изолированном `gates-runner` контейнере** (least privilege,
   свои CLI: gitleaks/onnxruntime/...).
6. **Любое действие пишется в неподделываемый Audit Trail** (`events`, hash-chain) +
   все CI-прогоны — в `pipeline_runs`.

---

## 📚 Документация

Полный набор — в [`docs/`](docs/). Точка входа: **[docs/00_INDEX.md](docs/00_INDEX.md)**.

Самое важное:
- [docs/04_ARCHITECTURE.md](docs/04_ARCHITECTURE.md) — компоненты и потоки данных
- [docs/05_CANONICAL_FLOW.md](docs/05_CANONICAL_FLOW.md) — канон жизненного цикла модели
- [docs/06_IDENTITY_AND_AUTH.md](docs/06_IDENTITY_AND_AUTH.md) — JWT + RBAC + MLflow за auth-прокси
- [docs/09_DATA_MODEL.md](docs/09_DATA_MODEL.md) — схема БД (включая `pipeline_runs`)
- [docs/11_BACKEND_API.md](docs/11_BACKEND_API.md) — список ручек
- [docs/18_MLFLOW.md](docs/18_MLFLOW.md) — приватность и шаринг артефактов
- [HANDOFF.md](HANDOFF.md) — текущее состояние реализации и решённые грабли

## 🛠 Стек

Python 3.11 · FastAPI (бэкенд) · Streamlit (UI) · PostgreSQL / SQLite (дев) ·
MinIO (S3) · Redis · MLflow (tracking + registry) · GitHub Actions + self-hosted runner ·
Docker compose · gitleaks · onnxruntime · pandas · sklearn.

Подробно — [docs/15_TECH_STACK.md](docs/15_TECH_STACK.md).
