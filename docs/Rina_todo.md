# Rina_todo — пошаговый чеклист CI/CD

> Рабочий документ «по косточкам». Опирается на [`Rina_WOrk.md`](Rina_WOrk.md).  
> Ветка для работы: **`Rina`**. Отмечай `[x]` по мере выполнения.

---

## Перед стартом (один раз)

### Что установить на своём ПК

| Инструмент | Зачем |
|------------|--------|
| **Git** | ветка `Rina`, push |
| **Python 3.11** | локальный прогон гейтов |
| **Docker Desktop** | compose, образы гейтов, runner |
| **GitHub аккаунт** + доступ к репо команды | Actions, secrets |

Опционально позже: **cosign**, **trivy**, **gitleaks** (можно ставить только в CI/runner).

### Клон и ветка

```bash
cd alfa_case_2
git checkout Rina
cp .env.example .env   # заполнить позже с командой
```

### Кого предупредить в начале (сообщение в чат)

> **Всем:** я веду CI/CD на ветке `Rina`.  
> **Бэкенд:** мне нужен контракт JSON гейта (ниже §Контракт) и позже `POST repository_dispatch` + polling run.  
> **Фронт:** кнопки Verify/RUN/DEPLOY должны бить в бэк, не напрямую в GitHub.  
> **ML/DS:** для `train.py` нужен минимальный выход — файл `.safetensors` в `artifacts/`.  
> **Инфра:** PAT для self-hosted runner и список secrets в GitHub — согласуем на этапе 0.

---

## Контракт для коллег (не менять без согласования)

**JSON отчёта гейта** (stdout, `--json`):

```json
{
  "gate": "G1",
  "asset": "path/to/file",
  "passed": true,
  "checks": [{"check": "pii", "status": "PASS", "detail": "...", "evidence": {}}],
  "failed_checks": []
}
```

**Dispatch от бэка в GitHub:**

| Кнопка UI | `event_type` | Workflow |
|-----------|--------------|----------|
| Просканировать / Verify | `verify` или `scan` | `ci.yml` |
| RUN | `train` | `train.yml` |
| DEPLOY | `deploy` | `deploy.yml` |

**Payload `train`:** `model_name`, `dataset_name`, `dataset_version`, `git_commit`.  
**Payload `deploy`:** `model_name`, `version`.

**Бэкенд должен:** парсить JSON → `findings` + `events` + `set_status`. Гейт **не пишет в БД**.

---

# ЭТАП 0 — Подготовка среды (1–2 дня)

**Цель:** локально гонять гейты и понимать, куда встанет runner.  
**Проверки пока:** только вручную на ноуте, CI ещё не обязателен.

---

## 0.1 — Локальные демо-данные

- [ ] **Ты:** выполнить:
  ```bash
  pip install pandas pyarrow
  python data/make_datasets.py
  ```
- [ ] Убедиться, что есть файлы:
  - `data/train_m1_clean.csv`
  - `data/train_m1_poisoned.csv`

**Проверка G1 вручную:**

```bash
python src/gates/data_gate/data_gate.py --path data/train_m1_clean.csv --json
# ожидание: exit 0

python src/gates/data_gate/data_gate.py --path data/train_m1_poisoned.csv --json
# ожидание: exit 1
```

**Коллегам:** «Демо-датасеты генерятся через `make_datasets.py`, CI будет использовать те же пути».

---

## 0.2 — Прогон остальных гейтов вручную (базовая линия)

- [ ] G3 clean:
  ```bash
  python src/gates/dependency_gate/dependency_gate.py --path demo/requirements_clean.txt --json
  ```
- [ ] G3 bad:
  ```bash
  python src/gates/dependency_gate/dependency_gate.py --path demo/insecure/requirements_vuln.txt --json
  # exit 1
  ```
- [ ] G2 (пока может быть SKIP без gitleaks):
  ```bash
  pip install bandit pip-audit
  python src/gates/code_gate/code_gate.py --path src --stage ci --json
  python src/gates/code_gate/code_gate.py --path demo/insecure --stage ci --json
  ```

Записать в блокнот: что уже PASS/FAIL/SKIP — это baseline перед правками.

---

## 0.3 — Папка `scripts/ci/` (в репо уже есть)

| Файл | Назначение |
|------|------------|
| `scripts/ci/run_gate.sh` | `bash scripts/ci/run_gate.sh data data/train_m1_clean.csv` |
| `scripts/ci/build_all_gates.sh` | сборка образов `mlsec-gate-*` |
| `scripts/ci/parse_report.py` | краткий вывод JSON-отчёта |
| `scripts/ci/check_local.sh` | всё из 0.1–0.3 одной командой |
| `scripts/ci/README.md` | шпаргалка |

- [x] Файлы в репозитории
- [ ] **Ты:** прогнать `bash scripts/ci/check_local.sh` (Git Bash / WSL)

---

## 0.4 — `infra/docker-compose.gates.yml`

- [x] Файл-напоминание + сборка через `build_all_gates.sh`

- [ ] **Ты (если есть Docker):**

```bash
bash scripts/ci/build_all_gates.sh
docker images
```

---

## 0.5 — Runner (два режима)

### A) GitHub-hosted runner (ваш режим) — без своего Docker ci-runner

- [x] `.env`: `GITHUB_REPO`, `GITHUB_TOKEN`, `GITHUB_REF=Rina`
- [x] В workflow: `runs-on: ubuntu-latest` (облачный runner GitHub, не `self-hosted`)
- [x] **Не нужен** `docker compose … ci-runner` и Admin на Settings → Runners
- [ ] Запуск: **Actions → ci → Run workflow** → ветка **Rina**
- [ ] Локально гейты: `bash scripts/ci/check_local.sh`

**Коллегам:** «CI на GitHub-hosted; ветка `Rina`. Self-hosted в compose — позже, если инфра попросит».

### B) Свой runner в Docker (нужен Admin на репо)

- `REPO_URL`, `ACCESS_TOKEN`, `RUNNER_NAME` в `.env` → `docker compose -f infra/docker-compose.yml up -d ci-runner`
- Classic PAT `repo`+`workflow` или `RUNNER_TOKEN` от владельца.

---

## 0.6 — `.env.example`

- [x] Добавлены `RUNNER_NAME`, `GATEKEEPER_URL`, `USE_GATEKEEPER`, `CI_SKIP_PREFLIGHT`, комментарии cosign
- [x] **Ты:** `.env` создан (`REPO_URL`, `ACCESS_TOKEN`, `RUNNER_NAME` — см. 0.5)

**Коллегам (бэк):** «Какие URL внутри docker-сети для postgres/mlflow с runner?»

---

### ✅ Критерий готовности этапа 0

- [ ] **Ты:** G1 clean/bad локально (`check_local.sh` или вручную)
- [x] `scripts/ci/` в репозитории
- [ ] **Ты:** runner **Idle** в репо (инфра) **или** локально `check_local.sh` OK; свой `ci-runner` — опционально

---

# ЭТАП 1 — Довести `ci.yml` (2–3 дня)

**Цель:** на каждый push/PR — параллельные проверки данных, кода, зависимостей.  
**Когда запускать:** каждый коммит в `Rina`; вручную Actions → **ci** → Run workflow.

---

## 1.1 — Job `syntax` (уже есть)

- [ ] После добавления новых `.py` — дописать пути в список `py_compile` в `ci.yml`.
- [ ] Локально перед push:
  ```bash
  python -m py_compile src/gates/*/*.py
  ```

**Коллегам:** «Не ломайте синтаксис — job `syntax` первый».

---

## 1.2 — Job `data-gate` (G1) — ужесточить при необходимости

- [ ] Убедиться, что шаги **clean passes** и **poisoned is blocked** без `|| true`.
- [ ] Push → проверить в GitHub Actions оба шага зелёные/красные как задумано.

**Ничего не говорить коллегам по данным** — ingest на бэке; ты только фикстуры в CI.

---

## 1.3 — Job `dependency-gate` (G3)

- [ ] Уже должно работать; перепроверить после push.

---

## 1.4 — Job `code-gate` (G2) — твоя главная доработка

**Файлы:**

- [ ] `src/gates/code_gate/code_gate.py` — парсинг bandit/pip-audit JSON, FAIL только HIGH/CRITICAL.
- [ ] `src/gates/code_gate/requirements.txt` — bandit, pip-audit (если вынесено).
- [ ] `.github/workflows/ci.yml`:
  - [ ] Установить **gitleaks** (action `gitleaks/gitleaks-action` или curl binary).
  - [ ] **Убрать `|| true`** на clean и bad шагах.
  - [ ] clean: `--path src` → **exit 0 обязателен**.
  - [ ] bad: `--path demo/insecure` → **exit 1 обязателен** (обёртка `if ... exit 1` как у data-gate).

**Проверка локально** — повторить 0.2 после правок.

**Коллегам:**  
«Секреты и демо-код только в `demo/insecure/` — CI специально ломает PR, если туда что-то попадёт в скан `src/`».

---

## 1.5 — Job `registry-gate` (G5) — **создать**

**Создать фикстуры:**

| Файл | Назначение |
|------|------------|
| `demo/model_cards/valid_card.json` | PASS |
| `demo/model_cards/invalid_card.json` | FAIL (нет owner/tier) |

**Файлы:**

- [ ] Доработать `src/gates/registry_gate/registry_gate.py` под эти JSON.
- [ ] В `ci.yml` добавить job `registry-gate` по образцу `dependency-gate`.

**Коллегам (бэк + фронт):**  
«Формат model card для G5 — согласуем поля с `core/model_card.py`. Вот пример valid: `demo/model_cards/valid_card.json`».

---

## 1.6 — Job `build-gates` — **создать**

- [ ] В `ci.yml`:
  ```yaml
  build-gates:
    runs-on: [self-hosted]
    steps:
      - uses: actions/checkout@v4
      - run: bash scripts/ci/build_all_gates.sh
  ```
- [ ] При желании: шаг «smoke docker» — `docker run mlsec-gate-data --path ...`.

**Коллегам:** не обязательно.

---

## 1.7 — Job `db-smoke`

- [ ] Пока оставить как есть (скелет).
- [ ] **Разблокировать**, когда бэк сделает `core/db.log_event` + `verify_chain`:
  - добавить service postgres в job или `needs` от compose.
  - убрать заглушку в `tests/smoke_db.py`.

**Коллегам (бэк):** «Напишите, когда `log_event` готов — подключу db-smoke в CI».

---

## 1.8 — Сохранение отчёта для бэка (подготовка)

- [ ] В каждый gate-job добавить шаг:
  ```yaml
  - run: python scripts/ci/parse_report.py > gate-report-${{ gate }}.json
  - uses: actions/upload-artifact@v4
    with:
      name: gate-reports
      path: "*.json"
  ```

**Коллегам (бэк):** «Артефакты workflow `gate-reports` — формат до интеграции API».

---

### ✅ Критерий готовности этапа 1

- [ ] `workflow_dispatch` → workflow **ci** → все jobs green на чистой ветке
- [ ] Сломать нарочно `demo/insecure` в тестовой ветке → `code-gate` / `data-gate` red
- [ ] PR в `Rina` показывает checks в GitHub

**Когда гонять полный CI:** после каждого merge-готового коммита в `Rina`.

---

# ЭТАП 2 — Довести скрипты гейтов G2/G4/G5 (3–5 дней)

**Цель:** стабильные PASS/FAIL, готовность к `train.yml`.  
**Проверки:** локально + отдельный workflow или job в `ci.yml`.

---

## 2.1 — G4 `model_gate`

**Файлы:**

- [ ] `src/gates/model_gate/model_gate.py`:
  - [ ] subprocess **modelscan** (нет → SKIP)
  - [ ] `--expected-sha <hash>` для deploy
  - [ ] `.pkl` → FAIL
- [ ] `src/gates/model_gate/Dockerfile` — установка modelscan при необходимости.

**Создать фикстуру:**

- [ ] `demo/models/bad.pkl` (пустой/фейк) — только для CI bad-test
- [ ] `artifacts/.gitkeep` — папка под выход train

**Проверка:**

```bash
python src/gates/model_gate/model_gate.py --path demo/models/bad.pkl --json
# exit 1
```

**Коллегам (ML):** «Прод-формат весов: safetensors/onnx, не pickle».

---

## 2.2 — G5 `registry_gate` (логика lineage)

- [ ] Проверки: `dataset_name`, `dataset_version`, `git_sha`, `run_id` не пустые для register.
- [ ] Job в CI или тест-скрипт `scripts/ci/test_registry_gate.sh`.

**Коллегам (бэк):** «При register в API передавайте те же поля lineage, что ждёт G5».

---

## 2.3 — `parse_report.py` финальная версия

- [ ] Exit 1, если `passed: false` (для использования в shell).

---

### ✅ Критерий этапа 2

- [ ] Все 5 гейтов (G1–G5) локально: clean PASS, demo bad FAIL
- [ ] Образы `mlsec-gate-*` собираются

---

# ЭТАП 3 — `train.yml` (3–5 дней)

**Цель:** канонический артефакт из CI.  
**Когда запускать:** только после этапа 1–2; вручную Actions → **train** → Run workflow.

**Зависимость от бэка:** preflight датасета (можно mock).

---

## 3.1 — Создать `scripts/ci/preflight_train.sh`

**Логика:**

1. Читает `DATASET_NAME`, `DATASET_VERSION` из env.
2. **Пока бэк не готов:** если `CI_SKIP_PREFLIGHT=true` — пропуск (только dev).
3. **Когда бэк готов:** `curl "$GATEKEEPER_URL/api/v1/registry"` → статус датасета must be `available`.

- [ ] Файл создан.
- [ ] В `train.yml` первый step после checkout: `bash scripts/ci/preflight_train.sh`.

**Коллегам (бэк):**  
«Перед train CI вызовет GET registry: датасет `{name}@{version}` должен быть `available`. Иначе train не стартует (канон §5.8)».

---

## 3.2 — Доработать `src/train/train.py`

**Минимум для CI (если ML-команда не успела):**

- [ ] Обучение-заглушка: сохранить пустой/маленький `.safetensors` в `artifacts/model.safetensors`.
- [ ] Печать `SHA256` в stdout.
- [ ] Аргументы CLI уже есть — использовать из workflow inputs.

**Коллегам (ML/DS):**  
«Замените заглушку в `train.py` на реальное обучение; путь артефакта оставьте `artifacts/model.safetensors`».

---

## 3.3 — Обновить `.github/workflows/train.yml`

Порядок шагов **строго:**

| Шаг | Команда |
|-----|---------|
| 1 | `preflight_train.sh` |
| 2 | `actions/checkout` на input `git_commit` |
| 3 | G2 `code_gate --stage ci --path .` |
| 4 | G3 `dependency_gate --path requirements.txt` |
| 5 | `python src/train/train.py ...` |
| 6 | G4 `model_gate --path artifacts/model.safetensors` |
| 7 | G5 + `post_register.sh` (заглушка) |
| 8 | upload-artifact: `artifacts/`, `ci-train-report.json` |

- [ ] Убрать все `echo TODO` по мере реализации.
- [ ] `runs-on: [self-hosted]`
- [ ] Env: `MLFLOW_TRACKING_URI`, MinIO — когда compose доступен runner’у.

---

## 3.4 — Создать `scripts/ci/post_register.sh`

**Пока:**

```bash
# curl -X POST "$GATEKEEPER_URL/api/v1/..." с телом lineage
echo '{"status":"registered_stub"}' > ci-register.json
```

**Коллегам (бэк):** «Нужен endpoint register после train: model_name, version, sha256, dataset_*, git_sha, run_id, trained_in_ci=true».

---

### ✅ Критерий этапа 3

- [ ] `workflow_dispatch` train с тестовыми inputs → зелёный до G4
- [ ] Артефакт `model.safetensors` в Actions artifacts
- [ ] G2 fail → train не доходит до train.py

**Когда гонять train:** после зелёного `ci.yml`; не на каждый commit — только по кнопке / dispatch.

---

# ЭТАП 4 — `deploy.yml` (3–5 дней)

**Цель:** прод только с approved + SHA + cosign.  
**Когда запускать:** после train + HITL (mock или реальный Approve).

---

## 4.1 — `scripts/ci/preflight_deploy.sh`

- [ ] Проверка: модель `approved` (curl API или mock `CI_SKIP_PREFLIGHT`).
- [ ] Tier HIGH без `approved_by` → exit 1.

**Коллегам (бэк + фронт):**  
«DEPLOY workflow стоит, пока статус не `approved`. DS не может Approve — только MLSecOps».

---

## 4.2 — G2 deploy + trivy (единственный раз)

**Файлы:**

- [ ] `deploy.yml`: шаг `code_gate --stage deploy`
- [ ] Шаг: `docker build` inference image → `trivy image --severity HIGH,CRITICAL --exit-code 1`

**Установить на runner:** trivy (apt или action).

**Коллегам (инфра):** «Нужен docker.sock на runner для build + trivy».

---

## 4.3 — cosign

- [ ] Secrets в GitHub: `COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD`
- [ ] Шаги sign + verify перед `docker run`

**Коллегам (лид):** «Добавьте cosign secrets в repo Settings → Secrets».

---

## 4.4 — G4 SHA + MinIO prod

- [ ] `EXPECTED_SHA` из API реестра
- [ ] Скрипт upload в `models/prod/*` (вызов `core/storage` или aws cli к MinIO)

**Коллегам (бэк):** «Отдайте SHA модели по API для deploy; upload prod — через CI, не руками».

---

## 4.5 — Health + alias production

- [ ] `curl` health inference `:8080`
- [ ] Заглушка callback бэку / MLflow alias

---

### ✅ Критерий этапа 4

- [ ] deploy без approve → fail
- [ ] deploy с approve + совпадающий SHA → pass
- [ ] Подмена SHA в тесте → G4 fail

---

# ЭТАП 5 — Интеграция с бэкендом и UI (параллельно с 3–4)

**Твои задачи:**

- [ ] Документ `docs/ci-contract.md` (опционально) — dispatch + JSON + poll run id
- [ ] Согласовать polling: бэк читает `GET /repos/.../actions/runs/{id}`
- [ ] Заменить `CI_SKIP_PREFLIGHT` на реальные API
- [ ] Убрать upload-artifact stub, когда бэк пишет в PG

**Сообщение бэкенду (когда ci.yml зелёный):**

> Готовы event types: `verify`, `scan`, `train`, `deploy`.  
> PAT нужен scope: `repo`, `workflow`.  
> Пример dispatch:
> ```json
> POST /repos/{owner}/{repo}/dispatches
> {"event_type":"train","client_payload":{"model_name":"m1","dataset_name":"ds","dataset_version":"v1","git_commit":"abc123"}}
> ```

**Сообщение фронту:**

> Показывайте статус job из API бэка. URL Actions: `https://github.com/{org}/{repo}/actions`.  
> Не вызывайте GitHub напрямую из Streamlit без бэка.

---

# ЭТАП 6 — Финальное демо (1–2 дня)

По [`16_DEMO_SCENARIOS.md`](16_DEMO_SCENARIOS.md):

| # | Сценарий | Что гонишь ты |
|---|----------|----------------|
| 1 | Poisoned CSV | `ci.yml` data-gate или ручной G1 |
| 2 | Секрет / pytirch | `ci.yml` code + dependency |
| 3 | HITL + deploy | `deploy.yml` + preflight |
| 4 | 429 attack | не CI — `attack_sim.py` (команда serve); ты только поднимаешь deploy |

- [ ] Чеклист демо пройден на ветке `Rina`
- [ ] Merge request в main с описанием workflows

**Коллегам на демо:** «Показываем GitHub Actions: зелёный clean, красный poisoned, train → artifact → deploy с SHA».

---

# Сводка: что создать (файлы)

| # | Путь | Этап |
|---|------|------|
| 1 | `scripts/ci/run_gate.sh` | 0 |
| 2 | `scripts/ci/build_all_gates.sh` | 0 |
| 3 | `scripts/ci/parse_report.py` | 0 → 2 |
| 4 | `infra/docker-compose.gates.yml` | 0 |
| 5 | `demo/model_cards/valid_card.json` | 1 |
| 6 | `demo/model_cards/invalid_card.json` | 1 |
| 7 | `.github/workflows/ci.yml` (правки) | 1 |
| 8 | `src/gates/code_gate/code_gate.py` (правки) | 1 |
| 9 | `src/gates/model_gate/model_gate.py` (правки) | 2 |
| 10 | `demo/models/bad.pkl` | 2 |
| 11 | `artifacts/.gitkeep` | 2 |
| 12 | `scripts/ci/preflight_train.sh` | 3 |
| 13 | `scripts/ci/post_register.sh` | 3 |
| 14 | `src/train/train.py` (минимум) | 3 |
| 15 | `.github/workflows/train.yml` (правки) | 3 |
| 16 | `scripts/ci/preflight_deploy.sh` | 4 |
| 17 | `.github/workflows/deploy.yml` (правки) | 4 |
| 18 | `.env.example` (дополнение) | 0 |
| 19 | `docs/ci-contract.md` (опц.) | 5 |

---

# Когда что запускать (шпаргалка)

| Действие | Команда / где | Как часто |
|----------|---------------|-----------|
| Быстрая проверка гейта | `python src/gates/.../..._gate.py --path ... --json` | перед каждым коммитом |
| Все демо-данные | `python data/make_datasets.py` | после pull |
| Сборка образов | `bash scripts/ci/build_all_gates.sh` | перед deploy docker-gates |
| CI полный | Push / PR → GitHub **ci** | каждый push в `Rina` |
| Train | Actions → **train** → Run workflow | по готовности этапа 3 |
| Deploy | Actions → **deploy** | только с approved моделью |
| Compose стенд | `docker compose -f infra/docker-compose.yml up` | интеграция с бэком |

---

# Порядок этапов (не перепрыгивать)

```
0 подготовка → 1 ci.yml → 2 гейты G2/G4/G5 → 3 train.yml → 4 deploy.yml → 5 интеграция бэк → 6 демо
```

**Не начинать train**, пока `ci.yml` не зелёный на clean.  
**Не начинать deploy**, пока train не выдаёт артефакт + SHA.

---

# Блокеры — к кому идти

| Блокер | Кому |
|--------|------|
| Runner queued forever | Инфра / PAT / `ci-runner` compose |
| `log_event` / db-smoke | Бэкенд `core/db.py` |
| Кнопка RUN не запускает workflow | Бэкенд dispatch |
| Нет реального обучения | ML / `train.py` |
| Approve / Tier в UI | Фронт + бэкенд HITL |
| MinIO WORM prod | Бэкенд `core/storage.py` + инфра MinIO |

---

*Обновляй чекбоксы в этом файле по ходу работы. Полная теория — в [`Rina_WOrk.md`](Rina_WOrk.md).*
