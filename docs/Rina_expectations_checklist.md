# Чеклист ожиданий — Рина (CI/CD)

> Кратко: **что жду от коллег** и **что делаю сама**.  
> Детальный план: [`Rina_todo.md`](Rina_todo.md). Интеграция: [`Rina_do_befor_work.md`](Rina_do_befor_work.md).  
> Ветка: **`Rina`**. Репо: `Kondachello/MlSecOps`.

Отмечай `[x]` по мере закрытия. Не менять **контракт JSON гейта** и **`event_type` dispatch** без сообщения в чат.

---

## Что я жду от других

### Бэкенд (Gatekeeper + `core/`)

| # | Ожидание | Зачем мне | Когда нужно | Статус |
|---|----------|-----------|-------------|--------|
| B1 | **Не менять** формат JSON гейта (`gate`, `passed`, `checks`, `failed_checks`) | CI и артефакты уже на этом контракте | сейчас | — |
| B2 | **`POST repository_dispatch`** с payload как в таблице ниже + polling run → парсинг JSON | Кнопки UI → workflows без PAT из фронта | этап 5 | [ ] |
| B3 | Парсинг JSON → **`findings` + `events` + `set_status`** (`core.db.ingest_gate_report`, `log_event`) | Логи для UI, не из CI job | этап 5 | [ ] частично: `core/db.py` есть, API — нет |
| B4 | **`GET /api/v1/registry`** — датасет `{name}@{version}` со статусом `available` | `preflight_train.sh` без mock | этап 3 | [ ] |
| B5 | **`POST` register после train** (model_name, version, sha256, dataset_*, git_sha, run_id, `trained_in_ci=true`) | `post_register.sh` вместо заглушки | этап 3 | [ ] |
| B6 | **Deploy preflight:** модель `approved`; Tier HIGH без `approved_by` → блок | `preflight_deploy.sh` | этап 4 | [ ] |
| B7 | **SHA модели по API** для deploy (`EXPECTED_SHA`) | G4 в `deploy.yml` | этап 4 | [ ] |
| B8 | Реализовать **`src/api/main.py`** (эндпоинты из `11_BACKEND_API.md`) | Вся цепочка ingest → UI | этап 5 | [ ] |
| B9 | **`core/storage.py`** — upload prod в MinIO | deploy шаг 4.4 | этап 4 | [ ] |
| B10 | **`core/mlflow_utils.py`** — runs, register | verify / train связка | этап 3–5 | [ ] |
| B11 | Сообщить, когда API стабилен → я уберу **`CI_SKIP_PREFLIGHT`** / подключу **`GATEKEEPER_URL`** | Переключение адаптеров в `scripts/ci/` | после B4–B7 | [ ] |
| B12 | (Опц.) Webhook или сигнал «run finished» | Меньше polling | позже | [ ] |

**Dispatch (не менять без согласования):**

| Кнопка UI | `event_type` | Workflow |
|-----------|--------------|----------|
| Verify / Просканировать | `verify` или `scan` | `ci.yml` |
| RUN | `train` | `train.yml` |
| DEPLOY | `deploy` | `deploy.yml` |

**Payload train:** `model_name`, `dataset_name`, `dataset_version`, `git_commit`.  
**Payload deploy:** `model_name`, `version`.

**Model card / G5:** поля согласованы с `core/model_card.py`; пример PASS — `demo/model_card_complete.json`.

**Правило канона:** данные FAIL → train не стартует (preflight); модель FAIL → статус датасета в реестре не ломаем.

---

### Фронт (Streamlit / UI)

| # | Ожидание | Зачем | Статус |
|---|----------|-------|--------|
| F1 | Кнопки **Verify / RUN / DEPLOY** → **только бэкенд**, не GitHub API из UI | Единая точка RBAC + dispatch | [ ] |
| F2 | Прогресс и статус job — **из API бэка** (poll run), не напрямую из Streamlit к GitHub | Без PAT в браузере | [ ] |
| F3 | **HITL Approve** для deploy (Tier HIGH): DS не может approve — только MLSecOps | `preflight_deploy` + демо сценарий 3 | [ ] |
| F4 | Показ **findings** и **events** по активу (когда бэк отдаёт `/findings`, `/events`) | Связка с JSON гейтов | [ ] |

**Пока бэк не готов:** RUN/Verify можно вручную в GitHub Actions → ветка `Rina`.

---

### ML / Data Science

| # | Ожидание | Зачем | Статус |
|---|----------|-------|--------|
| M1 | **`src/train/train.py`**: стабильный выход **`artifacts/model.safetensors`** (не pickle) | G4 + upload-artifact в train | [ ] |
| M2 | **SHA256** артефакта в stdout после train | deploy + реестр | [ ] |
| M3 | CLI-аргументы train совместимы с inputs в `train.yml` | workflow без переделки | [ ] |
| M4 | Прод-формат весов: **safetensors / onnx**, не `.pkl` | model_gate | [ ] |

**Если не успеваете:** я могу временно заглушку в `train.py` — вы потом замените обучение, путь артефакта тот же.

---

### Инфра / владелец репо

| # | Ожидание | Зачем | Статус |
|---|----------|-------|--------|
| I1 | **GitHub-hosted** `ubuntu-22.04` — основной режим (этап 0–1) | Без Admin на self-hosted | [x] |
| I2 | Secrets в репо (когда дойдём до deploy): **`COSIGN_PRIVATE_KEY`**, **`COSIGN_PASSWORD`** | cosign в `deploy.yml` | [ ] |
| I3 | (Если вернём self-hosted) Admin + runner + `docker.sock` для **trivy** + build inference | этап 4 | [ ] |
| I4 | MinIO prod bucket / WORM — по канону | `core/storage` + deploy | [ ] |
| I5 | Compose-стенд для интеграции: Postgres, MinIO, MLflow, authproxy | локально бэк+UI; опционально service в GHA | [ ] |

**Не жду от инфры сейчас:** self-hosted runner, PAT для регистрации runner (перешли на GitHub-hosted).

---

### Все (общие правила)

| # | Ожидание |
|---|----------|
| T1 | Не ломать синтаксис гейтов — job **`syntax`** в CI первый |
| T2 | Секреты и «плохой» код только в **`demo/insecure/`**, не в `src/` под скан G2 |
| T3 | Демо-данные: `python data/make_datasets.py` — те же пути, что в CI |
| T4 | Согласовывать изменения контракта JSON / `event_type` / полей model card **в чате** |

---

## Что жду от себя (Рина)

### Уже сделано (не трогать без причины)

- [x] Этап 0: GitHub-hosted, push → `ci.yml` на ветке `Rina`
- [x] Этап 1 (основное): G1–G5 в `ci.yml`, фикстуры, gitleaks, registry/model gates
- [x] `core/db.py` + smoke/seed (**в CI job БД не пишу**, `CI_SKIP_DB_SMOKE` на GHA)
- [x] `.env` локально: `GITHUB_*`, без runner-полей

---

### Сейчас / ближайшее (этап 1 — дожать)

| # | Задача | Статус |
|---|--------|--------|
| R1 | Перепроверить G1–G5 в Actions после каждого значимого push | [ ] |
| R2 | **`build-gates`** — убрать `continue-on-error`, зелёный job | [ ] |
| R3 | Нарочно сломать `demo/insecure` → убедиться, что **code-gate / data-gate** red | [ ] |
| R4 | PR в `Rina` → checks видны в GitHub | [ ] |
| R5 | **`upload-artifact`** с JSON отчётов в каждом gate-job (1.8) | [ ] |
| R6 | **`db-smoke` в GHA:** postgres `services:` или оставить `CI_SKIP_DB_SMOKE` до стенда | [ ] |
| R7 | Локально с Docker: `postgres up` → `python tests/smoke_db.py` → OK | [ ] |

---

### Этап 2 — гейты стабильнее

| # | Задача | Статус |
|---|--------|--------|
| R8 | G5: lineage (`dataset_name`, `dataset_version`, `git_sha`, `run_id`) + тест-скрипт | [ ] |
| R10 | `artifacts/.gitkeep`, образы `mlsec-gate-*` при необходимости | [ ] |

---

### Этап 3 — `train.yml`

| # | Задача | Статус |
|---|--------|--------|
| R11 | `scripts/ci/preflight_train.sh` (mock → API когда B4 готов) | [ ] |
| R12 | `scripts/ci/post_register.sh` (заглушка → API когда B5 готов) | [ ] |
| R13 | Порядок шагов в `train.yml` по канону (preflight → G2 → G3 → train → G4 → G5 → artifact) | [ ] |
| R14 | Заглушка в `train.py`, если ML не успел (M1) | [ ] |
| R15 | `workflow_dispatch` train → зелёный до G4 + артефакт safetensors | [ ] |

**Не начинать train**, пока `ci.yml` не стабильно зелёный на clean.

---

### Этап 4 — `deploy.yml`

| # | Задача | Статус |
|---|--------|--------|
| R16 | `preflight_deploy.sh` | [ ] |
| R17 | G2 deploy + **trivy** на inference image | [ ] |
| R18 | cosign sign/verify (когда I2) | [ ] |
| R19 | G4 `--expected-sha` + health check | [ ] |

**Не начинать deploy**, пока train не отдаёт артефакт + SHA.

---

### Этап 5 — стыковка (когда коллеги закрывают B*)

| # | Задача | Статус |
|---|--------|--------|
| R20 | Переключить `USE_GATEKEEPER=true`, убрать mock preflight | [ ] |
| R21 | Согласовать polling run id с бэком | [ ] |
| R22 | (Опц.) `docs/ci-contract.md` для команды | [ ] |
| R23 | Убрать дубли: если бэк пишет в PG — CI только артефакты, не TEMP_write в job | [ ] |

---

### Этап 6 — демо

| # | Задача | Статус |
|---|--------|--------|
| R24 | Сценарии из `16_DEMO_SCENARIOS.md` на ветке `Rina` | [ ] |
| R25 | MR в `main` с описанием workflows | [ ] |

---

### Чего я **не** делаю (осознанно)

- Полноценный Gatekeeper API и RBAC в UI  
- Прямая запись в Postgres из **каждого** CI job (только артефакты; ingest — в бэке)  
- Реализация `core/storage.py`, `core/mlflow_utils.py` (зона бэка)  
- Поднятие полного prod-стенда вместо инфры (могу помочь проверить compose локально)

---

## Блокеры → к кому иду

| Симптом | Кому |
|---------|------|
| Кнопка RUN не запускает workflow | Бэкенд (B2) |
| Preflight train всегда mock | Бэкенд (B4) |
| Нет findings в UI | Бэкенд (B3, B8) + фронт (F4) |
| Нет реального обучения | ML (M1–M3) |
| Approve / Tier в UI | Фронт (F3) + бэк (B6) |
| cosign / trivy secrets | Инфра / лид (I2, I3) |
| MinIO prod upload | Бэкенд (B9) + инфра (I4) |
| Runner queued / self-hosted | Инфра (I3) — только если вернём режим B |

---

## Одно сообщение в чат (копипаст)

> **Рина / CI:** гейты и `ci.yml` на ветке `Rina`, отчёты JSON + скоро артефакты в Actions. Гейты **не пишут в БД**.  
> **Нужно от вас:** бэк — dispatch + poll + JSON→findings/events + API preflight/register; фронт — кнопки только в бэк; ML — `artifacts/model.safetensors` + SHA; инфра — cosign secrets позже.  
> Контракт: `docs/Rina_do_befor_work.md` §2–3. Чеклист ожиданий: этот файл.

---

*Обновлено: 2026-06-03. Синхронизировать с [`Rina_todo.md`](Rina_todo.md) при смене этапов.*
