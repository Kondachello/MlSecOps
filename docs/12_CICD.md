# 12 — CI/CD (GitHub Actions + self-hosted runner)

## 12.1 Решение

CI/CD = **GitHub Actions**, но раннер — **self-hosted**, поднятый в `docker compose`. Так
сохраняется семантика GHA (workflows, jobs, steps), но джобы исполняются **на машине демо**.
Это компромисс между «офлайн на ноуте» (требование куратора) и «всё в GitHub Actions»
(требование команды): сервисы платформы поднимаются compose-ом, CI-джобы — на локальном раннере.

> Зависимость: оркестрация workflow всё же идёт через GitHub (dispatch). Для полностью офлайн
> запасной вариант — `act` или Gitea Actions; основной путь — self-hosted runner.

## 12.2 Принцип пайплайна

Один логический пайплайн делится на **джобы по типу актива**, в каждой джобе **шаги = проверки**
(1 шаг ≈ 1 проверка). На каждый гейт — **свой Docker-образ** (изоляция, §7.2). Джобы по
возможности независимы; зависимость статусов (данные↔код↔модель) — см.
[`05_CANONICAL_FLOW.md`](05_CANONICAL_FLOW.md) §5.8.

Принцип каждой гейт-джобы: **«чистое проходит, плохое блокируется»** (две проверки — clean pass
и bad-fixture blocked). Не валить CI на живой базе CVE — нестабильные проверки доказывать на
фикстурах в `demo/`.

## 12.3 Workflows

### `ci.yml` — на PR/верификации (код, зависимости, данные)
Джобы:
- `syntax` — `py_compile` изменённых файлов.
- `data-gate` — G1 (clean pass / poisoned blocked).
- `code-gate` — G2 `--stage ci` (gitleaks + bandit + pip-audit).
- `dependency-gate` — G3 (allow-list/пиннинг/источник; фикстура `pytirch` → блок).
- `db-smoke` — smoke БД.
- `build-gates` — сборка образов `mlsec-gate-*`.

### `train.yml` — обучение в CI (стадия RUN)
Шаги (строгий порядок):
1. `code_gate --stage ci` (**первым**, SAST/SCA перед обучением).
2. `train.py` — обучение на **проверенных** коде и данных.
3. `model_gate` (G4) на **итоговом CI-артефакте** (формат, modelscan, SHA-расчёт).
4. `mlflow.log_model` (alias=`candidate`) + артефакт в `models/...`.
5. `register_model` (Postgres + MLflow), lineage, `trained_in_ci=true`.

### `deploy.yml` — деплой в прод
Шаги:
1. Выкачать модель из `models/...` + код инференса по git SHA.
2. `code_gate --stage deploy` (secrets + SAST + CVE).
3. собрать образ → **trivy image** (единственный запуск trivy).
4. `model_gate` (G4): SHA-сверка с реестром.
5. **cosign sign** артефакта и образа.
6. положить прод-копию в `models/prod/*` (WORM).
7. **проверка cosign-подписи + SHA ПЕРЕД `docker run`** → запуск сервиса инференса.
8. health-check → MLflow alias=`production`, статус `prod`, событие.

HITL: для `Tier=HIGH` `deploy.yml` **стоит** до `approve` от MLSecOps (см. §11.2).

**fail-closed на деплое:** в `deploy.yml` гейты вызываются с `--fail-closed` (G2 deploy + G4
подпись) — `SKIP` (нет инструмента) трактуется как `FAIL`. Прод-путь не fail-open. См.
[`20_CONTROLS_COVERAGE.md`](20_CONTROLS_COVERAGE.md) §20.2.

## 12.4 Триггеры из UI

Кнопки «Просканировать ресурс» / RUN / DEPLOY дёргают workflow через
`repository_dispatch` / `workflow_dispatch` (бэкенд → GitHub API → self-hosted runner).
Результат каждой джобы возвращается в бэкенд и согласуется с БД: `passed/blocked/error` →
обновление статуса актива + `findings` + `events`. В UI — «красивый» прогресс джоб/шагов.

## 12.5 Карта «гейт → стадия → команда»

| Стадия | Гейт | Команда |
|---|---|---|
| Загрузка датасета | G0, G1 | `ingest_dataset.py <src> --name … --version …` |
| Верификация | G5, G2(ci), G3 | `/api/v1/verify` |
| Обучение в CI | G2(ci), G4 | `train.yml` |
| Деплой | G2(deploy)+trivy, G4, cosign | `deploy.yml` |

## 12.6 Правила для агента
- Новую гейт-джобу добавлять по образцу `data-gate`/`code-gate`: clean pass + bad-fixture blocked.
- После изменений — обновить список файлов в `syntax` (py_compile), держать CI зелёным.
- Секреты (cosign-ключ, токены) — только в **GitHub Actions secrets**, никогда в коде.
