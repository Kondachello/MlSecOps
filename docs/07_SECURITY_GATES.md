# 07 — Security Gates (G0–G7)

Гейт — автоматическая проверка на конкретной стадии. `PASS` пропускает, `FAIL` блокирует.
**Каждый гейт — отдельный Docker-образ.** Маппинг гейт → угроза — в [`08_THREAT_MODEL.md`](08_THREAT_MODEL.md).

## 7.1 Единый контракт гейта (обязателен для всех)

Каждый гейт `src/gates/<gate>/<gate>.py` предоставляет:

```python
def gate_check(target, ...) -> list[dict]:
    # элемент: {"check": str, "status": "PASS"|"FAIL"|"SKIP",
    #           "detail": str, "evidence": dict (опц.)}
    ...

def build_report(target, results) -> dict:
    # {"gate": str, "asset": str, "passed": bool,
    #  "checks": list, "failed_checks": list}
    ...

def main():
    # argparse, печать JSON-отчёта в stdout, sys.exit(0|1)
    ...
```

Строгие правила:
1. **Один гейт — одна папка** `src/gates/<gate>/`: `<gate>.py` + `__init__.py` + `Dockerfile` + `requirements.txt`.
2. **Гейт сам в БД не пишет** (чтобы работать в CI без БД). `findings`+`events` пишет
   **оркестратор** (Gatekeeper/ingest), парся stdout-JSON. Опционально — `--db` best-effort.
3. **Graceful degradation:** нет инструмента/сети/БД → `SKIP` + предупреждение, **не падать**.
4. **Severity:** `critical|high|medium|low` — маппинг проверка→severity в оркестраторе/гейте.
5. **Заблокированное не удаляем** — версионируем в `quarantine` (улика).
6. **Никаких секретов/RCE** в гейтах; демо-«плохое» — в `demo/`.

## 7.2 Изоляция: образ на каждый гейт

```
src/gates/<gate>/
  <gate>.py          логика
  __init__.py
  Dockerfile         образ ТОЛЬКО с инструментами этого гейта (база python:3.11-slim)
  requirements.txt   минимум зависимостей
```
Образы: `mlsec-gate-data`, `mlsec-gate-code`, `mlsec-gate-dependency`, `mlsec-gate-model`,
`mlsec-gate-registry`.

**Контракт запуска** (одинаково в CI и в Gatekeeper):
```bash
docker run --rm --network none \
  -v "$ARTIFACT:/in:ro" \
  mlsec-gate-<name> --path /in --json
# stdout = JSON build_report(); exit 0 = PASS, 1 = FAIL
```
- `--network none` для гейтов без сети (data/model) — sandbox для опасных артефактов.
- `code`/`dependency` (нужны advisory-БД) — сеть разрешена, артефакт всё равно `:ro`.
- Запись в БД делает вызывающий, парся stdout. Сборка — `infra/docker-compose.gates.yml`
  + build-job в CI.

## 7.3 Каталог гейтов

### G0 — Onboarding Gate (регистрация актива)
**Где:** при добавлении модели/датасета в реестр (UI/CI). **Назначение:** ни один актив без паспорта и владельца.

| Проверка | Инструмент | Блок |
|---|---|---|
| Наличие/валидность паспорта (`model_card`) | pydantic + JSON-schema | нет/невалиден |
| Обязательные поля: owner, Tier, источник данных, назначение | pydantic | пусто/невалидно |
| Присвоение `Tier` (авто-правила/MLSecOps) | поле в `models` | нет Tier → дефолт HIGH (fail-safe) |
| Уникальность name+version | UNIQUE в Postgres | дубль версии |

**Угрозы:** #20 Shadow AI, #25 видимость реестра. **Файл:** `core/model_card.py` + UI.

### G1 — Data Gate (валидация данных)
**Где:** загрузка/онбординг датасета, ДО обучения. **Назначение:** не пустить грязные/небезопасные данные.

| Проверка | Инструмент | Блок |
|---|---|---|
| Формат файла + скан на скрытые скрипты/закладки | парсер + сигнатуры | вредоносное вложение |
| Схема (колонки == эталон) | pandas + эталон JSON | лишние/недостающие |
| Типы и диапазоны | pandas dtypes + правила | несоответствие |
| Баланс классов (анти-poisoning) | `value_counts(normalize)` | сдвиг доли > порога |
| Пропуски/дубликаты/константы | pandas | аномалии качества |
| ПДн / PII | regex (email/карты/паспорт) + опц. Presidio | найден PII |
| Prompt-инъекции (для RAG-текста) | regex/паттерны | найден паттерн |

**Угрозы:** #1 Data Poisoning, #2 PII, #11, #15. **Файл:** `src/gates/data_gate/`.

### G2 — Code Gate (скан кода в CI)
**Где:** GitHub Actions на PR/верификации; стадии `--stage ci|deploy`. **Назначение:** не пустить секреты, уязвимости, опасный код.

| Проверка | Инструмент | Блок |
|---|---|---|
| Секреты в коде | **gitleaks** | любой detect → exit 1 |
| SAST (статанализ) | **bandit** | HIGH-issues |
| CVE зависимостей (SCA) | **pip-audit** `-r requirements.txt` | CRITICAL/HIGH |
| CVE Docker-образа (только `--stage deploy`) | **trivy image** | критичные CVE |

**Угрозы:** #8 CVE, #10 секреты. **Файл:** `src/gates/code_gate/`.
> Граница с G3: **CVE/SCA зависимостей — здесь (G2)**; имена/пиннинг/источник пакетов — в G3.
> `trivy` запускается **ровно один раз** — на собранном образе в `deploy` (это «перепроверка
> контейнеров перед продом»). Не дублировать на ранних стадиях.

### G3 — Supply Gate (цепочка поставки)
**Где:** установка зависимостей + закачка внешней модели. **Назначение:** доверяем только известным именам и источникам.

| Проверка | Инструмент | Блок |
|---|---|---|
| Allow-list имён пакетов (анти-typosquatting) | кастомный чекер + белый список | `pytirch`/`tenserflew` и пр. |
| Пиннинг версий (хеши/lock) | `--require-hashes` / lock-файл | незапиненная зависимость |
| Доверенный источник | namespace HF / индекс PyPI | непроверенный репозиторий |

**Угрозы:** #3 (источник), #9 typosquatting. **Файл:** `src/gates/dependency_gate/`.
> Рекомендация по размещению: **отдельная джоба** `dependency-gate` (свой образ) — чище, чем
> смешивать с G2. Запускается на стадии зависимостей перед обучением/деплоем.

### G4 — Model Gate (валидация артефакта)
**Где:** конец CI-обучения, при онбординге внешних весов, перед стартом прод-контейнера. **Назначение:** только безопасный формат, целостный и тот самый файл.

| Проверка | Инструмент | Блок |
|---|---|---|
| Allow-list форматов весов | расширение/магия файла | `.pkl/.joblib/.bin` → блок; разрешены `.safetensors/.onnx/.cbm/.txt` |
| Скан весов на вредоносный код | **modelscan / picklescan** | подозрительные opcode/импорты |
| Целостность | SHA-256 ↔ реестр | mismatch → деплой отменён |
| Подпись / provenance | **cosign / sigstore** | нет валидной подписи |
| Consistency train↔serve | pytest на N строках | расхождение фич |

**Угрозы:** #3 pickle/RCE, #4 подмена, #19 skew, #26 подпись. **Файл:** `src/gates/model_gate/`.

### G5 — Compliance / Registry Gate (паспортизация и lineage)
**Где:** перед записью версии в реестр / при `/verify`. **Назначение:** документированность и прослеживаемость.

| Проверка | Инструмент | Блок |
|---|---|---|
| Полнота model card | pydantic/JSON-schema | неполно |
| Lineage: данные(версия+хэш) → код(SHA) → модель(версия+хэш+run_id) | проверка связей | разрыв связи |
| Уникальность/инкремент версии | `model_versions` | нет привязки к версии данных/кода |

**Угрозы:** #20 Shadow AI, #23 версионирование/lineage. **Файл:** `src/gates/registry_gate/`.

### G6 — Observability (мониторинг прода)
**Где:** постоянно на прод-трафике. **Назначение:** ловить деградацию и подмену до потери денег.

| Проверка | Инструмент | Триггер |
|---|---|---|
| Data/Concept Drift | **evidently** / PSI | `PSI > 0.25` → DRIFT |
| Деградация качества | мониторинг метрик на эталоне | падение ниже порога |
| Детект подмены модели | периодический ре-хэш запущенного артефакта ↔ реестр | mismatch → алерт |

**Угрозы:** #14 drift, #4 (подмена в рантайме). **Файл:** `src/monitor/`.

### G7 — Runtime Gate (защита прод-API)
**Где:** FastAPI-инференс (middleware + Pydantic + Redis). **Назначение:** защита от кражи, DoS, утечек.

| Проверка | Инструмент | Ответ |
|---|---|---|
| Rate limiting (анти-extraction/DoS) | **Redis** счётчик по ключу/IP | >N req/min → `429` |
| Валидация входа (схема/диапазоны) | **Pydantic** | `422` |
| Лимит размера payload | FastAPI лимит тела | `413/422` |
| Output reduction | класс/округление вместо logits | `{"decision":"approve"}` |
| DLP в логах | middleware regex/Presidio | маскирование карт/ФИО |
| (GenAI, P3) guardrails/output-DLP/квоты | regex/LLM-Guard | блок инъекций |

**Угрозы:** #5 extraction, #6 DoS, #11 evasion, #12 DLP, #13 membership (+P3). **Файл:** `src/serve/`.

## 7.3bis fail-closed (строгий режим) и Semgrep

- **fail-closed:** каждый гейт принимает флаг `--fail-closed` — проверка со статусом `SKIP`
  (нет инструмента/данных) трактуется как `FAIL`. Для критичных активов «нет сканера → блок».
  Включён в `deploy.yml` (G2 deploy + G4 подпись). В CI clean-pass шагах НЕ включён.
  Подробно — [`20_CONTROLS_COVERAGE.md`](20_CONTROLS_COVERAGE.md) §20.2.
- **Semgrep (ML-aware SAST):** добавлен в G2 `code_gate` (`check_semgrep`) рядом с bandit;
  нет бинарника → `SKIP`.

## 7.4 Сквозные механизмы (не гейт, но обязательны)

| Механизм | Инструмент | Назначение |
|---|---|---|
| **Audit Trail** | Postgres `events` + `log_event()` | история всех действий |
| **Целостность лога** | hash-chain + append-only | защита от подделки истории (#24) |
| **RBAC** | `require_role()` | привилегированные действия — только по роли (#22) |
| **False Positives** | статус `finding` + кнопки в UI | разбор ложных срабатываний |
| **HITL** | статус `pending_hitl` + Approve | ручной контроль Tier=HIGH и внешних весов |
| **Identity** | SSO + auth-прокси | неподделываемая атрибуция |

## 7.5 Стадии → гейты → команда

| Стадия | Гейт | Команда |
|---|---|---|
| Загрузка датасета | G0, G1 | `ingest_dataset.py <src> --name … --version …` |
| Верификация (код/lineage/зависимости) | G5, G2(ci), G3 | `/api/v1/verify` → workflow |
| Обучение в CI | G2(ci), G4 | `train.yml` |
| Деплой | G2(deploy)+trivy, G4, cosign | `deploy.yml` |
| Рантайм | G7 | сервис `src/serve/` |
| Мониторинг | G6 | `src/monitor/` |
