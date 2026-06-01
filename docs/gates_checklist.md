# Security Gates — чеклист проверок и механизмов (G0–G7)

> Для каждого гейта: какие проверки, каким инструментом/механизмом, где запускается, что блокирует, какие угрозы закрывает (#N из `threat_model_plan.md`).
> Принцип: каждая проверка → пишет структурированный JSON-`finding` + событие в `events`. Блок = ненулевой exit в CI или 4xx в рантайме.

---

## G0 — Onboarding Gate (регистрация актива)
**Где:** при добавлении модели/датасета в реестр (Streamlit/CI-скрипт).
**Назначение:** ни один актив не попадает в систему без паспорта и владельца.

| Проверка | Механизм / инструмент | Блок-условие |
|---|---|---|
| Наличие `model_card.yaml` | YAML-парсер + JSON-schema валидация | нет файла или нет полей → блок регистрации |
| Обязательные поля: owner, Tier, источник данных, назначение | pydantic-модель карточки | пустые/невалидные поля |
| Присвоение `Tier ∈ {LOW, MED, HIGH}` | поле в Postgres `models` | нет Tier → дефолт HIGH (fail-safe) |
| Уникальность name+version | UNIQUE constraint в Postgres | дубль версии |

**Угрозы:** #20 Shadow AI, #25 видимость реестра.
**Стек:** Postgres, pydantic, PyYAML.

---

## G1 — Data Gate (валидация данных)
**Где:** загрузка датасета / онбординг, ДО `train.py`. Скрипт `data_gate.py`.
**Назначение:** не пустить «грязные» и небезопасные данные в обучение.

| Проверка | Механизм / инструмент | Блок-условие |
|---|---|---|
| Схема датасета (набор колонок == эталон) | pandas + эталонная схема (JSON) | лишние/недостающие колонки |
| Типы и диапазоны значений | pandas dtypes + правила | несоответствие типов |
| Баланс классов (анти-poisoning) | `df['target'].value_counts(normalize=True)` | сдвиг доли класса > порога (напр. 2%→50%) |
| Поиск ПДн / PII | Regex (email, 16-знач. карты, паспорт) + опц. **Presidio** | найден PII в колонках |
| Скан текстов на prompt-инъекции (для RAG) | Regex/классификатор паттернов `[SYSTEM INSTRUCTION]`, `ignore previous` | найден паттерн при индексации |

**Угрозы:** #1 Data Poisoning, #2 PII в данных, #15 Indirect Prompt Injection.
**Стек:** pandas, re, (опц.) Microsoft Presidio.

---

## G2 — Code Gate (скан кода в CI)
**Где:** GitHub Actions / локальный CI на каждый PR в master.
**Назначение:** не пустить секреты и уязвимые зависимости даже на ревью.

| Проверка | Механизм / инструмент | Блок-условие |
|---|---|---|
| Секреты в коде (пароли, API-ключи) | **gitleaks** (или trufflehog) | любой detect → exit 1 |
| CVE в Python-зависимостях | **pip-audit** (`-r requirements.txt -f json`) | severity CRITICAL/HIGH |
| CVE в Docker-образе (опц.) | **trivy image** | критичные CVE в слоях |
| Линт/статанализ (опц.) | ruff / bandit | bandit HIGH-issues |

**Угрозы:** #8 CVE в либах, #10 секреты в коде.
**Стек:** gitleaks, pip-audit, (опц.) trivy, bandit.

---

## G3 — Supply Gate (цепочка поставки)
**Где:** установка зависимостей в CI + закачка внешней модели с HF.
**Назначение:** доверяем только известным источникам и именам.

| Проверка | Механизм / инструмент | Блок-условие |
|---|---|---|
| Allow-list имён пакетов (анти-typosquatting) | `supply_gate.py`: сверка `requirements.txt` с белым списком вендоров | `pytirch`, `tenserflew` и пр. → блок |
| Пиннинг версий (хеши) | `pip install --require-hashes` / lock-файл | незапиненная зависимость |
| Доверенный источник модели | проверка namespace HF / allow-list репозиториев | модель из непроверенного репо |

**Угрозы:** #3 Supply Chain (источник модели), #9 Typosquatting.
**Стек:** pip (require-hashes), кастомный python-чекер, allow-list.

---

## G4 — Model Gate (валидация артефакта модели)
**Где:** сборка/регистрация модели + перед стартом прод-контейнера.
**Назначение:** только безопасный формат, целостный и тот самый файл.

| Проверка | Механизм / инструмент | Блок-условие |
|---|---|---|
| Allow-list форматов весов | проверка расширения/магии файла | `.pkl/.joblib/.bin` → блок; разрешены `.safetensors/.onnx/.cbm/.txt` |
| Скан весов на вредоносный код | **modelscan** (Protect AI) / **picklescan** | подозрительные opcode/импорты |
| Целостность артефакта | SHA-256: считаем и сверяем с Postgres-реестром | hash mismatch → деплой отменён |
| Криптоподпись / provenance | **cosign / sigstore** | нет валидной подписи MLSecOps |
| Consistency train↔serve | pytest: одинаковые фичи в `train.py` и `app.py` на 5 строках | расхождение результатов |

**Угрозы:** #3 pickle/RCE, #4 подмена артефакта, #19 training-serving skew, #26 подпись.
**Стек:** hashlib, modelscan/picklescan, cosign, pytest.

---

## G5 — Compliance Gate (паспортизация / compliance-as-code)
**Где:** перед записью версии в реестр (MLflow/Postgres).
**Назначение:** документированность и прослеживаемость для регулятора.

| Проверка | Механизм / инструмент | Блок-условие |
|---|---|---|
| Полнота model card | JSON-schema валидация | неполная документация |
| Lineage: данные → код(commit) → модель | запись `dataset_version + git_commit + sha256` | разрыв связи |
| Версионирование | таблица `model_versions`, инкремент | нет привязки к версии данных/кода |

**Угрозы:** #20 Shadow AI, #23 версионирование/lineage.
**Стек:** Postgres, JSON-schema, git.

---

## G6 — Observability (мониторинг прода)
**Где:** постоянно на прод-трафике (скрипт/дашборд).
**Назначение:** ловить деградацию ДО потери денег.

| Проверка | Механизм / инструмент | Триггер алерта |
|---|---|---|
| Data / Concept Drift | **evidently** / расчёт **PSI** | `PSI > 0.25` → DRIFT DETECTED |
| Деградация качества | мониторинг метрик на эталоне | падение метрики ниже порога |
| Дашборд | Streamlit (или Grafana) | визуализация + событие в `events` |

**Угрозы:** #14 Data/Concept Drift.
**Стек:** evidently, pandas, Streamlit/Grafana.

---

## G7 — Runtime Gate (защита прод-API)
**Где:** FastAPI-эндпоинт инференса (middleware + Pydantic).
**Назначение:** защита от кражи, DoS, утечек и атак в рантайме.

| Проверка | Механизм / инструмент | Блок-условие / ответ |
|---|---|---|
| Rate limiting (анти-extraction/DoS) | **Redis** счётчик по IP/API-key | >100 req/min → `429 Too Many Requests` |
| Валидация входа (схема, диапазоны) | **Pydantic** (`max_length`, валидаторы `amount>0`, `0≤age≤120`) | `422 Unprocessable Entity` |
| Лимит размера payload | лимит тела запроса в FastAPI | большой payload → `413/422` |
| Output reduction (анти-extraction/membership) | округление/категория вместо сырых logits | `{"decision":"approve"}` вместо `0.8123491` |
| DLP в логах | middleware Regex/Presidio перед записью | маскирование карты `****-1234`, ФИО |
| Guardrails для LLM (если Модель 4) | классификатор/Regex + нормализатор Base64/Hex | блок prompt-инъекций (#7), bypass (#16) |
| Output DLP для LLM | Regex на секрет в ответе | замена на `[Заблокировано фильтром]` (#17) |
| Квоты для LLM | `max_tokens`, таймаут 10с | обрыв запроса (#21) |
| HITL для деструктивных tools агента | флаг «требует подтверждения оператора» | `delete_*` → ждёт Approve (#18) |

**Угрозы:** #5 extraction, #6 DoS, #11 evasion, #12 DLP логов, #13 membership, #7/#16/#17/#18/#21 (GenAI).
**Стек:** FastAPI, Pydantic, Redis, re/Presidio, (опц.) LLM-Guard.

---

## Сквозные механизмы (не гейт, но обязательны)

| Механизм | Инструмент | Назначение |
|---|---|---|
| **Audit Trail** | Postgres `events` + хелпер `log_event()` | история всех действий, выводится в UI |
| **Целостность лога** | hash-chain (`prev_hash`+`row_hash`), append-only права | защита от подделки истории (#24) |
| **RBAC** | middleware `require_role()`, роли DS/DE/MLSecOps/Product/CEO | Approve/retire только MLSecOps (#22) |
| **False Positives** | статус `finding` + кнопки «причина / FP / перезапуск» в Streamlit | боль MLOps, перенастройка гейтов |
| **HITL** | статус `quarantine` + кнопка Approve Deploy | ручной контроль Tier=HIGH |

---

## Сводка «гейт → инструменты» (шпаргалка)

- **G0:** pydantic, JSON-schema, Postgres
- **G1:** pandas, regex, Presidio
- **G2:** gitleaks, pip-audit, trivy, bandit
- **G3:** allow-list чекер, pip --require-hashes
- **G4:** hashlib, modelscan/picklescan, cosign, pytest
- **G5:** Postgres, JSON-schema, git
- **G6:** evidently (PSI), Streamlit/Grafana
- **G7:** FastAPI, Pydantic, Redis, regex/Presidio, LLM-Guard
- **Сквозное:** Postgres (events+hash-chain), RBAC middleware, Streamlit UI
