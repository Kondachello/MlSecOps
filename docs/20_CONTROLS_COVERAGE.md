# 20 — Карта покрытия: контроли, тесты, fail-closed, RiskAcceptance (GRC)

GRC-обвязка поверх модели угроз: замкнутый контур **угроза → контроль → тест → покрытие**.
Это «паспорт защищённости в цифрах» (как «32/32 контроля» у зрелых платформ).

## 20.1 Каталог контролей — `src/common/controls.py`

Единый источник правды (pure-data модуль, без зависимостей). Каждый контроль:

```python
{"id": "SUP-01", "title": "Вредоносный артефакт модели", "threats": ["#3"],
 "gate": "G4", "layer": "build", "status": "live",
 "tests": ["model_gate.weights_scan", "ci:model-gate bad-fixture"],
 "std": {"ATLAS": "AML.T0010.003", "OWASP": "ML06", "NIST": "MANAGE-2.2", "FSTEC": "СП.1"}}
```

- **layer**: `build | data | code | runtime | identity | infra | grc`.
- **status**: `live` (реализовано + покрыто тестом), `planned` (инфра/зона A), `accepted`
  (остаточный риск принят через RiskAcceptance).
- **std**: маппинг на MITRE ATLAS · OWASP ML Top 10 · NIST AI RMF · ФСТЭК БДУ.

ID-схемы: `SUP-/DATA-/CODE-/RT-/DOS-/DOW-/ACC-/CRED-/EXF-/MON-/VIS-/GOV-/CI-/SIG-/NET-/AUD-/SKEW-/GATE-/DLP-`.

`coverage()` возвращает `{total, live, accepted, planned, closed, pct}` (accepted считается
закрытым — риск осознанно принят). Текущее: **30 контролей, 25 live, 5 planned (инфра/A) = 83%**.

## 20.2 fail-closed (строгий режим)

Каждый гейт принимает флаг **`--fail-closed`**: проверка со статусом `SKIP` (нет инструмента/
данных) трактуется как **`FAIL`**. Для критичных активов «нет сканера → блок», а не «пропустить».

- Включён в `deploy.yml` (G2 deploy + G4 подпись) — прод-путь fail-closed.
- В раннере гейтов UI — галочка «fail-closed».
- В CI clean-pass шагах НЕ включён (чтобы зелёная сборка не падала от отсутствующих бинарников).

## 20.3 RiskAcceptance (GRC exception)

Если контроль `planned` (зона A/инфра) или временно недоступен — MLSecOps может **принять
остаточный риск** с обоснованием. Контроль → `accepted`, покрытие растёт.

- UI: раздел «Карта покрытия» → выбор контроля → «Принять остаточный риск» (только MLSecOps).
- API: `POST /api/v1/controls/{id}/accept {reason, by}` (персистит в БД + событие — зона A).
  До готовности A — локальный fallback `controls.set_accepted()` + immediate UI.

## 20.4 Как это работает с бэкендом A (не хардкод)

| Что | Сейчас (без A) | Когда A готов |
|---|---|---|
| Каталог контролей | `controls.CONTROLS` (локально) | `GET /api/v1/controls` (A отдаёт + статусы из БД) |
| Принятие риска | `set_accepted()` in-memory + UI | `POST /controls/{id}/accept` персистит в БД |
| Покрытие | `coverage()` локально | считается из ответа `/controls` |

UI читает контроли через `get_controls()` = **API-first, fallback на локальный каталог** — при
подключении A переключение автоматическое, без правок UI.

## 20.5 Связь с моделью угроз

Каждый `threats: ["#N"]` ссылается на угрозу из [`08_THREAT_MODEL.md`](08_THREAT_MODEL.md) (#1..#26).
Каждый `tests: [...]` ссылается на реальную проверку гейта / CI-джобу / pytest. Тест
`tests/test_controls.py` проверяет консистентность (у каждого контроля есть угроза, тесты,
уникальный ID, корректная математика покрытия).

## 20.6 Рантайм-контроли периметра (G7, добавлены)

| ID | Контроль | Поведение | Файл |
|---|---|---|---|
| RT-01 | Extraction-детект | rate-limit → 429 | `serve` `_limiter` |
| DOS-01 | Load-shedding | глоб. семафор `MAX_INFLIGHT` → 503 (ядро живо) | `serve` `_inflight` |
| DOW-01 | Cost/token-quota | бюджет на ключ/мин → 429 | `serve` `cost_exceeded` |
| RT-05 | Валидация входа | Pydantic → 422, payload-лимит → 413 | `serve` |
| RT-02 | OOD/adversarial | вход-выброс → `suspect` + Finding | `serve` `ood_check` |
| RT-03 | Output-reduction | класс вместо вероятностей | `serve` `reduce_output` |
| DLP-01 | DLP логов | маскирование ПДн | `serve`/`audit` `dlp_mask` |
| MON-01 | Дрейф данных | PSI > 0.25 → Finding | `monitor` |

См. также [`13_RUNTIME_AND_MONITORING.md`](13_RUNTIME_AND_MONITORING.md).
