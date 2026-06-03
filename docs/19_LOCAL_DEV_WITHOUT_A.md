# 19 — Локальный прогон B+C без бэкенда A

Пока роль A (core/db, storage, identity, Gatekeeper API) не готова, слои **B (гейты + CI)** и
**C (модели + рантайм + мониторинг + UI)** работают и демонстрируются **автономно**, с
graceful-деградацией там, где нужен A.

## Что работает без A

| Возможность | Как | Замена A |
|---|---|---|
| Гейты G1/G3/G4/G5 | `python src/gates/<g>/<g>.py … --json` | — (standalone по контракту) |
| Обучение 3 моделей → ONNX | `make train-all` | — |
| Consistency train↔serve (#19) | `make consistency` | — |
| G7 инференс + rate-limit | `make serve-credit` + `make attack` | Redis опц. (in-memory fallback) |
| G6 мониторинг (дрейф/подмена) | `make monitor` | — |
| **Audit Trail** | `src/common/audit.log_event` | пишет в `logs/events.jsonl`, пока нет `core.db.log_event` |
| Фичи для PSI на живом трафике | serve → `logs/inference_<model>.jsonl` | локальный том вместо БД A |
| UI | `streamlit run ui/app.py` | моки при недоступном Gatekeeper |

## Один прогон сквозь
```bash
make setup            # pip install -r requirements.txt
make demo             # scripts/demo_local.sh: данные → гейты → 3 модели → G4 → атака → мониторинг
```

`scripts/demo_local.sh` проверяет каждую пару «clean PASS / bad BLOCK» и поднимает инференс с
атакой — всё без A/MLflow/GitHub.

## Graceful-деградация (ключевой приём)
- `src/common/audit.py`: `log_event()` сначала пробует `core.db.log_event` (когда A готов) →
  иначе пишет в `logs/events.jsonl`. Когда A реализует БД — переключение автоматическое, код не меняется.
- `serve`: Redis недоступен → in-memory rate-limit; ONNX-артефакт отсутствует → `proba=0.0` (health покажет `model_loaded=false`).
- `monitor`: evidently не установлен → собственный PSI по корзинам.

## Инференс-сервисы (3 модели)
| Модель | Сервис | Порт | Эндпоинт |
|---|---|---|---|
| credit_scoring | `inference-credit` (`src.serve.app`) | 8080 | `POST /predict` |
| text_classifier | `inference-text` (`src.serve.app_text`) | 8081 | `POST /classify` |
| transaction_risk | `inference-risk` (`src.serve.app_risk`) | 8082 | `POST /predict` |

`monitor` (compose) читает `logs/inference_credit_scoring.jsonl` в watch-режиме (`--watch 30`)
и считает live-PSI против `data/train_m1_clean.csv`.

## Что переключится на A автоматически (точки интеграции)
- `audit.log_event` → `core.db.log_event` (Postgres + hash-chain).
- serve грузит модель из MinIO/реестра вместо локального `artifacts/`.
- UI: моки → реальные `GET /api/v1/{events,registry,findings}` и `POST /verify`.
- `train.yml`/`deploy.yml`: `curl` к `/api/v1/register` и `/models/{}/versions/{}` (сейчас graceful-`|| echo WARNING`).
