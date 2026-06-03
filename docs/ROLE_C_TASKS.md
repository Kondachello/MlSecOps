# ROLE C — задачи и зафиксированные контракты (хендофф)

Зона C: **Runtime (G7) · Мониторинг (G6) · ML-модели + train.py · UI · дашборд.**
Перед стартом: [`00_INDEX.md`](00_INDEX.md), [`05_CANONICAL_FLOW.md`](05_CANONICAL_FLOW.md),
[`13_RUNTIME_AND_MONITORING.md`](13_RUNTIME_AND_MONITORING.md), [`14_FRONTEND_UI.md`](14_FRONTEND_UI.md).

## Уже готово (эталон — не переписывать, расширять по образцу)
- `src/common/features.py` — **единая** фичеинженерия (train↔serve, #19).
- `src/train/train.py` — модель №1 (sklearn→**ONNX**), пишет `artifacts/{model}.onnx`,
  `artifacts/model_path.txt`, `artifacts/run_id.txt` (контракт `train.yml` от B).
- `src/serve/app.py` — G7: Redis rate-limit→429 (graceful in-memory), Pydantic→422, payload→413,
  `reduce_output`, DLP-логи; грузит ONNX через onnxruntime.
- `src/serve/attack_sim.py` — нагрузка для демо (429).
- `tests/test_consistency.py` + `tests/conftest.py` — #19 (parity фичей; работает и без модели).

## 🔒 Контракты, которые НЕЛЬЗЯ нарушать
1. **Формат весов — только G4 allow-list:** `.onnx / .safetensors / .cbm / .txt`. НЕ `.pkl/.joblib`.
2. **Выход `train.py`:** артефакт + `artifacts/model_path.txt` + `artifacts/run_id.txt`.
3. **Фичи — только через `src/common/features`.** serve НЕ переопределяет featurize (тест это ловит).
4. **REST к A** (`/api/v1/events|registry|findings|verify|deploy/*/approve`) — UI кодит против него;
   до готовности A — на моках.

## Задачи по приоритету
- **C1 (готов эталон):** модель №1 + train.py. Запустить локально, убедиться `model_gate` PASS.
- **C2 (готов):** `features.py` + `test_consistency.py`. Закрывает долг #19 совместно с B.
- **C3:** доустановить deps и поднять `serve/app.py`; проверить `attack_sim.py` → 429.
- **C4:** `src/monitor/monitor.py` — PSI (evidently) на `data/prod_traffic_drifted.csv` → DRIFT;
  ре-хэш запущенного артефакта ↔ реестр (детект подмены).
- **C5:** модели №2 и №3 (CNN→.safetensors/.onnx; текст→.onnx) — по образцу train.py, со своими
  `featurize_*` в `common`. По микросервису на модель в `src/serve/`.
- **C6:** UI (`ui/app.py`) — наполнить вкладки (моки→API A): Верификация, Находки (evidence/FP),
  История (целостность лога), Деплой/Approve (HITL), Дашборд + CEO read-only.

## Локальный прогон (без A/B)
```bash
pip install -r requirements.txt
python data/make_datasets.py
python src/train/train.py --git-commit local --dataset-name train_m1_clean \
  --dataset-version v1 --data-source-type verified_id
python src/gates/model_gate/model_gate.py --path artifacts/credit_scoring.onnx --json   # ожидаем PASS
pytest tests/test_consistency.py -v --model-path artifacts/credit_scoring.onnx
uvicorn src.serve.app:app --port 8080 &
python src/serve/attack_sim.py --url http://localhost:8080/predict --n 200               # ожидаем 429
```

## Зависимости/координация
- **От A:** REST-эндпоинты для UI и загрузка моделей из MinIO в serve; `/api/v1/register` для e2e train.
- **С B:** `test_consistency.py` уже подключён в `train.yml`; формат артефакта согласован (ONNX∈allow-list).
