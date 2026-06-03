# Makefile — задачи B+C (работают без бэкенда A).
# Использует локальный venv .venv (обходит PEP 668 / Homebrew "externally-managed").
# Переопределить интерпретатор: make PY=/path/to/python
VENV ?= .venv
PY   ?= $(VENV)/bin/python
# ML-стек (onnxruntime/skl2onnx) надёжнее всего на 3.11/3.12. Берём первый доступный.
BASE_PY ?= $(shell command -v python3.11 || command -v python3.12 || command -v python3)

.PHONY: help setup datasets fixtures train-all gates consistency serve-credit serve-text serve-risk attack monitor demo build-gates test clean

help:
	@echo "Сначала: make setup  (создаёт .venv и ставит зависимости)"
	@echo "Затем:   make demo | train-all | gates | consistency | serve-credit | attack | monitor"

$(VENV)/bin/python:
	$(BASE_PY) -m venv $(VENV)

setup: $(VENV)/bin/python   ## создать .venv и установить зависимости
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r requirements.txt
	@echo "✅ Готово. Зависимости в $(VENV). Дальше: make demo"

datasets:             ## сгенерировать демо-датасеты
	$(PY) data/make_datasets.py

fixtures:             ## сгенерировать фикстуры моделей (.pkl FAIL / .safetensors PASS)
	$(PY) demo/insecure/make_model_fixtures.py

train-all: datasets   ## обучить 3 модели в ONNX
	$(PY) src/train/train.py      --model-name credit_scoring   --git-commit local --dataset-name train_m1_clean --dataset-version v1 --data-source-type verified_id
	$(PY) src/train/train_text.py --model-name text_classifier  --git-commit local --dataset-name synthetic_text --dataset-version v1 --data-source-type verified_id
	$(PY) src/train/train_risk.py --model-name transaction_risk --git-commit local --dataset-name train_m1_clean --dataset-version v1 --data-source-type verified_id

gates:                ## прогнать гейты на clean/bad фикстурах
	-$(PY) src/gates/data_gate/data_gate.py       --path data/train_m1_clean.csv --json
	-$(PY) src/gates/dependency_gate/dependency_gate.py --path demo/requirements_clean.txt --json
	-$(PY) src/gates/registry_gate/registry_gate.py     --card demo/model_card_complete.json --json
	-$(PY) src/gates/model_gate/model_gate.py     --path artifacts/credit_scoring.onnx --json

consistency:          ## тест парности train<->serve (#19)
	$(PY) -m pytest tests/test_consistency.py -q

serve-credit:         ## поднять инференс модели №1 (порт 8080)
	$(PY) -m uvicorn src.serve.app:app --host 0.0.0.0 --port 8080

serve-text:           ## модель №2 (порт 8081)
	$(PY) -m uvicorn src.serve.app_text:app --host 0.0.0.0 --port 8081

serve-risk:           ## модель №3 (порт 8082)
	$(PY) -m uvicorn src.serve.app_risk:app --host 0.0.0.0 --port 8082

attack:               ## эмуляция Model Stealing → 429
	$(PY) src/serve/attack_sim.py --url http://localhost:8080/predict --n 200

monitor:              ## разовый прогон дрейфа+подмены
	$(PY) src/monitor/monitor.py --reference data/train_m1_clean.csv --current data/prod_traffic_drifted.csv --columns amount age

build-gates:          ## собрать изолированные образы гейтов
	docker compose -f infra/docker-compose.gates.yml build

test:                 ## py_compile + consistency
	$(PY) -m py_compile core/*.py src/gates/*/*.py src/common/*.py src/serve/*.py src/train/*.py src/monitor/*.py ui/app.py
	$(PY) -m pytest tests/ -q

demo:                 ## сквозной B+C прогон без A (через .venv)
	PYTHON=$(abspath $(PY)) bash scripts/demo_local.sh

clean:
	rm -rf artifacts/*.onnx logs/*.jsonl __pycache__ */__pycache__
