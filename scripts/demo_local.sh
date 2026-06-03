#!/usr/bin/env bash
# demo_local.sh — сквозной прогон B+C БЕЗ бэкенда A (без БД/MLflow/GitHub).
# Показывает: данные → гейты → обучение 3 моделей → G4 → инференс+атака → мониторинг.
# Требует: pip install -r requirements.txt  (pandas/numpy/sklearn/skl2onnx/onnxruntime/fastapi/...).
set -euo pipefail
cd "$(dirname "$0")/.."

PY=${PYTHON:-python3}
line() { printf '\n\033[1;36m── %s ──\033[0m\n' "$1"; }
pass() { printf '\033[0;32m  ✔ %s\033[0m\n' "$1"; }
fail() { printf '\033[0;31m  ✘ %s\033[0m\n' "$1"; }

# Гейт ожидаемо PASS (exit 0)
expect_pass() { if "$@" >/dev/null 2>&1; then pass "PASS: $*"; else fail "ожидался PASS: $*"; exit 1; fi; }
# Гейт ожидаемо BLOCK (exit 1)
expect_block() { if "$@" >/dev/null 2>&1; then fail "ожидался BLOCK: $*"; exit 1; else pass "BLOCKED (как надо): $*"; fi; }

line "1. Демо-датасеты (чистые + приманки)"
$PY data/make_datasets.py
$PY demo/insecure/make_model_fixtures.py || true

line "2. G1 Data Gate: чистый PASS / отравленный BLOCK"
expect_pass  $PY src/gates/data_gate/data_gate.py --path data/train_m1_clean.csv
expect_block $PY src/gates/data_gate/data_gate.py --path data/train_m1_poisoned.csv

line "3. G3 Supply Gate: чистый PASS / typosquat BLOCK"
expect_pass  $PY src/gates/dependency_gate/dependency_gate.py --path demo/requirements_clean.txt
expect_block $PY src/gates/dependency_gate/dependency_gate.py --path demo/insecure/requirements_vuln.txt

line "4. G5 Registry Gate: полный паспорт PASS / неполный BLOCK"
expect_pass  $PY src/gates/registry_gate/registry_gate.py --card demo/model_card_complete.json
expect_block $PY src/gates/registry_gate/registry_gate.py --card demo/insecure/model_card_incomplete.json

line "5. Обучение 3 моделей в G4-разрешённом формате (ONNX)"
$PY src/train/train.py       --model-name credit_scoring   --git-commit local --dataset-name train_m1_clean --dataset-version v1 --data-source-type verified_id
$PY src/train/train_text.py  --model-name text_classifier  --git-commit local --dataset-name synthetic_text --dataset-version v1 --data-source-type verified_id
$PY src/train/train_risk.py  --model-name transaction_risk --git-commit local --dataset-name train_m1_clean --dataset-version v1 --data-source-type verified_id

line "6. G4 Model Gate на каждом артефакте (формат+SHA) / .pkl BLOCK"
for a in credit_scoring text_classifier transaction_risk; do
  expect_pass $PY src/gates/model_gate/model_gate.py --path artifacts/$a.onnx
done
[ -f demo/insecure/model_unsafe.pkl ] && expect_block $PY src/gates/model_gate/model_gate.py --path demo/insecure/model_unsafe.pkl

line "7. Consistency train↔serve (#19)"
$PY -m pytest tests/test_consistency.py -q || { fail "consistency"; exit 1; }

line "8. G7 рантайм: поднять инференс (модель №1) и проверить rate-limit"
$PY -m uvicorn src.serve.app:app --host 127.0.0.1 --port 8080 >/tmp/serve.log 2>&1 &
SERVE_PID=$!
sleep 4
$PY src/serve/attack_sim.py --url http://127.0.0.1:8080/predict --n 200 --workers 50 || true
kill $SERVE_PID 2>/dev/null || true
pass "G7: см. долю 429 выше (rate-limit). Фичи записаны в logs/inference_credit_scoring.jsonl"

line "9. G6 мониторинг: дрейф (PSI) и подмена (SHA)"
$PY src/monitor/monitor.py --reference data/train_m1_clean.csv --current data/prod_traffic_drifted.csv --columns amount age || true
SHA=$($PY src/monitor/monitor.py --check-substitution artifacts/credit_scoring.onnx | awk '/SHA-256/{print $NF}')
$PY src/monitor/monitor.py --check-substitution artifacts/credit_scoring.onnx --expected-sha "$SHA" || true
$PY src/monitor/monitor.py --check-substitution artifacts/credit_scoring.onnx --expected-sha "deadbeef" || true

line "ГОТОВО"
pass "B+C-стек отработал сквозь, без бэкенда A. Audit Trail (фолбэк) → logs/events.jsonl"
