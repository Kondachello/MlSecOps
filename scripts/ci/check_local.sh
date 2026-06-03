#!/usr/bin/env bash
# Быстрая проверка этапа 0 (локально). Нужны: python 3.11, pandas, numpy.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
RUN="$ROOT/scripts/ci/run_gate.sh"

echo "=== демо-данные ==="
pip install -q pandas numpy pyarrow 2>/dev/null || true
python data/make_datasets.py

echo "=== G1 clean (ожидаем 0) ==="
"$RUN" data data/train_m1_clean.csv

echo "=== G1 poisoned (ожидаем 1) ==="
if "$RUN" data data/train_m1_poisoned.csv; then
  echo "ОШИБКА: poisoned должен падать"; exit 1
fi

echo "=== G3 clean (ожидаем 0) ==="
"$RUN" dependency demo/requirements_clean.txt

echo "=== G3 bad (ожидаем 1) ==="
if "$RUN" dependency demo/insecure/requirements_vuln.txt; then
  echo "ОШИБКА: pytirch должен падать"; exit 1
fi

echo "=== этап 0: базовые проверки OK ==="
