#!/usr/bin/env bash
# Запуск гейта локально или из workflow (Git Bash / Linux).
# Пример: ./scripts/ci/run_gate.sh data data/train_m1_clean.csv
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

GATE="${1:?укажи gate: data | code | dependency | model | registry}"
TARGET="${2:?укажи путь к файлу или каталогу}"
shift 2 || true

case "$GATE" in
  data)
    python src/gates/data_gate/data_gate.py --path "$TARGET" --json "$@"
    ;;
  code)
    python src/gates/code_gate/code_gate.py --path "$TARGET" --stage ci --json "$@"
    ;;
  dependency)
    python src/gates/dependency_gate/dependency_gate.py --path "$TARGET" --json "$@"
    ;;
  model)
    python src/gates/model_gate/model_gate.py --path "$TARGET" --json "$@"
    ;;
  registry)
    python src/gates/registry_gate/registry_gate.py --path "$TARGET" --json "$@"
    ;;
  *)
    echo "Неизвестный gate: $GATE" >&2
    exit 2
    ;;
esac
