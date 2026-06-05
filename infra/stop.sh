#!/usr/bin/env bash
# ============================================================================
#  stop.sh — остановить локальный дев-стенд MLSecOps (macOS/Linux).
#  Гасит процессы по PID из .run/ и добивает слушателей на портах 5000/8200/8501.
#  Запуск:  bash infra/stop.sh
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN="$REPO/.run"

API_PORT="${API_PORT:-8200}"
MLFLOW_PORT="${MLFLOW_PORT:-5000}"
UI_PORT="${UI_PORT:-8501}"

# 1) По сохранённым PID.
for name in ui backend mlflow; do
  pidfile="$RUN/$name.pid"
  if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      echo "[stop] $name (pid $pid)"
      kill "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
done

# 2) Добить всех, кто ещё слушает наши порты (на случай дочерних воркеров MLflow).
for port in "$UI_PORT" "$API_PORT" "$MLFLOW_PORT"; do
  pids="$(lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    echo "[stop] порт $port → pids: $pids"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    sleep 1
    pids="$(lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
    # shellcheck disable=SC2086
    [ -n "$pids" ] && kill -9 $pids 2>/dev/null || true
  fi
done

echo "Остановлено."
