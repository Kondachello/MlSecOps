#!/usr/bin/env bash
# ============================================================================
#  start.sh — запуск всего локального дев-стенда MLSecOps одной командой (macOS/Linux).
#  Аналог infra/start.cmd для Windows.
#
#  Запуск из любого места:   bash infra/start.sh
#  (или сделай исполняемым:  chmod +x infra/start.sh && ./infra/start.sh)
#
#  Поднимает 3 сервиса в ФОНЕ (логи в logs/, PID в .run/):
#    1) MLflow server  :5000  — backend store = НАШ репо-файл mlsec_mlflow.db (контроль),
#                               артефакты — в ~/mlsec_mlflow/artifacts (вне репо, чистый путь).
#    2) Backend (API)  :8200  — FastAPI + auth-прокси /mlflow.
#    3) Streamlit UI   :8501.
#
#  Остановить:  bash infra/stop.sh
#  Логи:        tail -f logs/{mlflow,backend,ui}.log
#  Порт 8200 (а не 8000) — для паритета с Windows/доками (GATEKEEPER_URL по умолчанию).
# ============================================================================
set -euo pipefail

# Репо-корень = родитель папки этого скрипта.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO"

# Python: предпочитаем venv репозитория, иначе системный python3.
if [ -x "$REPO/.venv/bin/python" ]; then
  PY="$REPO/.venv/bin/python"
else
  PY="$(command -v python3 || true)"
fi
if [ -z "${PY:-}" ]; then
  echo "[ОШИБКА] Не найден python (.venv/bin/python или python3). Установи Python 3.11+." >&2
  exit 1
fi
echo "Python: $PY"

# --- Параметры стенда -------------------------------------------------------
API_PORT="${API_PORT:-8200}"
MLFLOW_PORT="${MLFLOW_PORT:-5000}"
UI_PORT="${UI_PORT:-8501}"

# BACKEND STORE MLflow = НАШ файл в репо (контроль/безопасность), НЕ дефолтный ./mlruns и НЕ
# mlsec_dev.db (там конфликт имён таблиц datasets/model_versions со схемой MLflow).
OURSTORE="$REPO/mlsec_mlflow.db"
export MLFLOW_BACKEND_STORE_URI="${MLFLOW_BACKEND_STORE_URI:-sqlite:///$OURSTORE}"
# Артефакты (большие бинарники) — на диске, вне репо, чистый путь.
ARTDIR="${ARTDIR:-$HOME/mlsec_mlflow/artifacts}"
mkdir -p "$ARTDIR"

# Общее окружение для дочерних процессов.
export DB_BACKEND="${DB_BACKEND:-sqlite}"
export BOOTSTRAP_ADMIN_PASSWORD="${BOOTSTRAP_ADMIN_PASSWORD:-admin-pass}"
export MLFLOW_UPSTREAM_URL="http://127.0.0.1:$MLFLOW_PORT"
export GATEKEEPER_URL="http://localhost:$API_PORT"
export MLFLOW_UI_URL="http://localhost:$MLFLOW_PORT"
export APP_DEBUG="${APP_DEBUG:-true}"
export PYTHONPATH="$REPO"
# Внутренний MLflow доверенный и локальный — не пускаем запросы к нему через системный прокси.
export NO_PROXY="127.0.0.1,localhost,::1${NO_PROXY:+,$NO_PROXY}"
export no_proxy="$NO_PROXY"

LOGS="$REPO/logs"; RUN="$REPO/.run"
mkdir -p "$LOGS" "$RUN"

echo "Repo:         $REPO"
echo "MLflow store: $MLFLOW_BACKEND_STORE_URI"
echo "Artifacts:    $ARTDIR"
echo "Ports:        MLflow=$MLFLOW_PORT  API=$API_PORT  UI=$UI_PORT"
echo

# --- Хелперы ----------------------------------------------------------------
port_busy() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

start_svc() { # name port "cmd..."
  local name="$1" port="$2"; shift 2
  if port_busy "$port"; then
    echo "[skip] $name: порт $port уже занят (сервис, видимо, уже запущен)."
    return 0
  fi
  echo "[start] $name → :$port  (лог: logs/$name.log)"
  ( "$@" ) >"$LOGS/$name.log" 2>&1 &
  echo $! >"$RUN/$name.pid"
}

wait_http() { # url tries label
  local url="$1" tries="${2:-40}" label="${3:-service}"
  for _ in $(seq 1 "$tries"); do
    if curl -s -o /dev/null "$url" 2>/dev/null; then return 0; fi
    sleep 1
  done
  echo "[warn] $label не ответил на $url за ${tries}с — смотри лог." >&2
  return 1
}

# --- 0) Bootstrap первого админа (идемпотентно) -----------------------------
echo "[seed] admin (msecops / $BOOTSTRAP_ADMIN_PASSWORD)"
"$PY" -m infra.seed_admin || echo "[warn] seed_admin не отработал (возможно, БД занята) — продолжаю."

# --- 1) MLflow --------------------------------------------------------------
start_svc mlflow "$MLFLOW_PORT" \
  "$PY" -m mlflow server \
    --backend-store-uri "$MLFLOW_BACKEND_STORE_URI" \
    --artifacts-destination "file://$ARTDIR" \
    --host 127.0.0.1 --port "$MLFLOW_PORT" --workers 1
# MLflow 3 на первом старте мигрирует БД ~10-30с — ждём готовности REST.
wait_http "http://127.0.0.1:$MLFLOW_PORT/health" 40 "MLflow" \
  || wait_http "http://127.0.0.1:$MLFLOW_PORT/" 10 "MLflow" || true

# --- 2) Backend (FastAPI + auth-прокси) -------------------------------------
start_svc backend "$API_PORT" \
  "$PY" -m uvicorn src.api.main:app --host 127.0.0.1 --port "$API_PORT"
wait_http "http://127.0.0.1:$API_PORT/api/v1/events" 30 "Backend" || true

# --- 3) Streamlit UI --------------------------------------------------------
start_svc ui "$UI_PORT" \
  "$PY" -m streamlit run ui/app.py --server.port "$UI_PORT" --server.address 127.0.0.1 \
    --server.headless true

echo
echo "Готово. Открой:"
echo "  UI:      http://localhost:$UI_PORT   (вход: msecops / $BOOTSTRAP_ADMIN_PASSWORD)"
echo "  API:     http://localhost:$API_PORT/docs"
echo "  MLflow:  http://localhost:$MLFLOW_PORT"
echo
echo "Логи:     tail -f logs/{mlflow,backend,ui}.log"
echo "Стоп:     bash infra/stop.sh"
echo "Демо:     $PY examples/dev_train_mock.py   (после выдачи роли DS аккаунту)"
