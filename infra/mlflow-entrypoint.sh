#!/bin/bash
set -eu

pip install -q --no-cache-dir psycopg2-binary 2>/dev/null || true

PG_HOST="${POSTGRES_HOST:-postgres}"
PG_DB="${MLFLOW_POSTGRES_DB:-mlflow}"
ART="${MLFLOW_ARTIFACT_ROOT:-file:///mlflow-artifacts}"
URI="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${PG_HOST}:5432/${PG_DB}"

echo "mlflow: waiting for ${PG_HOST}..."
for _ in $(seq 1 60); do
  if python -c "import socket; socket.gethostbyname('${PG_HOST}')" 2>/dev/null; then
    break
  fi
  sleep 2
done

echo "mlflow: backend-store=${URI} artifacts=${ART}"
exec mlflow server \
  --host 0.0.0.0 \
  --port 5000 \
  --backend-store-uri "${URI}" \
  --default-artifact-root "${ART}"
