#!/bin/bash
set -eu

URI="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}"
ROOT="${MLFLOW_ARTIFACT_ROOT:-file:///mlflow-artifacts}"

echo "mlflow: backend-store=${URI} artifacts=${ROOT}"
exec mlflow server \
  --host 0.0.0.0 \
  --port 5000 \
  --backend-store-uri "${URI}" \
  --default-artifact-root "${ROOT}"
