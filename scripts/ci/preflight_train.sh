#!/usr/bin/env bash
# Preflight before train.yml: dataset must be available (mock or Gatekeeper).
set -euo pipefail

USE_GATEKEEPER="${USE_GATEKEEPER:-true}"
DATASET_NAME="${DATASET_NAME:?DATASET_NAME required}"
DATASET_VERSION="${DATASET_VERSION:?DATASET_VERSION required}"

export DATASET_NAME DATASET_VERSION
bash "$(dirname "$0")/preflight_dataset.sh"
