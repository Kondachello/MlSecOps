#!/usr/bin/env bash
# Установка Trivy (официальный install.sh). Используется в deploy.yml и Dockerfile gate-code.
set -euo pipefail
VERSION="${TRIVY_VERSION:-0.58.2}"
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin "v${VERSION}"
trivy --version
