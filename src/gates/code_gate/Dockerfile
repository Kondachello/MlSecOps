# G2 Code Gate — gitleaks + bandit + pip-audit (+ trivy для stage=deploy).
# Версии пиннированы для воспроизводимости. Обновлять при ревью зависимостей.
FROM python:3.11-slim

ARG GITLEAKS_VERSION=8.18.4

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# gitleaks — статический бинарь из GitHub Releases
RUN curl -sSfL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# trivy НЕ в образе: install.sh на GHA падает после "found version" (сеть/GitHub API).
# Trivy только на runner в deploy.yml (scripts/ci/install_trivy.sh). CI job code-gate — без trivy.
# В контейнере --stage deploy без trivy → check trivy_image = SKIP.

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY code_gate.py .

# Сеть разрешена (pip-audit advisory DB); артефакт монтируется :ro.
ENTRYPOINT ["python", "code_gate.py"]
