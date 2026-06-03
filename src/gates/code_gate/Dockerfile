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

# trivy не в CI-образе: tar релиза v0.52.2 на GHA давал 404; в ci.yml --stage ci trivy не нужен.
# На deploy — trivy на runner / в deploy.yml (docs/12_CICD, Rina_todo этап 4).
# code_gate при stage=deploy без trivy в PATH → check SKIP, не fail сборки образа.

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY code_gate.py .

# Сеть разрешена (нужны advisory-БД для pip-audit/trivy); артефакт монтируется :ro.
ENTRYPOINT ["python", "code_gate.py"]
