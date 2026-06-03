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

# trivy — deploy (--stage deploy --image); официальный install.sh (прямой tar v0.52 давал 404 на GHA)
ARG TRIVY_VERSION=0.58.2
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}" \
    && trivy --version

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY code_gate.py .

# Сеть разрешена (нужны advisory-БД для pip-audit/trivy); артефакт монтируется :ro.
ENTRYPOINT ["python", "code_gate.py"]
