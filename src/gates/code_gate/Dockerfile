# G2 Code Gate — gitleaks + bandit + pip-audit (+ trivy для stage=deploy).
# Версии пиннированы для воспроизводимости. Обновлять при ревью зависимостей.
FROM python:3.11-slim

ARG GITLEAKS_VERSION=8.18.4
ARG TRIVY_VERSION=0.52.2

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# gitleaks — статический бинарь из GitHub Releases
RUN curl -sSfL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# trivy — используется ТОЛЬКО на стадии deploy (--stage deploy --image <image>)
# Устанавливаем через официальный скрипт (apt-репо или прямой бинарь)
RUN curl -sSfL \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY code_gate.py .

# Сеть разрешена (нужны advisory-БД для pip-audit/trivy); артефакт монтируется :ro.
ENTRYPOINT ["python", "code_gate.py"]
