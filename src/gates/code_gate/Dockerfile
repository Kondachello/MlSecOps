# G2 Code Gate — gitleaks + bandit + pip-audit (+ trivy для stage=deploy).
FROM python:3.11-slim

# Бинарники сканеров. Версии пиннить при реализации.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# TODO: установить конкретные версии gitleaks и trivy (curl release / официальный установщик)
#   gitleaks: https://github.com/gitleaks/gitleaks/releases
#   trivy:    https://aquasecurity.github.io/trivy/

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY code_gate.py .

# Сеть разрешена (нужны advisory-БД для pip-audit/trivy); артефакт монтируется :ro.
ENTRYPOINT ["python", "code_gate.py"]
