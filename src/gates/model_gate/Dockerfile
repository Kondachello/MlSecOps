# G4 Model Gate — modelscan/picklescan + cosign (подпись + проверка).
# --network none: артефакт монтируется :ro, сеть не нужна для хэша/скана.
# cosign нужен ТОЛЬКО при --cosign-key (на деплое).
FROM python:3.11-slim

ARG COSIGN_VERSION=2.2.4

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# cosign — проверка Sigstore-подписей артефактов
RUN curl -sSfL \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
    -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY model_gate.py .

# Запуск без сети, артефакт монтируется read-only:
#   docker run --rm --network none -v "$ART:/in:ro" mlsec-gate-model --path /in/model.safetensors --json
ENTRYPOINT ["python", "model_gate.py"]
