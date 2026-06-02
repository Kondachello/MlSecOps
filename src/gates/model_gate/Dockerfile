# G4 Model Gate — modelscan/picklescan + cosign (подпись).
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# TODO: установить cosign (sigstore) для проверки подписи на деплое.
COPY model_gate.py .
# Артефакт монтируется :ro; сеть не нужна для формата/хэша:
#   docker run --rm --network none -v "$ART:/in:ro" mlsec-gate-model --path /in --json
ENTRYPOINT ["python", "model_gate.py"]
