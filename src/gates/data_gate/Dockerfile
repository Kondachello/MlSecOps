# G1 Data Gate — образ ТОЛЬКО с инструментами этого гейта.
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY data_gate.py .

# Запуск без сети, артефакт монтируется read-only:
#   docker run --rm --network none -v "$DS:/in:ro" mlsec-gate-data --path /in --json
ENTRYPOINT ["python", "data_gate.py"]
