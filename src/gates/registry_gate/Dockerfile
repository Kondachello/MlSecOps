# G5 Compliance/Registry Gate — только stdlib.
FROM python:3.11-slim
WORKDIR /app
COPY registry_gate.py .
#   docker run --rm --network none -v "$CARD:/in:ro" mlsec-gate-registry --card /in/card.json --json
ENTRYPOINT ["python", "registry_gate.py"]
