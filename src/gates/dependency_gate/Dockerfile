# G3 Supply/Dependency Gate — только stdlib.
FROM python:3.11-slim
WORKDIR /app
COPY dependency_gate.py .
# Сеть не нужна для allow-list/пиннинга:
#   docker run --rm --network none -v "$CODE:/in:ro" mlsec-gate-dependency --path /in --json
ENTRYPOINT ["python", "dependency_gate.py"]
