"""core/storage.py — MinIO (S3): бакеты datasets/quarantine/models(+mlflow), WORM на проде.

См. docs/10_STORAGE.md. Ключи: <bucket>/<name>/<version>/<sha12>_<filename>.
Заблокированное НЕ удаляем (quarantine = улика). Прод — неизменяем (Object Lock/WORM).
Скелет: контракты зафиксированы, реализация TODO.
"""
from __future__ import annotations

import os
from typing import Optional

BUCKET_DATASETS = os.getenv("MINIO_BUCKET_DATASETS", "datasets")
BUCKET_QUARANTINE = os.getenv("MINIO_BUCKET_QUARANTINE", "quarantine")
BUCKET_MODELS = os.getenv("MINIO_BUCKET_MODELS", "models")
BUCKET_MLFLOW = os.getenv("MINIO_BUCKET_MLFLOW", "mlflow")


def _client():
    """boto3 S3-клиент к MinIO. Graceful: нет MinIO → вызывающий код деградирует. TODO."""
    raise NotImplementedError("TODO: boto3.client('s3', endpoint_url=MINIO_ENDPOINT, ...)")


def object_key(name: str, version: str, sha256: str, filename: str) -> str:
    return f"{name}/{version}/{sha256[:12]}_{filename}"


def upload(bucket: str, key: str, data: bytes) -> None:
    """Положить объект. TODO."""
    raise NotImplementedError("TODO")


def download(bucket: str, key: str) -> bytes:
    """Скачать объект. TODO."""
    raise NotImplementedError("TODO")


def available(bucket: str) -> bool:
    """Доступен ли бакет/хранилище (для graceful degradation). TODO."""
    raise NotImplementedError("TODO")


def lock_prod(key: str) -> None:
    """Включить WORM/Object Lock (retention) на прод-объекте models/prod/<key>.

    После этого перезапись/удаление объекта запрещены. См. docs/10_STORAGE.md §10.3.
    TODO: put_object_retention / object lock config.
    """
    raise NotImplementedError("TODO")
