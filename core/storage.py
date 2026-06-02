"""
storage.py — работа с MinIO (S3-совместимое хранилище артефактов).

Три бакета:
  datasets    — чистые, допущенные датасеты;
  quarantine  — ЗАБЛОКИРОВАННЫЕ артефакты (вредоносные/отравленные) —
                НЕ удаляем, а версионируем и храним как улику для атрибуции;
  models      — артефакты моделей.

MinIO опционален: если недоступен, вызывающий код продолжает работу
(см. available()), просто без выгрузки в объектное хранилище.
"""
from __future__ import annotations

import os
from pathlib import Path

import boto3
from botocore.client import Config
from botocore.exceptions import BotoCoreError, ClientError

DATASETS_BUCKET = os.getenv("MINIO_BUCKET_DATASETS", "datasets")
QUARANTINE_BUCKET = os.getenv("MINIO_BUCKET_QUARANTINE", "quarantine")
MODELS_BUCKET = os.getenv("MINIO_BUCKET_MODELS", "models")
ALL_BUCKETS = (DATASETS_BUCKET, QUARANTINE_BUCKET, MODELS_BUCKET)


def _endpoint() -> str:
    # внутри docker-compose: "minio:9000"; локально: "localhost:9000"
    return os.getenv("MINIO_ENDPOINT", "localhost:9000")


def get_client():
    return boto3.client(
        "s3",
        endpoint_url=f"http://{_endpoint()}",
        aws_access_key_id=os.getenv("MINIO_USER", "minioadmin"),
        aws_secret_access_key=os.getenv("MINIO_PASSWORD", "minioadmin"),
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


def available() -> bool:
    """Доступен ли MinIO (для graceful-fallback)."""
    try:
        get_client().list_buckets()
        return True
    except (BotoCoreError, ClientError, OSError):
        return False


def ensure_buckets(client=None) -> None:
    c = client or get_client()
    for b in ALL_BUCKETS:
        try:
            c.head_bucket(Bucket=b)
        except ClientError:
            c.create_bucket(Bucket=b)


def upload_file(local_path: str | Path, bucket: str, key: str, client=None) -> str:
    """Загрузить файл в бакет. Возвращает s3-URI."""
    c = client or get_client()
    ensure_buckets(c)
    c.upload_file(str(local_path), bucket, key)
    return f"s3://{bucket}/{key}"
