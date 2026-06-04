"""core/storage.py — MinIO (S3) + локальный fallback; WORM-маркер на прод-объектах."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

BUCKET_DATASETS = os.getenv("MINIO_BUCKET_DATASETS", "datasets")
BUCKET_QUARANTINE = os.getenv("MINIO_BUCKET_QUARANTINE", "quarantine")
BUCKET_MODELS = os.getenv("MINIO_BUCKET_MODELS", "models")
BUCKET_MLFLOW = os.getenv("MINIO_BUCKET_MLFLOW", "mlflow")

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")

_REPO_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_ROOT = Path(os.getenv("STORAGE_LOCAL_ROOT", str(_REPO_ROOT / "storage_local")))


def object_key(name: str, version: str, sha256: str, filename: str) -> str:
    return f"{name}/{version}/{sha256[:12]}_{filename}"


def _s3_client():
    import boto3
    from botocore.client import Config

    return boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
        config=Config(signature_version="s3v4"),
    )


def available(bucket: str) -> bool:
    """Доступно ли хранилище (MinIO или локальный fallback)."""
    if MINIO_ENDPOINT and MINIO_ACCESS_KEY and MINIO_SECRET_KEY:
        try:
            _s3_client().head_bucket(Bucket=bucket)
            return True
        except Exception:
            pass
    _LOCAL_ROOT.mkdir(parents=True, exist_ok=True)
    return True


def upload(bucket: str, key: str, data: bytes) -> None:
    """Положить объект (MinIO или storage_local/<bucket>/<key>)."""
    if MINIO_ENDPOINT and MINIO_ACCESS_KEY and MINIO_SECRET_KEY:
        try:
            _s3_client().put_object(Bucket=bucket, Key=key, Body=data)
            return
        except Exception:
            pass
    dest = _LOCAL_ROOT / bucket / key
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)


def download(bucket: str, key: str) -> bytes:
    if MINIO_ENDPOINT and MINIO_ACCESS_KEY and MINIO_SECRET_KEY:
        try:
            obj = _s3_client().get_object(Bucket=bucket, Key=key)
            return obj["Body"].read()
        except Exception:
            pass
    path = _LOCAL_ROOT / bucket / key
    if not path.is_file():
        raise FileNotFoundError(f"{bucket}/{key}")
    return path.read_bytes()


def lock_prod(key: str) -> None:
    """WORM: маркер неизменяемости (Object Lock в MinIO — TODO; локально — .worm файл)."""
    bucket = BUCKET_MODELS
    marker_key = f"{key}.worm"
    payload = b"locked"
    if MINIO_ENDPOINT and MINIO_ACCESS_KEY and MINIO_SECRET_KEY:
        try:
            client = _s3_client()
            # Best-effort: retention на объекте (если бакет с Object Lock)
            try:
                client.put_object_retention(
                    Bucket=bucket,
                    Key=key,
                    Retention={"Mode": "COMPLIANCE", "RetainUntilDate": "2099-01-01T00:00:00Z"},
                )
            except Exception:
                client.put_object(Bucket=bucket, Key=marker_key, Body=payload)
            return
        except Exception:
            pass
    path = _LOCAL_ROOT / bucket / marker_key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
