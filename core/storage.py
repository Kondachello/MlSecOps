"""core/storage.py — MinIO (S3): бакеты datasets/quarantine/models(+mlflow), WORM на проде.

См. docs/10_STORAGE.md. Ключи: <bucket>/<name>/<version>/<sha12>_<filename>.
Заблокированное НЕ удаляем (quarantine = улика). Прод — неизменяем (Object Lock/WORM).

Реализация поверх boto3 (S3-совместимый MinIO). Везде GRACEFUL DEGRADATION: если boto3
не установлен или MinIO недоступен/не настроен — `available()` вернёт False, а операции
бросят StorageUnavailable (вызывающий код должен это ловить и деградировать, а не падать).

ВАЖНО (по обсуждению с владельцем): сейчас артефакты MLflow физически лежат в artifact store
MLflow (локально — ./mlruns, в compose — бакет `mlflow` в MinIO). Этот модуль — слой для
будущего: WORM-копия одобренных/прод-моделей в S3/MinIO под двойным контролем (MLflow + наш
сервис). До настройки MINIO_* модуль не активен и ни на что не влияет.
"""
from __future__ import annotations

import os
from typing import Optional

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "")  # пусто → хранилище не настроено
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", os.getenv("AWS_ACCESS_KEY_ID", ""))
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", os.getenv("AWS_SECRET_ACCESS_KEY", ""))
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

BUCKET_DATASETS = os.getenv("MINIO_BUCKET_DATASETS", "datasets")
BUCKET_QUARANTINE = os.getenv("MINIO_BUCKET_QUARANTINE", "quarantine")
BUCKET_MODELS = os.getenv("MINIO_BUCKET_MODELS", "models")
BUCKET_MLFLOW = os.getenv("MINIO_BUCKET_MLFLOW", "mlflow")


class StorageUnavailable(RuntimeError):
    """Хранилище не настроено/недоступно — вызывающий должен деградировать, а не падать."""


def _client():
    """boto3 S3-клиент к MinIO. StorageUnavailable, если boto3 нет или MINIO_* не заданы."""
    if not MINIO_ENDPOINT:
        raise StorageUnavailable("MINIO_ENDPOINT не задан — объектное хранилище не настроено")
    try:
        import boto3  # тянется как зависимость только когда хранилище реально используется
        from botocore.client import Config
    except Exception as e:  # noqa: BLE001
        raise StorageUnavailable(f"boto3 недоступен: {e}") from e
    scheme = "https" if MINIO_SECURE else "http"
    endpoint = MINIO_ENDPOINT if "://" in MINIO_ENDPOINT else f"{scheme}://{MINIO_ENDPOINT}"
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=MINIO_ACCESS_KEY or None,
        aws_secret_access_key=MINIO_SECRET_KEY or None,
        config=Config(signature_version="s3v4"),
    )


def object_key(name: str, version: str, sha256: str, filename: str) -> str:
    return f"{name}/{version}/{sha256[:12]}_{filename}"


def upload(bucket: str, key: str, data: bytes) -> None:
    """Положить объект. StorageUnavailable, если хранилище не настроено/недоступно."""
    try:
        _client().put_object(Bucket=bucket, Key=key, Body=data)
    except StorageUnavailable:
        raise
    except Exception as e:  # noqa: BLE001
        raise StorageUnavailable(f"upload failed ({bucket}/{key}): {e}") from e


def download(bucket: str, key: str) -> bytes:
    """Скачать объект. StorageUnavailable, если хранилище не настроено/недоступно."""
    try:
        resp = _client().get_object(Bucket=bucket, Key=key)
        return resp["Body"].read()
    except StorageUnavailable:
        raise
    except Exception as e:  # noqa: BLE001
        raise StorageUnavailable(f"download failed ({bucket}/{key}): {e}") from e


def available(bucket: Optional[str] = None) -> bool:
    """Доступно ли хранилище (и опц. конкретный бакет) — для graceful degradation.

    Никогда не бросает: возвращает False, если хранилище не настроено/недоступно.
    """
    try:
        c = _client()
    except StorageUnavailable:
        return False
    try:
        if bucket:
            c.head_bucket(Bucket=bucket)
        else:
            c.list_buckets()
        return True
    except Exception:  # noqa: BLE001
        return False


def lock_prod(key: str, *, days: int = 365) -> None:
    """Включить WORM/Object Lock (retention) на прод-объекте models/<key>.

    После этого перезапись/удаление запрещены до истечения retention (COMPLIANCE-режим).
    Требует, чтобы бакет был создан с Object Lock. См. docs/10_STORAGE.md §10.3.
    """
    import datetime as _dt
    until = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=days)
    try:
        _client().put_object_retention(
            Bucket=BUCKET_MODELS, Key=key,
            Retention={"Mode": "COMPLIANCE", "RetainUntilDate": until},
        )
    except StorageUnavailable:
        raise
    except Exception as e:  # noqa: BLE001
        raise StorageUnavailable(f"lock_prod failed ({BUCKET_MODELS}/{key}): {e}") from e
