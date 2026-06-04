#!/usr/bin/env bash
# Upload prod model artifact with WORM lock (MinIO or local fallback).
set -euo pipefail

MODEL_NAME="${MODEL_NAME:?MODEL_NAME}"
VERSION="${VERSION:?VERSION}"
ARTIFACT="${1:-artifacts/model.safetensors}"

cd "$(dirname "$0")/../.."
python - <<PY
import hashlib, os, sys
from pathlib import Path

repo = Path.cwd()
sys.path.insert(0, str(repo))

from core import storage

art = Path("${ARTIFACT}")
if not art.is_file():
    print(f"worm_upload: artifact missing: {art}", file=sys.stderr)
    sys.exit(1)

data = art.read_bytes()
sha = hashlib.sha256(data).hexdigest()
key = storage.object_key("${MODEL_NAME}", "${VERSION}", sha, art.name)
bucket = os.getenv("MINIO_BUCKET_MODELS", storage.BUCKET_MODELS)

prod_key = f"prod/{key}"
storage.upload(bucket, prod_key, data)
storage.lock_prod(prod_key)
print(f"worm_upload: OK bucket={bucket}/prod key={key} sha256={sha[:12]}...")
PY
