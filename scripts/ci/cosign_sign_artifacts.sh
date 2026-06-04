#!/usr/bin/env bash
# Sign files with cosign when COSIGN_PRIVATE_KEY is set; otherwise emit SKIP manifest.
set -euo pipefail

OUT_DIR="${1:-./signed}"
mkdir -p "${OUT_DIR}"
shift || true
FILES=("$@")

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "cosign: no files to sign" >&2
  exit 0
fi

if [[ -z "${COSIGN_PRIVATE_KEY:-}" ]]; then
  echo "cosign: SKIP — COSIGN_PRIVATE_KEY not set (demo mode)"
  python - <<'PY' > "${OUT_DIR}/cosign-skip.json"
import json
print(json.dumps({"signed": False, "reason": "COSIGN_PRIVATE_KEY not configured"}, indent=2))
PY
  exit 0
fi

if ! command -v cosign >/dev/null 2>&1; then
  curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /tmp/cosign
  chmod +x /tmp/cosign
  export PATH="/tmp:${PATH}"
fi

export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"

MANIFEST="${OUT_DIR}/signatures.json"
echo '{"artifacts":[]}' > "${MANIFEST}"

for f in "${FILES[@]}"; do
  if [[ ! -f "${f}" ]]; then
    echo "cosign: skip missing ${f}"
    continue
  fi
  echo "cosign sign-blob: ${f}"
  cosign sign-blob --yes --key "env://COSIGN_PRIVATE_KEY" "${f}" \
    --output-signature "${OUT_DIR}/$(basename "${f}").sig" \
    --output-certificate "${OUT_DIR}/$(basename "${f}").cert"
done

python - <<PY
import json, glob, os
out = os.environ.get("OUT_DIR", "./signed")
files = sorted(glob.glob(os.path.join(out, "*.sig")))
print(json.dumps({"signed": True, "count": len(files), "signatures": files}, indent=2))
PY
