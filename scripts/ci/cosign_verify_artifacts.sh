#!/usr/bin/env bash
# Verify cosign signatures produced by cosign_sign_artifacts.sh (mandatory on prod deploy).
set -euo pipefail

SIG_DIR="${1:-./signed}"
shift || true
FILES=("$@")

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "cosign verify: no files" >&2
  exit 1
fi

if [[ -f "${SIG_DIR}/cosign-skip.json" ]]; then
  if [[ "${REQUIRE_COSIGN:-false}" == "true" ]]; then
    echo "cosign verify: FAIL — signing was SKIPPED but REQUIRE_COSIGN=true" >&2
    exit 1
  fi
  echo "cosign verify: SKIP (demo mode, REQUIRE_COSIGN not set)"
  exit 0
fi

if ! command -v cosign >/dev/null 2>&1; then
  curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /tmp/cosign
  chmod +x /tmp/cosign
  export PATH="/tmp:${PATH}"
fi

KEY_ARG=()
if [[ -n "${COSIGN_PUBLIC_KEY:-}" ]]; then
  KEY_ARG=(--key "env://COSIGN_PUBLIC_KEY")
elif [[ -n "${COSIGN_PRIVATE_KEY:-}" ]]; then
  KEY_ARG=(--key "env://COSIGN_PRIVATE_KEY")
else
  echo "cosign verify: no COSIGN_PUBLIC_KEY or COSIGN_PRIVATE_KEY" >&2
  exit 1
fi

export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"
FAIL=0
for f in "${FILES[@]}"; do
  base="$(basename "${f}")"
  sig="${SIG_DIR}/${base}.sig"
  cert="${SIG_DIR}/${base}.cert"
  if [[ ! -f "${sig}" ]]; then
    echo "cosign verify: missing signature ${sig}" >&2
    FAIL=1
    continue
  fi
  echo "cosign verify-blob: ${f}"
  if [[ -f "${cert}" ]]; then
    cosign verify-blob "${KEY_ARG[@]}" --signature "${sig}" --certificate "${cert}" "${f}"
  else
    cosign verify-blob "${KEY_ARG[@]}" --signature "${sig}" "${f}"
  fi
done
exit "${FAIL}"
