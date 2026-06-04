#!/usr/bin/env bash
# Generate CycloneDX SBOM from requirements.txt (supply-chain audit artifact).
set -euo pipefail

OUT="${1:-sbom.json}"
REQ="${2:-requirements.txt}"

python -m pip install --quiet 'cyclonedx-bom>=4.0,<7'

cyclonedx-py requirements -i "${REQ}" -o "${OUT}" -of json

test -s "${OUT}"
echo "SBOM written: ${OUT} ($(wc -c < "${OUT}") bytes)"
