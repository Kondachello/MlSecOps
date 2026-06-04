#!/usr/bin/env bash
# Generate CycloneDX SBOM from requirements.txt (supply-chain audit artifact).
set -euo pipefail

OUT="${1:-sbom.json}"
REQ="${2:-requirements.txt}"

pip install --quiet cyclonedx-bom
cyclonedx-py requirements -i "${REQ}" -o "${OUT}" --format json
echo "SBOM written: ${OUT} ($(wc -c < "${OUT}") bytes)"
