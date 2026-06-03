#!/usr/bin/env bash
# Сборка Docker-образов гейтов: mlsec-gate-data, mlsec-gate-code, ...
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

for dir in "$ROOT"/src/gates/*/; do
  [ -f "$dir/Dockerfile" ] || continue
  name="$(basename "$dir")"   # data_gate
  tag="mlsec-gate-${name%_gate}"
  echo "==> $tag  ($dir)"
  docker build -t "$tag" "$dir"
done

echo "Готово."
