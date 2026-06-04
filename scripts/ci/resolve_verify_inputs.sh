#!/usr/bin/env bash
# Merge workflow_dispatch inputs and repository_dispatch client_payload → GITHUB_OUTPUT.
# Used by .github/workflows/verify.yml
set -euo pipefail

payload() {
  local key="$1"
  local default="${2:-}"
  python - <<PY
import json, os
key = "$key"
default = """$default"""
ev = json.loads(os.environ.get("GITHUB_EVENT", "{}"))
inp = ev.get("inputs") or {}
cp = ev.get("client_payload") or {}
v = inp.get(key)
if v is None or v == "":
    v = cp.get(key)
if v is None or v == "":
    v = default
if isinstance(v, bool):
    print("true" if v else "false")
elif isinstance(v, (int, float)):
    print(v)
else:
    print(str(v))
PY
}

FLOW="$(payload flow A)"
DATASET_PATH="$(payload dataset_path data/train_m1_clean.csv)"
DATASET_SHA="$(payload dataset_sha256 "")"
DATASET_VERIFIED="$(payload dataset_already_verified false)"
MODEL_CARD="$(payload model_card_path demo/model_card_complete.json)"
GIT_SHA="$(payload git_sha "")"
MODEL_NAME="$(payload model_name "")"
RUN_ID="$(payload run_id "")"
DATASET_NAME="$(payload dataset_name "")"
DATASET_VERSION="$(payload dataset_version "")"
MODEL_ARTIFACT="$(payload model_artifact_path "")"
REQUIREMENTS="$(payload requirements_path demo/requirements_clean.txt)"
CODE_PATH="$(payload code_path src)"

# normalize booleans
case "${DATASET_VERIFIED,,}" in
  true|1|yes) SKIP_G1="true" ;;
  *) SKIP_G1="false" ;;
esac

{
  echo "flow=${FLOW}"
  echo "dataset_path=${DATASET_PATH}"
  echo "dataset_sha256=${DATASET_SHA}"
  echo "dataset_already_verified=${DATASET_VERIFIED}"
  echo "skip_g1=${SKIP_G1}"
  echo "model_card_path=${MODEL_CARD}"
  echo "git_sha=${GIT_SHA}"
  echo "model_name=${MODEL_NAME}"
  echo "run_id=${RUN_ID}"
  echo "dataset_name=${DATASET_NAME}"
  echo "dataset_version=${DATASET_VERSION}"
  echo "model_artifact_path=${MODEL_ARTIFACT}"
  echo "requirements_path=${REQUIREMENTS}"
  echo "code_path=${CODE_PATH}"
} >> "${GITHUB_OUTPUT}"

echo "verify inputs: flow=${FLOW} skip_g1=${SKIP_G1} dataset=${DATASET_PATH}"
