#!/usr/bin/env bash
set -euo pipefail
pip install --quiet semgrep
semgrep --version
