#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export MODEL_RISK_OFFICER_STANDALONE=1
exec python serve_standalone.py
