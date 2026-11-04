#!/usr/bin/env bash
# DSAR Concierge — standalone agent, local run.
set -euo pipefail
cd "$(dirname "$0")"
export DSAR_STANDALONE=1
export DSAR_DATA_DIR="${DSAR_DATA_DIR:-$PWD/.dsar-data}"
export DSAR_BASE_URL="${DSAR_BASE_URL:-http://127.0.0.1:8891}"
export EMAIL_SMTP_PORT="${EMAIL_SMTP_PORT:-1026}"
exec python3 serve_standalone.py
