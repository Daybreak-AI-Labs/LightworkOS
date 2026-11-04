#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export ENV_HUNTER_STANDALONE=1
exec python serve_standalone.py
