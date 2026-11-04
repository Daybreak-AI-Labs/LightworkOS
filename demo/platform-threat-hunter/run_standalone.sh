#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PLATFORM_HUNTER_STANDALONE=1
exec python serve_standalone.py
