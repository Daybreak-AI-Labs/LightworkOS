#!/usr/bin/env bash
# Devcontainer / Codespaces bootstrap: editable-install the workspace packages
# the same way CI does, so tests and the CLI work out of the box.
set -euo pipefail

# Stay inside the interpreter window CI tests (3.11-3.12). A newer host
# interpreter (3.13) cannot install the cohort, so prefer a supported one.
python_bin=python3
for candidate in python3.12 python3.11; do
  if command -v "$candidate" >/dev/null 2>&1; then
    python_bin="$candidate"
    break
  fi
done
# The host python3 fallback can be below the floor (3.10 on Ubuntu 22.04);
# stop here rather than inside pip's requires-python check.
if ! "$python_bin" -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
  echo "post-create.sh: Lightwork needs Python 3.11 or 3.12, but $python_bin is $("$python_bin" -c 'import sys;print("%d.%d"%sys.version_info[:2])'). Install Python 3.11 or 3.12, then re-run." >&2
  exit 1
fi

"$python_bin" -c 'import sys; sys.exit(0 if (3, 11) <= sys.version_info[:2] <= (3, 12) else "Lightwork requires Python 3.11 or 3.12 for development.")'
"$python_bin" -m venv .venv
export PATH="$PWD/.venv/bin:$PATH"

# Resolve every dependency from the reviewed CI set, exactly as the test and
# posture jobs do (ci.yml sets the same PIP_CONSTRAINT). An unconstrained
# install drifts from the gate: two dashboard streaming tests encode Starlette
# 1.7.0 behaviour and fail on 1.8.0.
export PIP_CONSTRAINT="$PWD/requirements/ci.txt"

# Install every reviewed local package together so pip resolves their declared
# runtime dependencies without downloading a separate copy of the core.
python scripts/install_release_cohort.py --editable

# Development-only dependencies and optional test integrations.
# pyjwt[crypto] mirrors the CI test job (test_oidc.py self-skips without it).
# cffi: distro-owned cryptography builds (e.g. Debian's 41.x) lack
# _cffi_backend for this interpreter and crash pytest collection with a
# pyo3 PanicException; pip can't replace the distro package, but installing
# cffi fixes the import. build: so `python3 -m build --wheel` works per-package.
# pytest-xdist + pytest-timeout: the CI invocation (-n auto --dist loadfile,
# --timeout) and the CLAUDE.md test command need them. sqlalchemy: the
# database tool imports it; .github/actions/test-shard installs it and three
# governed-tools / query-execution tests fail without it. detect-secrets: the
# scripts/pre-push-lint.sh baseline gate silently skips without it.
pip install pytest pytest-asyncio pytest-xdist pytest-timeout 'ruff>=0.5' 'vulture>=2.11' 'mypy>=1.18.2' \
            'pyjwt[crypto]' cffi build 'pyyaml>=6.0.3' sqlalchemy detect-secrets
# AI-evidence local parsers: Pillow mirrors the CI environment
# (requirements/ci.txt pins it); xlrd + olefile power the legacy-XLS worker.
# Their tests self-skip without these (test_oidc pattern), so this install is
# what makes them actually RUN in the devcontainer.
# lxml also matches core[spreadsheet] in CI, including the XLSX amplification checks.
pip install 'pillow>=10' 'xlrd>=2.0' 'olefile>=0.47' 'lxml>=5.0'
# openai: every OpenAI-compatible provider (openai/ollama/vllm/tgi/azure/...)
# imports it; without it a vllm:/ollama:-routed run dies at the provider.
pip install 'openai>=1.30'

echo
echo "Lightwork devcontainer ready."
echo "  try:  maverick --help"
echo "  test: python3 -m pytest -q -n auto --dist loadfile"
