#!/usr/bin/env bash
# Build a compiled, single-file `maverick` binary with Nuitka. Where
# PyInstaller bundles .pyc bytecode, Nuitka compiles the Python to C and then
# to a native binary. The PyInstaller path (build-macos-app.sh) stays the fast
# dev/demo build.
#
# NOT a cross-compiler: run this ON each target OS/arch you ship (an arm64 Mac
# for macOS arm64, an x86_64 Linux box for Linux x86_64, Windows for .exe). The
# output name is stamped with the host os/arch so a release feed can carry all
# of them side by side.
#
# PREREQUISITES:
#   - Python 3.11–3.12 (set PYTHON=... to pick one; default python3.12)
#   - A C toolchain Nuitka can drive:
#       macOS   : xcode-select --install            (clang)
#       Linux   : apt-get install -y build-essential patchelf   (gcc + patchelf)
#       Windows : run under MSYS2/Git-Bash with MSVC or bundled MinGW
#   - ~2–4 GB free disk and a few minutes: a C compile is slower than PyInstaller.
#
# RUN (from the repo root):
#   bash scripts/build-nuitka.sh
#
# OUTPUT:
#   dist/maverick-<os>-<arch>[.exe]   — the compiled single-file CLI
#
# Signing/notarization (Apple Developer ID / Windows Authenticode) is a
# separate, post-build step — see docs/DISTRIBUTION.md. This produces the
# unsigned binary; sign the artifact this emits.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3.12}"
command -v "$PY" >/dev/null 2>&1 || {
  echo "need $PY (or set PYTHON=... to an installed 3.11–3.12)"; exit 1; }

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS" in
  darwin) OSTAG="macos" ;;
  linux)  OSTAG="linux" ;;
  msys*|mingw*|cygwin*) OSTAG="windows" ;;
  *) OSTAG="$OS" ;;
esac
EXT=""; [ "$OSTAG" = "windows" ] && EXT=".exe"
OUT="maverick-${OSTAG}-${ARCH}${EXT}"

echo ">> [1/6] clean venv"
rm -rf .nuitkavenv dist/nuitka-build
"$PY" -m venv .nuitkavenv
# shellcheck disable=SC1091
source .nuitkavenv/bin/activate
python -m pip install --upgrade 'pip==26.2.2' >/dev/null

echo ">> [2/6] install packages NON-editable (so Nuitka can follow them)"
python scripts/install_release_cohort.py \
  --target-python python \
  --core-extra release-runtime
python -m pip install --constraint requirements/ci.txt 'nuitka==4.3.4'
python -m pip check
python -c "from maverick.providers import verify_release_runtime; verify_release_runtime()"

echo ">> [3/6] sanity: interpreter has sqlite3 + a C compiler"
python -c "import sqlite3, _sqlite3; print('sqlite3', sqlite3.sqlite_version)"
python -m nuitka --version >/dev/null || { echo "nuitka self-check failed"; exit 1; }

echo ">> [4/6] entry launcher (calls the same console-script target)"
mkdir -p dist/nuitka-build
cat > dist/nuitka-build/_entry.py <<'PY'
# Compiled entry point — identical to the `maverick` console script
# ([project.scripts] maverick = "maverick.cli:main").
import sys
import multiprocessing
if __name__ == "__main__":
    multiprocessing.freeze_support()
    from maverick.cli import main
    sys.exit(main())
PY

echo ">> [5/6] compile with Nuitka (standalone + onefile, C backend)"
# --include-package pulls the maverick packages whole (the CLI imports many
#   submodules dynamically, which --follow-imports alone can miss).
# --include-package-data ships the non-.py assets (dashboard Jinja templates,
#   a11y/report assets, packaged specialist packs) inside the binary.
# --nofollow-import-to excludes test trees so the binary stays lean and no test
#   fixtures ride along.
DESKTOP_INCLUDES=()
case "$(uname)" in
  Darwin) DESKTOP_INCLUDES=(--include-package=objc --include-package=CoreFoundation --include-package=Foundation --include-package=AppKit) ;;
  Linux) DESKTOP_INCLUDES=(--include-package=Xlib) ;;
esac
python -m nuitka \
  --standalone --onefile \
  "${DESKTOP_INCLUDES[@]}" \
  --output-dir=dist/nuitka-build \
  --output-filename="$OUT" \
  --include-package=maverick \
  --include-package=maverick_shield \
  --include-package=maverick_channels \
  --include-package=maverick_evolve \
  --include-package=maverick_dashboard \
  --include-package=maverick_mcp \
  --include-package=maverick_knowledge \
  --include-package=maverick_installer \
  --include-package=pywhispercpp \
  --include-package=openai \
  --include-package=boto3 \
  --include-package=botocore \
  --include-package=s3transfer \
  --include-package-data=maverick \
  --include-package-data=maverick_shield \
  --include-package-data=maverick_evolve \
  --include-package-data=maverick_dashboard \
  --include-package-data=maverick_knowledge \
  --include-package-data=boto3 \
  --include-package-data=botocore \
  --nofollow-import-to='*.tests' \
  --nofollow-import-to='*.test_*' \
  --assume-yes-for-downloads \
  --company-name="Daybreak Labs" \
  --product-name="Lightwork" \
  --file-description="Lightwork governed agent platform" \
  dist/nuitka-build/_entry.py

mkdir -p dist
mv "dist/nuitka-build/$OUT" "dist/$OUT"

echo ">> [6/6] smoke test the compiled binary"
"./dist/$OUT" --help
"./dist/$OUT" version
"./dist/$OUT" dashboard --help
"./dist/$OUT" mcp --help
"./dist/$OUT" release-runtime-check
voice_status="$("./dist/$OUT" voice status)"
printf '%s\n' "$voice_status"
grep -F "pywhispercpp engine (installed)" <<<"$voice_status"
"./dist/$OUT" doctor >/dev/null 2>&1 || true   # doctor exits non-zero without a provider key; that's fine

deactivate || true
echo
echo "DONE."
echo "  dist/$OUT   compiled single-file CLI (C backend — no shippable source)"
echo "Unsigned — sign/notarize per docs/DISTRIBUTION.md before distributing."
