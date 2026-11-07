#!/usr/bin/env bash
# Build a double-click Lightwork.app (+ optional .dmg) on macOS — compiled,
# no PyPI, no source shipped. Mirrors the proven release.yml "binaries" recipe
# (non-editable installs so PyInstaller can bundle them), then wraps the
# compiled `maverick` binary into an .app that opens the local dashboard.
#
# PREREQUISITES (Apple Silicon Mac):
#   xcode-select --install                         # command-line tools
#   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
#   brew install python@3.12 create-dmg            # create-dmg optional (for .dmg)
#
# RUN (from the repo root):
#   bash scripts/build-macos-app.sh
#
# OUTPUT:
#   dist/maverick            — the compiled single-file CLI binary
#   dist/Lightwork.app       — double-click app (opens the dashboard)
#   dist/Lightwork.dmg       — drag-to-Applications installer (if create-dmg present)
#
# NOTE: unsigned. First open: right-click Lightwork.app -> Open -> Open.
# Signing/notarization needs an Apple Developer account (see docs/DISTRIBUTION.md).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3.12}"
command -v "$PY" >/dev/null 2>&1 || { echo "need $PY (brew install python@3.12) or set PYTHON=..."; exit 1; }
[ "$(uname)" = "Darwin" ] || { echo "run this on macOS"; exit 1; }
VERSION="$("$PY" - <<'PY'
import tomllib
from pathlib import Path

cohort = tomllib.loads(Path("release-cohort.toml").read_text(encoding="utf-8"))
print(cohort["version"])
PY
)"
[ -n "$VERSION" ] || { echo "release-cohort.toml does not declare a version"; exit 1; }

echo ">> [1/6] clean venv"
rm -rf .buildvenv dist build/dist build/build
"$PY" -m venv .buildvenv
# shellcheck disable=SC1091
source .buildvenv/bin/activate
python -m pip install --upgrade 'pip==26.3' >/dev/null

echo ">> [2/6] install packages NON-editable (so PyInstaller can bundle them)"
python scripts/install_release_cohort.py \
  --target-python python \
  --core-extra release-runtime
python -m pip install --constraint requirements/ci.txt 'pyinstaller==6.21.0'
python -m pip check
python -c "from maverick.providers import verify_release_runtime; verify_release_runtime()"
python -c "from importlib.metadata import version; assert version('pywhispercpp') == '1.5.0'; print('pywhispercpp:', version('pywhispercpp'))"

echo ">> [3/6] sanity: sqlite3 present in this interpreter"
python -c "import sqlite3, _sqlite3; print('sqlite3', sqlite3.sqlite_version)"

echo ">> [4/6] compile the binary (PyInstaller, from build/)"
( cd build && pyinstaller --clean --noconfirm --distpath ../dist maverick.spec )
./dist/maverick version
./dist/maverick dashboard --help
./dist/maverick mcp --help
./dist/maverick release-runtime-check
voice_status="$(./dist/maverick voice status)"
printf '%s\n' "$voice_status"
grep -F "pywhispercpp engine (installed)" <<<"$voice_status"

echo ">> [5/6] wrap the compiled binary into Lightwork.app"
APP="dist/Lightwork.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp dist/maverick "$APP/Contents/MacOS/maverick"
# icon, if the Tauri source icon exists
if [ -f apps/installer-desktop/src-tauri/icons/icon.icns ]; then
  cp apps/installer-desktop/src-tauri/icons/icon.icns "$APP/Contents/Resources/Lightwork.icns"
fi
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Lightwork</string>
  <key>CFBundleDisplayName</key><string>Lightwork</string>
  <key>CFBundleIdentifier</key><string>com.daybreaklabs.lightwork</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>Lightwork</string>
  <key>CFBundleIconFile</key><string>Lightwork</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
# Launcher: start the compiled dashboard, then open the URL it prints.
cat > "$APP/Contents/MacOS/Lightwork" <<'LAUNCH'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="${TMPDIR:-/tmp}/lightwork-dashboard.log"
# First run drops into the wizard if unconfigured; the dashboard serves the
# local web UI. Both are the SAME compiled binary — no Python on the machine.
if [ ! -f "$HOME/.maverick/config.toml" ]; then
  osascript -e 'display dialog "First run: open Terminal and run the maverick binary once to set up (maverick init). Then reopen Lightwork." buttons {"OK"} default button 1' >/dev/null 2>&1 || true
fi
"$DIR/maverick" dashboard --host 127.0.0.1 --port 8765 >"$LOG" 2>&1 &
SRV=$!
for _ in $(seq 1 40); do
  URL="$(grep -oE 'http://127\.0\.0\.1:[0-9]+' "$LOG" | head -1 || true)"
  [ -n "$URL" ] && break; sleep 0.5
done
open "${URL:-http://127.0.0.1:8765}"
wait "$SRV"
LAUNCH
chmod +x "$APP/Contents/MacOS/Lightwork" "$APP/Contents/MacOS/maverick"

echo ">> [6/6] optional .dmg"
if command -v create-dmg >/dev/null 2>&1; then
  rm -f dist/Lightwork.dmg
  create-dmg --volname "Lightwork" --app-drop-link 480 170 \
    --window-size 720 380 dist/Lightwork.dmg "$APP" >/dev/null 2>&1 \
    && echo "   dist/Lightwork.dmg" || echo "   (create-dmg failed; the .app still works)"
else
  echo "   create-dmg not installed (brew install create-dmg) — skipping .dmg; the .app works."
fi

deactivate || true
echo
echo "DONE."
echo "  dist/Lightwork.app   double-click (first open: right-click -> Open -> Open)"
echo "  dist/maverick        the compiled CLI"
echo "Unsigned build — see docs/DISTRIBUTION.md for signing/notarization."
