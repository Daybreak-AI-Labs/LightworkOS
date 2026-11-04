#!/usr/bin/env bash
# Lightwork desktop bootstrap (macOS / Linux).
#
# Installs Python 3 if missing and uses a trusted system-installed pipx,
# then checks out an exact
# Lightwork commit into an isolated pipx environment, and launches the wizard
# (`maverick init`). There is deliberately no public-package-index fallback.
#
# Set MAVERICK_REF to a reviewed, lowercase, full 40-character commit SHA.
# Mutable refs and an omitted ref fail before the script changes the machine.

set -euo pipefail

REPO="${MAVERICK_REPO:-Daybreak-AI-Labs/LightworkOS}"
REF="${MAVERICK_REF:-}"
SRC_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/maverick/src"
STAGED_SRC=""

cleanup_staged_source() {
  if [ -n "${STAGED_SRC:-}" ] && [ -d "$STAGED_SRC" ]; then
    rm -rf -- "$STAGED_SRC"
  fi
}
trap cleanup_staged_source EXIT

log()  { printf '==> %s\n' "$*" >&2; }
warn() { printf '!!  %s\n' "$*" >&2; }
die()  { printf 'Lightwork install failed: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# pipx may be a standalone CLI (installed by a package manager) or a
# module under the system Python. Call whichever exists.
pipx_cmd() { if have pipx; then pipx "$@"; else python3 -m pipx "$@"; fi; }

ensure_git() {
  have git && return
  log "Installing git ..."
  if   have brew;    then brew install git
  elif have apt-get; then sudo apt-get update && sudo apt-get install -y git
  elif have dnf;     then sudo dnf install -y git
  elif have pacman;  then sudo pacman -Sy --noconfirm git
  else die "No supported package manager (brew/apt/dnf/pacman). Install git, then re-run."
  fi
}

python3_meets_floor() {
  [ "$(python3 -c 'import sys;print("%d%02d"%sys.version_info[:2])')" -ge 311 ]
}

ensure_python() {
  if have python3 && python3_meets_floor; then
    return
  fi
  log "Installing Python 3 ..."
  case "$(uname -s)" in
    Darwin) have brew || die "Install Homebrew (https://brew.sh) or Python 3.11+, then re-run."
            brew install python ;;
    *)      if   have apt-get; then sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip
            elif have dnf;     then sudo dnf install -y python3 python3-pip
            elif have pacman;  then sudo pacman -Sy --noconfirm python python-pip
            else die "No supported package manager. Install Python 3.11+, then re-run."
            fi ;;
  esac
  have python3 || die "Python install finished but 'python3' is not on PATH. Open a new terminal and re-run."
  # A distro's python3 can still be older than the floor (3.10 on
  # Ubuntu 22.04); stop here rather than at pip's requires-python check.
  python3_meets_floor || die "Lightwork needs Python 3.11 or newer, but this system's python3 is $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])'). Install Python 3.11 or newer as python3, then re-run."
}

ensure_pipx() {
  pipx_cmd --version >/dev/null 2>&1 && { pipx_cmd ensurepath >/dev/null 2>&1 || true; return; }
  log "Installing pipx ..."
  if   have brew;    then brew install pipx
  elif have apt-get; then sudo apt-get update && sudo apt-get install -y pipx
  elif have dnf;     then sudo dnf install -y pipx
  elif have pacman;  then sudo pacman -Sy --noconfirm python-pipx
  else
    die "Install pipx using your trusted system package manager, then re-run."
  fi
  pipx_cmd --version >/dev/null 2>&1 || die "pipx is unavailable after installation."
  pipx_cmd ensurepath >/dev/null 2>&1 || true
}

validate_source_pin() {
  [ -n "$REF" ] || die "MAVERICK_REF is required. Set it to a reviewed, full 40-character Lightwork commit SHA; public-index fallback is disabled."
  [[ "$REF" =~ ^[0-9a-f]{40}$ ]] && return 0
  die "MAVERICK_REF must be a lowercase, full 40-character commit SHA; got '$REF'."
}

validate_repo() {
  # MAVERICK_REPO is interpolated into https://github.com/$REPO for the git
  # clone/fetch below. Constrain it to a GitHub "owner/repo" slug so a hostile
  # or typo'd value can't point the install at a different repo or smuggle
  # shell/URL metacharacters into the git command. (Only the source path uses
  # REPO.)
  if [[ ! "$REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
    die "MAVERICK_REPO must be a GitHub 'owner/repo' slug (letters, digits, '.', '_', '-'); got '$REPO'."
  fi
}

fetch_source() {
  validate_repo
  validate_source_pin
  log "Downloading a fresh Lightwork source tree ($REPO@$REF) ..."
  mkdir -p "$(dirname "$SRC_DIR")"
  STAGED_SRC="$(mktemp -d "$(dirname "$SRC_DIR")/src.stage.XXXXXX")"
  git clone --no-checkout --filter=blob:none \
    "https://github.com/$REPO" "$STAGED_SRC"
  git -C "$STAGED_SRC" fetch --depth 1 origin "$REF"
  git -C "$STAGED_SRC" -c advice.detachedHead=false \
    checkout --detach FETCH_HEAD >/dev/null 2>&1
  actual_ref="$(git -C "$STAGED_SRC" rev-parse HEAD)"
  [ "$actual_ref" = "$REF" ] || die "Checked-out source is at '$actual_ref', not required ref '$REF'."
  [ -z "$(git -C "$STAGED_SRC" status --porcelain --untracked-files=all)" ] \
    || die "Fresh pinned Lightwork checkout is unexpectedly dirty."
  [ -f "$STAGED_SRC/packages/maverick-core/pyproject.toml" ] \
    || die "Pinned checkout is not a complete Lightwork source tree."
  rm -rf -- "$SRC_DIR"
  mv -- "$STAGED_SRC" "$SRC_DIR"
  STAGED_SRC=""
}

install_maverick() {
  log "Installing the complete Lightwork package cohort (this can take a minute) ..."
  fetch_source
  # Let pipx create and expose the managed environment without resolving a
  # partial dependency graph. The cohort helper immediately performs the one
  # constrained eight-package resolver transaction and verifies imports.
  pipx_cmd install --force --pip-args=--no-deps \
    "$SRC_DIR/packages/maverick-core"
  local venvs target_python
  venvs="$(pipx_cmd environment --value PIPX_LOCAL_VENVS)"
  target_python="$venvs/maverick-agent/bin/python"
  [ -x "$target_python" ] \
    || die "pipx created no maverick-agent environment at $target_python"
  python3 "$SRC_DIR/scripts/install_release_cohort.py" \
    --source-root "$SRC_DIR" \
    --target-python "$target_python" \
    --core-extra release-runtime
}

run_wizard() {
  local bin
  bin="$(pipx_cmd environment --value PIPX_BIN_DIR 2>/dev/null || true)"
  [ -n "$bin" ] || bin="$HOME/.local/bin"
  export PATH="$bin:$PATH"

  printf '\nMaverick installed.\nLaunching the setup wizard...\n\n'
  if ! have maverick; then
    warn "Installed, but 'maverick' is not on this shell's PATH yet."
    printf "Open a new terminal and run:  maverick init\n"
    return
  fi
  # This script is usually run via `curl | bash`, so stdin is the pipe,
  # not the keyboard. Re-attach the wizard to the terminal so its
  # interactive prompts can read input.
  if [ -e /dev/tty ]; then maverick init </dev/tty; else maverick init; fi
}

main() {
  printf '\nMaverick desktop installer\n\n'
  validate_source_pin
  ensure_python
  ensure_pipx
  ensure_git
  install_maverick
  # The desktop GUI installer sets MAVERICK_NO_WIZARD: do the install but
  # skip the interactive wizard (the app then points the user at
  # `maverick init`, which a GUI can't drive over a pipe).
  if [ -n "${MAVERICK_NO_WIZARD:-}" ]; then
    printf '\nMaverick installed. Run `maverick init` to configure it.\n'
  else
    run_wizard
  fi
}

main "$@"
