#!/usr/bin/env bash
# Lightwork VPS bootstrap script.
#
# Usage (the script URL and checkout must use the same reviewed commit):
#   LIGHTWORK_REF=<lowercase-full-40-character-commit-sha>
#   curl -fsSLo /tmp/lightwork-install.sh \
#     "https://raw.githubusercontent.com/Daybreak-AI-Labs/LightworkOS/${LIGHTWORK_REF}/deploy/vps/install.sh"
#   sudo MAVERICK_REF="$LIGHTWORK_REF" bash /tmp/lightwork-install.sh
#
# What it does:
#   1. Installs the distro's Python 3 (3.11 or newer is required), pipx, git
#   2. Installs the complete eight-package Lightwork release cohort into one
#      pipx venv
#   3. Runs `maverick init` interactively
#   4. Drops a systemd unit so maverick serve runs at boot
#   5. Optionally configures Caddy for HTTPS (see Caddyfile next to this script)
#
# Optional:
#   MAVERICK_CORE_EXTRAS  comma-separated maverick-agent extras to install
#     (default: release-runtime,postgres,oidc,s3,evidence-analysis -- the same
#     set the container image installs, so MAVERICK_WORLD_BACKEND=postgres,
#     OIDC browser login, S3 attachments and the AI evidence parsers work on a
#     VPS without a second install step).

set -euo pipefail

MAVERICK_REF="${MAVERICK_REF:-}"
MAVERICK_CORE_EXTRAS="${MAVERICK_CORE_EXTRAS:-release-runtime,postgres,oidc,s3,evidence-analysis}"
STAGED_SOURCE=""

cleanup_staged_source() {
  if [[ -n "${STAGED_SOURCE:-}" && -d "$STAGED_SOURCE" ]]; then
    rm -rf -- "$STAGED_SOURCE"
  fi
}
trap cleanup_staged_source EXIT

# Everything user-facing (the pipx venv, the wizard, the systemd service)
# runs as one non-root account with one consistent HOME, so the `maverick`
# binary always lives at a single known path. For sudo installs we use the
# invoking human; for direct-root installs we create/use a dedicated service
# account instead of running the remotely driven agent as root.
SERVICE_ACCOUNT="${MAVERICK_SERVICE_USER:-maverick}"
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  TARGET_USER="$SUDO_USER"
else
  TARGET_USER="$SERVICE_ACCOUNT"
fi
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6 || true)"
TARGET_HOME="${TARGET_HOME:-/var/lib/${TARGET_USER}}"

log() { echo "==> $*" >&2; }

validate_source_pin() {
  [[ "$MAVERICK_REF" =~ ^[0-9a-f]{40}$ ]] || {
    echo "MAVERICK_REF is required and must be a lowercase, full 40-character commit SHA; mutable tags/branches are refused." >&2
    exit 1
  }
}

run_as_user() {
  # Run a command as TARGET_USER with their HOME set.
  sudo -u "$TARGET_USER" -H "$@"
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (try: sudo bash install.sh)" >&2
    exit 1
  fi
}

ensure_target_user() {
  if [[ "$TARGET_USER" == "root" ]]; then
    echo "Refusing to install Lightwork as root; choose a non-root sudo user or set MAVERICK_SERVICE_USER." >&2
    exit 1
  fi

  if ! id -u "$TARGET_USER" >/dev/null 2>&1; then
    log "Creating dedicated Lightwork service user ${TARGET_USER} (${TARGET_HOME})..."
    useradd --system --create-home --home-dir "$TARGET_HOME" --shell /usr/sbin/nologin "$TARGET_USER"
  else
    log "Using existing Lightwork install user ${TARGET_USER} (${TARGET_HOME})..."
    if [[ "$(id -u "$TARGET_USER")" -eq 0 ]]; then
      echo "Refusing to install Lightwork under a UID 0 account." >&2
      exit 1
    fi
    if [[ ! -d "$TARGET_HOME" ]]; then
      primary_group="$(id -gn "$TARGET_USER")"
      install -d -o "$TARGET_USER" -g "$primary_group" "$TARGET_HOME"
    fi
  fi
}

install_system_deps() {
  log "Installing system packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv pipx \
    git curl ca-certificates sqlite3 sudo
  # The distro python3 can be older than the floor (3.10 on Ubuntu 22.04);
  # stop here rather than at pip's requires-python check.
  if [ "$(/usr/bin/python3 -I -c 'import sys;print("%d%02d"%sys.version_info[:2])')" -lt 311 ]; then
    echo "Lightwork needs Python 3.11 or newer, but /usr/bin/python3 is $(/usr/bin/python3 -I -c 'import sys;print("%d.%d"%sys.version_info[:2])'). Use a distribution release whose python3 is 3.11 or newer, then re-run." >&2
    exit 1
  fi
  pipx ensurepath || true
}

install_maverick() {
  log "Installing maverick @ ${MAVERICK_REF} for user ${TARGET_USER}..."
  # Build a fresh source tree and verify it before replacing the managed
  # checkout. Reusing /opt/maverick would let dirty tracked or untracked files
  # survive an otherwise-correct `git checkout <sha>` and enter the pipx build.
  install -d -m 0755 /opt
  STAGED_SOURCE="$(mktemp -d /opt/maverick.stage.XXXXXX)"
  git clone --no-checkout --filter=blob:none \
    https://github.com/Daybreak-AI-Labs/LightworkOS "$STAGED_SOURCE"
  git -C "$STAGED_SOURCE" fetch --depth 1 origin "$MAVERICK_REF"
  git -C "$STAGED_SOURCE" -c advice.detachedHead=false checkout --detach FETCH_HEAD
  actual_ref="$(git -C "$STAGED_SOURCE" rev-parse HEAD)"
  [[ "$actual_ref" == "$MAVERICK_REF" ]] || {
    echo "Checked-out source is at '$actual_ref', not required ref '$MAVERICK_REF'." >&2
    exit 1
  }
  [[ -z "$(git -C "$STAGED_SOURCE" status --porcelain --untracked-files=all)" ]] || {
    echo "Fresh Lightwork checkout is unexpectedly dirty; refusing installation." >&2
    exit 1
  }
  [[ -f "$STAGED_SOURCE/packages/maverick-core/pyproject.toml" ]] || {
    echo "Pinned checkout is not a complete Lightwork source tree." >&2
    exit 1
  }
  chmod 0755 "$STAGED_SOURCE"
  rm -rf -- /opt/maverick
  mv -- "$STAGED_SOURCE" /opt/maverick
  STAGED_SOURCE=""
  # pipx names the venv after the core distribution (`maverick-agent`). Create
  # that environment without resolving a partial graph, then let the shared
  # manifest-driven helper install all eight packages in one constrained
  # transaction and verify their imports.
  run_as_user pipx ensurepath || true
  run_as_user pipx install --force --pip-args=--no-deps \
    /opt/maverick/packages/maverick-core
  venvs="$(run_as_user pipx environment --value PIPX_LOCAL_VENVS)"
  target_python="$venvs/maverick-agent/bin/python"
  [[ -x "$target_python" ]] || {
    echo "pipx created no maverick-agent environment at $target_python" >&2
    exit 1
  }
  run_as_user python3 /opt/maverick/scripts/install_release_cohort.py \
    --source-root /opt/maverick \
    --target-python "$target_python" \
    --core-extra "$MAVERICK_CORE_EXTRAS"
}

run_wizard() {
  log "Launching the setup wizard. Pick deployment=vps when asked."
  run_as_user "${TARGET_HOME}/.local/bin/maverick" init
}

install_service() {
  log "Installing systemd unit (User=${TARGET_USER}, home=${TARGET_HOME})..."
  # The service user's interpreter is untrusted. It may probe its own
  # workspace, but its output must never become a root-installed unit.
  local venvs service_python
  venvs="$(run_as_user pipx environment --value PIPX_LOCAL_VENVS)" || return 1
  service_python="$venvs/maverick-agent/bin/python"
  [[ -x "$service_python" ]] || {
    echo "Verified application Python is missing at $service_python" >&2
    return 1
  }
  # Read and provision the selected workspace as the service account. Publish
  # only a completely rendered unit, retaining the previous unit on failure.
  local rendered_unit
  rendered_unit="$(mktemp /etc/systemd/system/.maverick.service.XXXXXX)"
  if ! run_as_user "$service_python" /opt/maverick/deploy/vps/render_service.py \
      --user "$TARGET_USER" --home "$TARGET_HOME" > /dev/null; then
    rm -f -- "$rendered_unit"
    echo "Workspace validation failed; the service was not enabled." >&2
    return 1
  fi
  # install_system_deps requires Python >= 3.11, so isolated system Python
  # has tomllib and does not load the service user's packages or startup hooks.
  if ! /usr/bin/python3 -I /opt/maverick/deploy/vps/render_service.py \
      --user "$TARGET_USER" --home "$TARGET_HOME" --no-probe > "$rendered_unit"; then
    rm -f -- "$rendered_unit"
    echo "Workspace validation failed; the service was not enabled." >&2
    return 1
  fi
  chmod 0644 "$rendered_unit"
  mv -f -- "$rendered_unit" /etc/systemd/system/maverick.service
  systemctl daemon-reload
  systemctl enable maverick.service
  log "Service installed. Start with:  systemctl start maverick"
}

main() {
  # Validate the immutable source decision before apt, user, or filesystem
  # changes. A missing pin must never degrade to a mutable release/tag/branch.
  validate_source_pin
  require_root
  ensure_target_user
  install_system_deps
  install_maverick
  run_wizard
  install_service
  log "Done. Tail logs with:  journalctl -u maverick -f"
}

main "$@"
