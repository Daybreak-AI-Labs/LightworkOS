#!/usr/bin/env bash
# One-command Lightwork browser demo (Option 1 in README.md: local).
#
# Generates a dashboard token if none is set, boots the dashboard container,
# waits for it to answer, and prints the URL, the token, and how to
# authenticate with it (the dashboard only accepts the Authorization: Bearer
# header -- there is no ?token=... link to open a browser to directly).
set -euo pipefail

cd "$(dirname "$0")"

COMPOSE_FILE="docker-compose.yml"
ENV_FILE="demo.env"
PORT="${MAVERICK_DEMO_PORT:-8765}"
TOKEN_FILE=".demo-token"

if [ ! -f "$ENV_FILE" ]; then
  echo "No $ENV_FILE found. Create it and add your key:" >&2
  echo "  cp demo.env.example demo.env && \${EDITOR:-nano} demo.env" >&2
  exit 1
fi

# Read MAVERICK_DEMO_PORT from the env file too, so the URL matches the publish.
# But a shell-exported MAVERICK_DEMO_PORT wins (docker compose interpolates the
# shell value into the port publish), so only fall back to demo.env when the
# shell didn't set it -- otherwise the printed/opened URL would disagree with
# the actually-published port.
if [ -z "${MAVERICK_DEMO_PORT:-}" ]; then
  PORT="$(grep -E '^MAVERICK_DEMO_PORT=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2 || true)"
  PORT="${PORT:-8765}"
fi

# A stable token per machine, so the demo URL keeps working across restarts.
# Stored beside this script and never committed (see .gitignore).
if [ -n "${MAVERICK_DASHBOARD_TOKEN:-}" ]; then
  TOKEN="$MAVERICK_DASHBOARD_TOKEN"
elif [ -f "$TOKEN_FILE" ]; then
  TOKEN="$(cat "$TOKEN_FILE")"
else
  TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))' 2>/dev/null \
           || openssl rand -hex 24)"
  # Create 0600 (umask 077 in a subshell) so the dashboard bearer isn't
  # world/group-readable on a multi-user host.
  ( umask 077; printf '%s' "$TOKEN" > "$TOKEN_FILE" )
fi
export MAVERICK_DASHBOARD_TOKEN="$TOKEN"

echo "Building and starting the Lightwork demo dashboard..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build

# The dashboard accepts only Authorization: Bearer, never ?token= in the URL,
# which would leak the bearer through browser history, logs and the Referer
# header. A plain browser navigation cannot set that
# header, so there is no clickable link; open a REST client instead.
URL="http://localhost:${PORT}/"
printf 'Waiting for the dashboard to come up'
ready=false
deadline=$((SECONDS + 60))
for _ in $(seq 1 60); do
  remaining=$((deadline - SECONDS))
  if ((remaining <= 0)); then break; fi
  request_timeout=$((remaining < 3 ? remaining : 3))
  if curl -fsS --connect-timeout 1 --max-time "$request_timeout" "http://localhost:${PORT}/livez" >/dev/null 2>&1; then
    ready=true
    break
  fi
  printf '.'
  sleep 1
done
echo
if [ "$ready" != true ]; then
  echo "Lightwork demo did not become ready within 60 seconds. Inspect docker compose logs before retrying." >&2
  exit 1
fi

echo
echo "Lightwork demo is live:  $URL"
echo "Dashboard token:         $TOKEN"
echo
echo "The dashboard requires the Authorization: Bearer header -- there is no"
echo "?token=... link, because a URL token leaks through logs and the Referer"
echo "header. Reach it with:"
echo "  curl -H \"Authorization: Bearer $TOKEN\" $URL"
echo "or open $URL in a browser with a header-injecting extension (e.g."
echo "ModHeader) configured to send that Authorization header, or put a"
echo "reverse proxy in front that injects it for a click-through demo link"
echo "(see Option 2 in deploy/demo/README.md)."
echo
echo "Stop it with:   docker compose -f deploy/demo/$COMPOSE_FILE down"
echo "Reset state:    docker compose -f deploy/demo/$COMPOSE_FILE down -v"
