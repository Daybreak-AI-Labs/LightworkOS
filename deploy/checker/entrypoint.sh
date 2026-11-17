#!/bin/sh
# Lightwork checker image: start a throwaway PostgreSQL 16, then run the
# command. The database lives in /tmp and goes away with the container.
# Exit code 97 means this setup failed, so the command never ran.
set -eu

fail() {
    echo "lightwork-checker: $*" >&2
    exit 97
}

# A container user without a home folder still needs one that it can write.
if [ -z "${HOME:-}" ] || [ ! -w "${HOME:-/}" ]; then
    HOME=/tmp/lw-home
    export HOME
    mkdir -p "$HOME"
fi

if [ "$(id -u)" = 0 ]; then
    fail "PostgreSQL does not run as root. Run Lightwork as an ordinary user."
fi
run=/tmp/lw-pg
rm -rf "$run"
mkdir -p "$run"
cp -R /opt/lw-pg-template "$run/data"
chmod 700 "$run/data"
if ! /usr/lib/postgresql/16/bin/pg_ctl -D "$run/data" -l "$run/log" -w -t 60 \
        -o "-k $run -h 127.0.0.1 -p ${PGPORT:-5432}" start >/dev/null; then
    cat "$run/log" >&2 || true
    fail "PostgreSQL did not start."
fi

exec "$@"
