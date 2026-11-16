# syntax=docker/dockerfile:1.7
# Lightwork checker image: Python 3.11 and 3.12, git, PostgreSQL 16 with a
# throwaway database started by the entrypoint, and Chromium with
# Playwright. Set it as [codebase] checker_image; see README.md here.
# Every base image and package is pinned. Nothing secret is stored: the
# database trusts local connections only and is gone when the container ends.

# python:3.12.16-slim-bookworm (Debian 12), pinned by digest.
ARG PYTHON_IMAGE=docker.io/library/python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
FROM ${PYTHON_IMAGE}

ARG PG_VERSION=16.16-1.pgdg12+1
# The PostgreSQL apt signing key (ACCC4CF8), checked by fingerprint.
ARG PGDG_KEY_FINGERPRINT=B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

# Building behind a proxy that inspects TLS: pass its certificate with
# --secret id=extra_ca,src=<file>. It is used while building, never stored.
RUN --mount=type=secret,id=extra_ca,required=false \
    set -eu; \
    if [ -s /run/secrets/extra_ca ]; then \
        install -m 644 /run/secrets/extra_ca /tmp/build-ca.crt; \
        printf 'Acquire::https::CaInfo "/tmp/build-ca.crt";\n' > /etc/apt/apt.conf.d/99-build-ca; \
    fi; \
    sed -i 's#http://deb.debian.org#https://deb.debian.org#g' /etc/apt/sources.list.d/debian.sources; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates=20250419~deb12u2 \
        curl=7.88.1-10+deb12u15 \
        git=1:2.39.5-0+deb12u3 \
        gnupg=2.2.40-1.1+deb12u2 \
        python3.11=3.11.2-6+deb12u9 \
        python3.11-venv=3.11.2-6+deb12u9 \
        libatomic1=12.2.0-14+deb12u1 \
        fonts-liberation=1:1.07.4-11 \
        libasound2=1.2.8-1+b1 \
        libatk-bridge2.0-0=2.46.0-5 \
        libatk1.0-0=2.46.0-5 \
        libatspi2.0-0=2.46.0-5 \
        libcairo2=1.16.0-7 \
        libcups2=2.4.2-3+deb12u9 \
        libdbus-1-3=1.14.10-1~deb12u1 \
        libdrm2=2.4.114-1+b1 \
        libgbm1=22.3.6-1+deb12u2 \
        libnspr4=2:4.35-1 \
        libnss3=2:3.87.1-1+deb12u4 \
        libpango-1.0-0=1.50.12+ds-1 \
        libx11-6=2:1.8.4-2+deb12u2 \
        libxcb1=1.15-1 \
        libxcomposite1=1:0.4.5-1 \
        libxdamage1=1:1.1.6-1 \
        libxext6=2:1.3.4-1+b1 \
        libxfixes3=1:6.0.0-2 \
        libxkbcommon0=1.5.0-1 \
        libxrandr2=2:1.5.2-2+b1; \
    cacert=""; \
    if [ -s /run/secrets/extra_ca ]; then cacert="--cacert /run/secrets/extra_ca"; fi; \
    curl -fsSL $cacert -o /tmp/pgdg.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc; \
    gpg --batch --show-keys --with-colons /tmp/pgdg.asc | grep -q "^fpr:::::::::${PGDG_KEY_FINGERPRINT}:"; \
    gpg --batch --dearmor -o /usr/share/keyrings/pgdg.gpg /tmp/pgdg.asc; \
    rm -f /tmp/pgdg.asc; \
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list; \
    mkdir -p /etc/postgresql-common; \
    echo "create_main_cluster = false" > /etc/postgresql-common/createcluster.conf; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        postgresql-16=${PG_VERSION} postgresql-client-16=${PG_VERSION}; \
    apt-get purge -y gnupg; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99-build-ca /tmp/build-ca.crt

# Python packages in both interpreters, and Chromium's headless shell.
COPY requirements.txt /opt/lw-checker/requirements.txt
RUN --mount=type=secret,id=extra_ca,required=false \
    set -eu; \
    if [ -s /run/secrets/extra_ca ]; then \
        export PIP_CERT=/run/secrets/extra_ca NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; \
    fi; \
    pip install -r /opt/lw-checker/requirements.txt; \
    python3.11 -m venv /opt/py311; \
    /opt/py311/bin/pip install -r /opt/lw-checker/requirements.txt; \
    printf '#!/bin/sh\nexec /opt/py311/bin/python3.11 "$@"\n' > /usr/local/bin/python3.11; \
    chmod 755 /usr/local/bin/python3.11; \
    python -m playwright install --only-shell chromium; \
    chmod -R a+rX /opt/ms-playwright

# A ready database template; the entrypoint copies it to /tmp and starts it.
RUN set -eu; \
    bin=/usr/lib/postgresql/16/bin; \
    install -d -o postgres -g postgres /opt/lw-pg-template; \
    su postgres -s /bin/sh -c "$bin/initdb -D /opt/lw-pg-template -U postgres \
        --auth=trust -E UTF8 --locale=C.UTF-8 --no-sync >/dev/null"; \
    printf "fsync = off\nsynchronous_commit = off\nfull_page_writes = off\n" \
        >> /opt/lw-pg-template/postgresql.conf; \
    su postgres -s /bin/sh -c "$bin/pg_ctl -D /opt/lw-pg-template -w \
        -o \"-k /tmp -h ''\" start >/dev/null && $bin/createdb -h /tmp lightwork_test \
        && $bin/pg_ctl -D /opt/lw-pg-template -w stop >/dev/null"; \
    chmod -R a+rX /opt/lw-pg-template

COPY entrypoint.sh /usr/local/bin/lw-checker-entrypoint

# Where a repository's tests find the database. MAVERICK_PG_DSN and
# MAVERICK_CONSENT_PG_DSN are the names Lightwork's own Postgres tests read.
ENV PGHOST=127.0.0.1 \
    PGPORT=5432 \
    PGUSER=postgres \
    PGDATABASE=lightwork_test \
    DATABASE_URL=postgresql://postgres@127.0.0.1:5432/lightwork_test \
    MAVERICK_PG_DSN=postgresql://postgres@127.0.0.1:5432/lightwork_test \
    MAVERICK_CONSENT_PG_DSN=postgresql://postgres@127.0.0.1:5432/lightwork_test

USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/lw-checker-entrypoint"]
CMD ["sh"]
