# Lightwork — single-container image.
#
# Build:   docker build -f deploy/docker/Dockerfile -t maverick:latest .
# Run:     docker run -it --rm \
#            -v $HOME/.maverick:/home/maverick/.maverick \
#            -v $HOME/maverick-workspace:/workspace \
#            -e ANTHROPIC_API_KEY \
#            maverick:latest start "..."
#
# Runs as the unprivileged "maverick" user (uid/gid 1000), not root.
#
# First run drops you into `maverick init` so the wizard can set up the
# config inside the mounted ~/.maverick directory.

# Pin the image index to the reviewed release base, including for local builds.
# Override with --build-arg PYTHON_DIGEST=@sha256:<digest> when reviewing an
# update. Apt repositories remain mutable and must also be snapshotted before
# the complete container can be described as reproducible.
ARG PYTHON_DIGEST=@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS kubectl-builder
ARG KUBECTL_VERSION=v1.36.4
ARG TARGETARCH=amd64
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl --fail --location "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" -o /kubectl \
    && curl --fail --location "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl.sha256" -o /kubectl.sha256 \
    && cd / && awk '{print $1 "  kubectl"}' kubectl.sha256 | sha256sum --check \
    && chmod 0755 /kubectl

FROM python:3.12-slim${PYTHON_DIGEST} AS wheel-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY release-cohort.toml ./
COPY requirements/ci.txt ./requirements/ci.txt
COPY scripts/install_release_cohort.py ./scripts/install_release_cohort.py
COPY packages/maverick-core ./packages/maverick-core
COPY packages/maverick-shield ./packages/maverick-shield
COPY packages/maverick-channels ./packages/maverick-channels
COPY packages/maverick-evolve ./packages/maverick-evolve
COPY packages/maverick-dashboard ./packages/maverick-dashboard
COPY packages/maverick-mcp ./packages/maverick-mcp
COPY packages/maverick-knowledge ./packages/maverick-knowledge
COPY apps/installer-cli ./apps/installer-cli

# Build the complete manifest-driven cohort and every dependency into a private
# wheelhouse. The runtime stage has no project trees, pyprojects, or tests.
RUN python -m pip install --upgrade 'pip==26.3' \
    && python scripts/install_release_cohort.py \
        --target-python python \
        --core-extra release-runtime,postgres,oidc,s3,evidence-analysis \
        --wheel-dir /wheelhouse

FROM python:3.12-slim${PYTHON_DIGEST} AS runtime

# PYTHONNOUSERSITE: the harness interpreter must never import from the user
# site-packages. System site-packages are root-owned (installed below, before
# USER maverick), so the only writable import path a model-driven `pip
# install --user` can reach at runtime is ~/.local/lib/pythonX/site-packages —
# with user-site honored, a mid-run install there shadows any module the
# harness lazily imports later (import-path poisoning of the process that
# holds credentials and enforces the gates). The sandbox's child-shell env
# drops this var (sandbox/local.py scrub_env), so packages the agent installs
# for its OWN scripts keep working; only the harness process is closed off.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY --from=kubectl-builder /kubectl /usr/local/bin/kubectl

# System deps for sqlite + git (skills, world model).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Resolve only against the builder's wheelhouse. The requirements file names
# all eight exact cohort distributions, and --no-index prevents a sibling name
# from falling back to a public lookalike.
COPY --from=wheel-builder /wheelhouse /wheelhouse
COPY requirements/ci.txt /tmp/requirements/ci.txt
RUN python -m pip install --upgrade 'pip==26.3' \
    && python -m pip install \
        --no-index \
        --find-links=/wheelhouse \
        --constraint /tmp/requirements/ci.txt \
        --requirement /wheelhouse/cohort-requirements.txt \
    && python -m pip check \
    && python -c "import maverick, maverick_shield, maverick_channels, maverick_evolve, maverick_dashboard, maverick_mcp, maverick_knowledge, maverick_installer" \
    && maverick release-runtime-check \
    && rm -rf /wheelhouse /tmp/requirements/ci.txt

# Run as an unprivileged user. Enterprise container policies (and most
# Kubernetes Pod Security Standards) reject containers running as root.
# uid/gid 1000 is conventional and stable so volume ownership is predictable.
# The state dir (~/.maverick -> /home/maverick/.maverick) and /workspace are
# owned by this user; mount host volumes with matching ownership.
RUN groupadd --gid 1000 maverick \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin maverick \
    && mkdir -p /workspace /home/maverick/.maverick \
    && chown -R maverick:maverick /workspace /home/maverick

COPY --chmod=0755 deploy/docker/entrypoint.sh /usr/local/bin/lightwork-entrypoint
ENV HOME=/home/maverick
ENV MAVERICK_WORKDIR=/home/maverick/.maverick/workspace
USER maverick
WORKDIR /workspace

# Health is deployment-mode-specific. Dashboard deployments probe /livez in
# their Compose/Kubernetes/Helm definitions; the base CLI/worker image declares
# no HTTP health check because those valid modes do not listen on port 8765.

# Default entrypoint is the maverick CLI. First run — if config is missing —
# helpfully points the user at `maverick init`.
ENTRYPOINT ["/usr/local/bin/lightwork-entrypoint"]
CMD ["--help"]
