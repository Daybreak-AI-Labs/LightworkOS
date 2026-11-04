#!/usr/bin/env bash
# Multi-architecture image build for Lightwork (deploy/multiarch).
#
# Run from the REPO ROOT:
#   deploy/multiarch/build.sh                       # amd64 + arm64
#   PUSH=1 TAG=registry.example.com/maverick:0.1.7 deploy/multiarch/build.sh
#
# Cross-building needs QEMU binfmt handlers registered once per host:
#   docker run --privileged --rm tonistiigi/binfmt --install all
# (CI: run that exact command, or use docker/setup-qemu-action, before this
# script.)
#
# The reduced image supports linux/amd64 and linux/arm64. riscv64 is rejected:
# mandatory cryptography/cffi and optional dashboard native dependencies need a
# larger toolchain and verified wheel/source-build path this image does not ship.
set -euo pipefail

PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
TAG="${TAG:-maverick:multiarch}"
BASE_IMAGE="${BASE_IMAGE:-python:3.12-slim}"
INSTALL_DASHBOARD="${INSTALL_DASHBOARD:-0}"

IFS=',' read -r -a requested_platforms <<<"$PLATFORMS"
for platform in "${requested_platforms[@]}"; do
    case "$platform" in
        linux/amd64|linux/arm64) ;;
        *)
            echo "error: unsupported platform '$platform'; allowed: linux/amd64,linux/arm64" >&2
            exit 2
            ;;
    esac
done

if [ ! -f deploy/multiarch/Dockerfile.multiarch ]; then
    echo "error: run from the repo root (deploy/multiarch/build.sh)" >&2
    exit 1
fi

# A docker-container builder is required for multi-platform output.
BUILDER=maverick-multiarch
docker buildx inspect "$BUILDER" >/dev/null 2>&1 \
    || docker buildx create --name "$BUILDER" --driver docker-container

args=(
    --builder "$BUILDER"
    --platform "$PLATFORMS"
    --build-arg "BASE_IMAGE=$BASE_IMAGE"
    --build-arg "INSTALL_DASHBOARD=$INSTALL_DASHBOARD"
    -f deploy/multiarch/Dockerfile.multiarch
    -t "$TAG"
)

if [ "${PUSH:-0}" = "1" ]; then
    args+=(--push)
else
    # Multi-platform images cannot be --load'ed into the local daemon; keep
    # the result in the build cache and just validate the build.
    echo "note: PUSH=1 not set -> building without exporting (validation run)"
fi

docker buildx build "${args[@]}" .
