#!/bin/sh
set -eu
# Volumes can hide image-created directories. Provision the runtime default
# after mounts are attached, as the unprivileged application user.
mkdir -p "${MAVERICK_WORKDIR:?MAVERICK_WORKDIR must name the persistent workspace}"
exec maverick "$@"
