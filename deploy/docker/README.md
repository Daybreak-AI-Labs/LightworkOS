# Persistent workspaces

The standard image defaults `MAVERICK_WORKDIR` to
`/home/maverick/.maverick/workspace`, inside the state volume used by the
Kubernetes, Helm, ECS, Fly and Railway recipes. The entrypoint creates that
directory after mounts are attached, as the unprivileged application user.
The Compose recipe overrides the default to its separate `/workspace` mount.
The alternative Fly.io recipe uses `/state/workspace` inside its `/state` volume.

An explicit `[sandbox].workdir` in `config.toml` takes precedence over this
deployment default. Setup prompts use the deployment default for new installs.
When upgrading an existing installation, review the saved workdir: a path
outside a persistent mount remains outside it. Choose a mounted directory and
copy any needed existing files before replacing the old container. For Compose:

```toml
[sandbox]
workdir = "/workspace"
```

For the standard single-state-volume recipes, use
`/home/maverick/.maverick/workspace`. If you customize the volume destination,
set `MAVERICK_WORKDIR` and any saved workdir to a directory within that mount.
Ensure the runtime user (UID/GID 1000 by default) can create and write it.

Before promoting a deployment, create a harmless workspace file, replace the
container while preserving its volumes, and verify the file is still present.
The repository's local contract tests verify the path/default and entrypoint
behavior; they do not replace a container-volume test on the target platform.
# Base image updates

The Dockerfile pins the Python and kubectl-builder image indexes by digest so
local and release builds begin from the reviewed images. The Python digest can
be overridden with `--build-arg PYTHON_DIGEST=@sha256:<digest>` when reviewing
an update; advance the release and CI build arguments with it. Dependabot checks
the Dockerfile for base-image updates. Apt repositories remain mutable, so the
base-image pins alone do not make the complete image reproducible.
