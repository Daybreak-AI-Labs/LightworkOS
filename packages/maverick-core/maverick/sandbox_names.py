"""Canonical names for Lightwork's built-in execution backends.

This module intentionally has no backend imports. The CLI reads it while
building Click options, so keeping the registry lightweight preserves fast
``maverick --help`` startup while preventing the CLI and sandbox factory from
drifting apart.
"""

BUILTIN_SANDBOX_BACKENDS = (
    "local",
    "docker",
    "podman",
    "gvisor",
    "devcontainer",
    "kubernetes",
    "ssh",
    "firecracker",
    "modal",
)

__all__ = ["BUILTIN_SANDBOX_BACKENDS"]
