"""Build-time gRPC stub generation + a runtime-protoc opt-out.

The gRPC loaders compile ``*_pb2.py`` from the bundled ``.proto`` files on first
use (no generated code is checked in). That's convenient for dev but wrong for a
locked-down enterprise deployment: it needs **write access to the install dir**
(read-only/immutable container filesystems fail) and it means the running code
isn't the audited build artifact (SBOM / reproducibility).

For an image/VM build, pre-generate the stubs with ``maverick gen-stubs`` and set
``MAVERICK_NO_RUNTIME_PROTOC=1`` in the runtime so a *missing* stub fails fast
with a clear message instead of silently invoking ``protoc`` at request time.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

_TRUE = {"1", "true", "yes", "on"}


def runtime_protoc_disabled() -> bool:
    """True when runtime stub generation is forbidden (immutable deploy)."""
    return os.environ.get("MAVERICK_NO_RUNTIME_PROTOC", "").strip().lower() in _TRUE


def guard_runtime_generation(proto: str) -> None:
    """Raise when a stub is missing and runtime generation is disabled."""
    if runtime_protoc_disabled():
        raise RuntimeError(
            f"gRPC stubs for {proto} are not present and runtime protoc "
            "generation is disabled (MAVERICK_NO_RUNTIME_PROTOC). Pre-generate "
            "them at build time with `maverick gen-stubs`."
        )


def generate_all() -> list[str]:
    """Compile every bundled .proto into checked-in-style stubs. Returns the
    proto names generated. Used at image/VM build time."""
    done: list[str] = []
    # maverick.proto (goal API)
    from .grpc_api import server as goal_server
    goal_server._generate_stubs()
    done.append("maverick.proto")
    # federation.proto
    from . import federation
    federation._generate_stubs()
    done.append("federation.proto")
    # plugin_host.proto (external tool plugins), if its generator is present
    try:
        from . import grpc_plugin_host
        gen = getattr(grpc_plugin_host, "_generate_stubs", None)
        if callable(gen):
            gen()
            done.append("plugin_host.proto")
    except Exception as e:  # pragma: no cover - optional surface
        log.warning("gen-stubs: plugin_host skipped: %s", e)
    return done


__all__ = ["runtime_protoc_disabled", "guard_runtime_generation", "generate_all"]
