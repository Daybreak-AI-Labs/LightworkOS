"""Resolve the deployment-wide halt authority without importing an API router."""
from __future__ import annotations


def shared_halt_backend() -> bool:
    """Return whether the shared store is authoritative, failing closed on errors."""
    from maverick.config import config_source_errors, load_config
    from maverick.world_model_backends import is_postgres_configured

    load_config()
    if config_source_errors():
        raise RuntimeError("halt backend configuration is unavailable")
    return bool(is_postgres_configured())
