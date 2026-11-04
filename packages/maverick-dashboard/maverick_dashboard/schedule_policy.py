"""Shared gate for operations that create or change scheduled work."""
from __future__ import annotations

from fastapi import HTTPException


def require_scheduling() -> None:
    from maverick.config import get_features

    if not get_features().get("scheduling", True):
        raise HTTPException(
            status_code=403,
            detail=(
                "scheduling is disabled ([features] scheduling = false). "
                "Re-enable it in config, or use `maverick schedule` on the host."
            ),
        )
