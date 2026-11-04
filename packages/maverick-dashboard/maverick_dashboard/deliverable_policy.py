"""Domain release policy and presentation shape for task deliverables."""
from __future__ import annotations

from fastapi import HTTPException


def goal_gate(domain: str) -> str | None:
    """Read the persisted release gate, failing closed when it is unavailable."""
    if not domain:
        return None
    try:
        from maverick.domain import available_domains, enforced_gate

        profile = available_domains().get(domain)
    except Exception as exc:  # pragma: no cover -- factory layer unavailable
        raise HTTPException(
            status_code=503,
            detail="deliverable release policy is temporarily unavailable",
        ) from exc
    if profile is None:
        raise HTTPException(
            status_code=409,
            detail="the goal's domain policy is no longer available",
        )
    return enforced_gate(profile)


def goal_shape(domain: str) -> str:
    """Read the pack's render shape, falling back to prose for unavailable metadata."""
    if not domain:
        return "prose"
    try:
        from maverick.domain import available_domains

        profile = available_domains().get(domain)
        return profile.output.shape if profile else "prose"
    except Exception:  # pragma: no cover -- factory layer unavailable
        return "prose"
