"""Data residency / region pinning.

Declares the deployment's data region and the set of regions data is permitted
to live in, and -- in **strict** mode -- refuses to boot when the declared
region is missing or outside the allowed set. Without this a region pin is only
ever an agent-reasoning hint (the ``data_residency`` tool); strict mode makes it
a startup gate, so a misconfigured pin fails loudly instead of silently storing
data in the wrong jurisdiction.

Resolution (env wins over config in every case):
  - region: ``MAVERICK_DATA_REGION`` / ``[residency] region`` (e.g. ``DE``, ``EU``).
  - allowed set: ``MAVERICK_RESIDENCY_ALLOWED`` (comma-separated) / ``[residency]
    allowed_regions`` (TOML list or comma string). Group names (``EU``/``EEA``)
    expand to their members on both sides, reusing the ``data_residency`` tool's
    group table so the two never drift.
  - strict: ``MAVERICK_RESIDENCY_STRICT`` / ``[residency] strict``; default off.
    When the environment does not set it and config.toml cannot be read, strict
    is assumed and the check reports the policy as unknown; start-up is refused
    only when the unreadable file mentions residency, so a broken file cannot
    switch the gate off and a typo elsewhere does not stop an install.

Off by default and a silent no-op until an operator opts in, so the single-tenant
default and existing deployments are unchanged (kernel rule 1).

Honest scope: this pins and validates the *declared* region against policy. It
cannot inspect the physical location of every byte (no app-layer code can); it
guarantees the deployment's declared region is coherent with the allowed set and
that a strict deployment cannot boot misconfigured.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from .tools.data_residency import _GROUPS, _expand


log = logging.getLogger(__name__)


class ResidencyError(RuntimeError):
    """Raised at boot when strict residency is on but the region is missing or
    outside the allowed set."""


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _cfg(key: str):
    try:
        from .config import load_config
        return (load_config() or {}).get("residency", {}).get(key)
    except Exception:  # pragma: no cover -- config never blocks a residency read
        return None


def _unreadable_sources() -> dict[str, str] | None:
    """Active config sources that could not be read (path -> error), or None
    when that cannot be determined. ``load_config`` returns defaults for them,
    so a ``[residency]`` policy in one may have been lost."""
    try:
        from .config import config_source_errors
        return config_source_errors(include_tenant=True)
    except Exception:
        return None


def _config_unreadable() -> bool:
    return _unreadable_sources() != {}


def _mentions_residency(path: str) -> bool:
    """Whether an unreadable source's raw bytes mention residency (a
    ``[residency]`` table or a ``residency`` key). Not parsed: it cannot be.
    A file that cannot be read at all counts as evidence."""
    try:
        return b"residency" in Path(path).read_bytes().lower()
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _env_set(name: str) -> bool:
    raw = os.environ.get(name)
    return raw is not None and raw.strip() != ""


def residency_strict() -> bool:
    """Whether strict residency is on. When it is not set in the environment
    and the configuration cannot be read, strict is assumed: the policy may be
    in the unreadable file, and a boot gate must not read lost policy as off."""
    env = os.environ.get("MAVERICK_RESIDENCY_STRICT")
    if env is not None and env.strip() != "":
        return _truthy(env)
    if _config_unreadable():
        return True
    return _truthy(_cfg("strict"))


def declared_region() -> str | None:
    raw = os.environ.get("MAVERICK_DATA_REGION")
    if raw is None or raw.strip() == "":
        raw = _cfg("region")
    code = str(raw).strip().upper() if raw else ""
    return code or None


def allowed_regions() -> set[str]:
    """The permitted storage regions, group names expanded to members. Empty set
    means "no allowlist configured" (region declared but unconstrained)."""
    raw = os.environ.get("MAVERICK_RESIDENCY_ALLOWED")
    if raw is None or raw.strip() == "":
        raw = _cfg("allowed_regions")
    if raw is None:
        return set()
    items = raw.split(",") if isinstance(raw, str) else list(raw)
    return set(_expand(items))


def _region_permitted(code: str, allowed: set[str]) -> bool:
    """Whether a declared storage region is admitted by ``allowed`` (already a
    member-expanded set of codes).

    A **point** region (``DE``) is permitted iff it is in the allowed set -- so
    ``region = "DE"`` satisfies ``allowed_regions = ["EU"]`` (DE is one of the
    expanded EU members). A **group** region (``EU``/``EEA``) is permitted iff
    **every** member is allowed (subset), NOT on any-overlap: declaring the whole
    ``EEA`` as your storage region must FAIL an ``EU``-only policy, because EEA
    additionally spans Iceland/Liechtenstein/Norway. Any-overlap here was a
    residency bypass."""
    if code in _GROUPS:
        return _GROUPS[code] <= allowed
    return code in allowed


def check_residency() -> tuple[bool, str]:
    """``(ok, detail)`` for the current residency configuration.

    Always ``ok`` when strict mode is off (informational). When strict: fails if
    the configuration cannot be read (unless the region and the allowlist both
    come from the environment), if no region is declared, or if a configured
    allowlist does not admit the declared region; passes otherwise.
    """
    if not residency_strict():
        region = declared_region()
        return True, (
            f"residency enforcement off (declared region {region})" if region
            else "residency enforcement off"
        )
    if not (_env_set("MAVERICK_DATA_REGION") and _env_set("MAVERICK_RESIDENCY_ALLOWED")) \
            and _config_unreadable():
        return False, (
            "residency policy unknown: the configuration could not be read "
            "(fix config.toml, or set MAVERICK_RESIDENCY_STRICT, "
            "MAVERICK_DATA_REGION and MAVERICK_RESIDENCY_ALLOWED)"
        )
    region = declared_region()
    if not region:
        return False, (
            "strict residency on but no region declared "
            "(set MAVERICK_DATA_REGION or [residency] region)"
        )
    allowed = allowed_regions()
    if allowed and not _region_permitted(region, allowed):
        return False, (
            f"declared region {region} is not fully within the allowed set "
            f"{sorted(allowed)} ([residency] allowed_regions)"
        )
    scope = f"within allowed {sorted(allowed)}" if allowed else "(no allowlist)"
    return True, f"strict residency: region {region} {scope}"


def require_residency_or_die() -> None:
    """Blocking residency preflight. NO-OP unless strict mode is on.

    When strict and the configuration is incoherent (no region, or a region
    outside the allowlist), raises :class:`ResidencyError` so the deployment
    aborts at startup instead of storing data in the wrong place. Mirrors
    :func:`maverick.deployment.require_enterprise_or_die`.

    When a config source cannot be read and the environment does not set
    strict mode, start-up is refused only if an unreadable source mentions
    residency; otherwise the unreadable files are logged and start-up goes on,
    so a typo in an install that never enabled residency does not block it.
    """
    env_set = _env_set("MAVERICK_RESIDENCY_STRICT")
    unreadable = _unreadable_sources()
    if not env_set and unreadable:
        if not any(_mentions_residency(path) for path in unreadable):
            log.error("residency: configuration could not be read (%s); it does "
                      "not mention residency, so strict residency stays off",
                      ", ".join(sorted(unreadable)))
            return
    if not residency_strict():
        return
    ok, detail = check_residency()
    if not ok:
        raise ResidencyError(detail)


__all__ = [
    "ResidencyError",
    "residency_strict",
    "declared_region",
    "allowed_regions",
    "check_residency",
    "require_residency_or_die",
]
