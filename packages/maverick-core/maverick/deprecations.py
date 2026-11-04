"""Deprecation registry + sunset gate.

Deprecations rot when they live in scattered comments: the warning ships, the
removal never happens, and the old path is maintained forever. This is the
single registry every deprecated path must be declared in, with the machinery
that makes the *sunset* actually happen:

* :data:`REGISTRY` — each entry: what's deprecated (a config key, env var,
  handler contract, API major), its replacement, the version it was deprecated
  in, and the version it is **removed in**.
* :func:`warn_once` — call-site helper: one ``DeprecationWarning`` per process
  per entry (never spams a long run).
* :func:`check_config` — scan a loaded config mapping for deprecated keys (the
  upgrade lint an operator runs after editing config.toml).
* :func:`past_due` — the **sunset gate**: entries whose ``remove_in`` is at or
  behind the current package version. ``python -m maverick.deprecations --ci``
  exits non-zero when a past-due deprecation still exists — CI then *forces*
  the actual removal (delete the old path AND its registry entry together).

Versions compare as dotted-numeric tuples; the current version comes from the
installed package metadata (fallback to the source default).
"""
from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Deprecation:
    name: str            # stable identifier, e.g. "plugins.api_v1"
    kind: str            # "config" | "env" | "contract" | "api" | "cli"
    target: str          # the deprecated thing, e.g. "[plugins] api_version=1"
    replacement: str     # what to use instead
    deprecated_in: str   # version the warning started
    remove_in: str       # version the old path is deleted in


# THE registry. Adding a deprecation means adding a row here and calling
# warn_once(name) at the old path's call site. Removing the old path means
# deleting BOTH (the sunset gate holds you to it).
REGISTRY: tuple[Deprecation, ...] = (
    Deprecation(
        name="plugins.api_v1",
        kind="api",
        target="plugin manifests declaring api_version = \"1\"",
        replacement="api_version = \"2\" (see docs/plugin-api-v2.md)",
        deprecated_in="0.1.6",
        remove_in="0.3.0",
    ),
    Deprecation(
        name="channels.str_handler",
        kind="contract",
        target="channel handlers returning bare str",
        replacement="return maverick_channels.Reply",
        deprecated_in="0.1.6",
        remove_in="0.3.0",
    ),
    Deprecation(
        name="intent_value.checked_at",
        kind="api",
        target="GET /api/v1/intent-value response field checked_at",
        replacement="recorded_as_of (checked_at carries the same value until removal)",
        deprecated_in="0.1.7",
        remove_in="0.3.0",
    ),
)


def _vtuple(version: str) -> tuple[int, ...]:
    parts = []
    for piece in str(version).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts or [0])


def current_version() -> str:
    # ``maverick.__version__`` already resolves installed distribution metadata
    # with the source-tree fallback. Reuse it instead of carrying a second
    # fallback literal that can drift past the deprecation sunset gate.
    from . import __version__

    return __version__


def get(name: str) -> Deprecation | None:
    for d in REGISTRY:
        if d.name == name:
            return d
    return None


_warned: set[str] = set()


def warn_once(name: str) -> None:
    """Emit one DeprecationWarning per process for the registered entry."""
    if name in _warned:
        return
    d = get(name)
    if d is None:  # an unregistered name is a programming error; warn loudly once
        log.warning("warn_once(%r): not in the deprecation registry", name)
        _warned.add(name)
        return
    _warned.add(name)
    warnings.warn(
        f"{d.target} is deprecated since {d.deprecated_in} and will be "
        f"REMOVED in {d.remove_in}; use {d.replacement}",
        DeprecationWarning,
        stacklevel=3,
    )


def reset_warned() -> None:
    _warned.clear()


def check_config(cfg: dict) -> list[str]:
    """Scan a loaded config mapping for deprecated config keys.

    Walks ``kind == "config"`` entries whose target is ``[section] key`` and
    reports the ones present. (Other kinds are warned at their call sites.)
    """
    problems: list[str] = []
    for d in REGISTRY:
        if d.kind != "config":
            continue
        target = d.target.strip()
        if not (target.startswith("[") and "]" in target):
            continue
        section, _, key = target.partition("]")
        section = section.lstrip("[").strip()
        key = key.strip().split("=")[0].strip()
        if key and isinstance(cfg.get(section), dict) and key in cfg[section]:
            problems.append(
                f"{d.target} is deprecated (since {d.deprecated_in}, removed in "
                f"{d.remove_in}); use {d.replacement}")
    return problems


def past_due(version: str | None = None) -> list[Deprecation]:
    """Entries whose removal version is at or behind ``version`` — the old
    path should already be GONE, registry entry included."""
    cur = _vtuple(version or current_version())
    return [d for d in REGISTRY if _vtuple(d.remove_in) <= cur]


def render() -> str:
    if not REGISTRY:
        return "no registered deprecations."
    cur = current_version()
    due = {d.name for d in past_due(cur)}
    lines = [f"deprecations (current version {cur}):"]
    for d in REGISTRY:
        flag = "  PAST DUE — remove now" if d.name in due else ""
        lines.append(
            f"  [{d.kind}] {d.target}\n"
            f"      -> {d.replacement}\n"
            f"      deprecated {d.deprecated_in}, removed in {d.remove_in}{flag}")
    return "\n".join(lines)


#: Verified-legal-content freshness gate. Modules that encode statutory
#: deadlines carry a VERIFIED_AT date stamped when the rules were checked
#: against primary sources; past this age the CI gate fails until someone
#: re-verifies — turning "we check the law by habit" into a ratchet.
VERIFIED_CONTENT_MAX_AGE_DAYS = 270
_VERIFIED_CONTENT_MODULES = ("maverick.breach_notification",)


def stale_verified_content(
    *, now: float | None = None,
) -> list[tuple[str, str, int]]:
    """(module, verified_at, age_days) for stale legal-content matrices."""

    import datetime
    import importlib
    import time as time_module

    stamp = time_module.time() if now is None else float(now)
    out: list[tuple[str, str, int]] = []
    for name in _VERIFIED_CONTENT_MODULES:
        module = importlib.import_module(name)
        verified = str(getattr(module, "VERIFIED_AT", "")).strip()
        parsed = datetime.datetime.strptime(verified, "%Y-%m-%d").replace(
            tzinfo=datetime.timezone.utc)
        age_days = int((stamp - parsed.timestamp()) // 86_400)
        if age_days > VERIFIED_CONTENT_MAX_AGE_DAYS:
            out.append((name, verified, age_days))
    return out


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick.deprecations",
                                description="Deprecation registry + sunset gate.")
    p.add_argument("--ci", action="store_true",
                   help="exit 1 when a past-due deprecation still exists")
    args = p.parse_args(argv)
    print(render())
    if args.ci:
        due = past_due()
        for d in due:
            print(f"PAST DUE: {d.name} was to be removed in {d.remove_in} — "
                  "delete the old path and its registry entry")
        stale = stale_verified_content()
        for name, verified, age in stale:
            print(f"STALE LEGAL CONTENT: {name} was verified {verified} "
                  f"({age} days ago; cap {VERIFIED_CONTENT_MAX_AGE_DAYS}) — "
                  "re-verify the matrix against primary sources and bump "
                  "VERIFIED_AT")
        return 1 if (due or stale) else 0
    return 0


__all__ = ["Deprecation", "REGISTRY", "VERIFIED_CONTENT_MAX_AGE_DAYS",
           "get", "warn_once", "reset_warned", "check_config", "past_due",
           "current_version", "render", "stale_verified_content"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
