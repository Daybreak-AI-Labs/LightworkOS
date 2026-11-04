"""Supply-chain pinning: a pin-and-verify ledger for the dependency tree
.

An agent runtime is only as trustworthy as the packages loaded into its
process: a quietly upgraded transitive dependency (or a typosquat pulled in by
a hotfix ``pip install``) changes what the kernel *is* without any code review
seeing it. The cheap, offline guard is a pin file: snapshot the installed
distribution set at deploy time, then verify the live environment against it
on later runs and surface any drift.

Pieces:

* :func:`snapshot` — ``{name: version}`` for every installed distribution via
  ``importlib.metadata.distributions()``. Names are normalized per PEP 503
  (lowercase; runs of ``-_.`` collapse to ``-``) so ``Foo_Bar`` and
  ``foo-bar`` can never read as drift. When the same distribution is visible
  twice on ``sys.path`` the first wins, matching import resolution order.
* :func:`write_pins` — persist ``{"generated_at": iso, "pins": {...}}`` as
  JSON, by default under ``data_dir("supply_chain_pins.json")``. The write is
  atomic (tmp + ``os.replace``) and 0600: the pin file is an integrity
  reference, so a torn write or a co-tenant edit must not be representable.
* :func:`verify` — compare a live snapshot against the pins and return a
  :class:`PinReport`: ``missing`` (pinned but no longer installed),
  ``drifted`` (``(name, pinned, installed)`` version changes) and
  ``unpinned`` (installed but never pinned — a *warning*, not a failure,
  because optional extras legitimately come and go). ``ok`` iff nothing is
  missing and nothing drifted.
* :func:`render` — readable report with a PASS/FAIL verdict.
* :func:`check_or_warn` — the kernel-facing convenience: when ``[safety]
  supply_chain_pinning`` is enabled (env ``MAVERICK_SUPPLY_CHAIN_PINNING``
  wins over config) AND a pin file exists, verify and ``log.warning`` on
  FAIL. It never raises and never blocks startup — drift is evidence for an
  operator, and the fail-open kernel rule applies. Default OFF: with no
  config and no env var this whole module is inert.

Stdlib-only, no network, deterministic given the same installed set (tests
fake ``importlib.metadata.distributions``).
"""
from __future__ import annotations

import importlib.metadata
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_PINS_FILENAME = "supply_chain_pins.json"

_NORMALIZE_RE = re.compile(r"[-_.]+")


def canonical_name(name: str) -> str:
    """PEP 503 normalized project name (``Foo_Bar.baz`` -> ``foo-bar-baz``)."""
    return _NORMALIZE_RE.sub("-", name).lower()


def _default_path() -> Path:
    from .paths import data_dir
    return data_dir(DEFAULT_PINS_FILENAME)


def snapshot() -> dict[str, str]:
    """``{normalized_name: version}`` for every installed distribution.

    One broken ``.dist-info`` (missing metadata, ``None`` name) is skipped
    rather than killing the snapshot — the ledger should describe what *is*
    loadable. Duplicate names keep the first-seen version (import order).
    """
    pins: dict[str, str] = {}
    for dist in importlib.metadata.distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.version
        except Exception:  # one corrupt dist-info must not abort the sweep
            continue
        if not name or not version:
            continue
        pins.setdefault(canonical_name(str(name)), str(version))
    return pins


def write_pins(path: str | Path | None = None, *, now: datetime | None = None) -> Path:
    """Snapshot the environment and persist it as the pin file.

    Atomic (tmp file + ``os.replace``) and created 0600 so a crash can't
    leave a half-written reference and co-tenants can't read or edit it.
    ``now`` injects the timestamp for deterministic tests. Returns the path.
    """
    p = Path(path) if path is not None else _default_path()
    from .file_lock import (
        atomic_write_text,
        ensure_private_directory,
        prepare_private_directory,
    )

    if path is None:
        ensure_private_directory(p.parent)
    else:
        prepare_private_directory(p.parent)
    ts = (now or datetime.now(timezone.utc)).isoformat()
    body = json.dumps(
        {"generated_at": ts, "pins": dict(sorted(snapshot().items()))},
        indent=2,
    ) + "\n"
    atomic_write_text(p, body)
    return p


@dataclass(frozen=True)
class PinReport:
    """Outcome of :func:`verify`.

    ``ok`` iff ``missing`` and ``drifted`` are both empty; ``unpinned`` is
    advisory only (new packages appeared since the pins were written).
    """

    missing: list[str]                      # pinned but not installed
    drifted: list[tuple[str, str, str]]     # (name, pinned, installed)
    unpinned: list[str]                     # installed but not pinned
    ok: bool
    generated_at: str | None = None         # when the pin file was written


def verify(path: str | Path | None = None) -> PinReport:
    """Compare the live environment against the pin file at ``path``.

    Raises ``FileNotFoundError`` / ``ValueError`` on a missing or unreadable
    pin file when called directly — :func:`check_or_warn` is the fail-open
    wrapper that pre-checks existence and swallows errors.
    """
    p = Path(path) if path is not None else _default_path()
    data = json.loads(p.read_text(encoding="utf-8"))
    raw = data.get("pins") if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        raise ValueError(f"{p}: not a pin file (no 'pins' object)")
    # Re-normalize on read so a hand-edited pin entry still matches.
    pinned = {canonical_name(str(k)): str(v) for k, v in raw.items()}
    installed = snapshot()
    missing = sorted(n for n in pinned if n not in installed)
    drifted = sorted(
        (n, pinned[n], installed[n])
        for n in pinned
        if n in installed and installed[n] != pinned[n]
    )
    unpinned = sorted(n for n in installed if n not in pinned)
    generated_at = data.get("generated_at")
    return PinReport(
        missing=missing,
        drifted=drifted,
        unpinned=unpinned,
        ok=not missing and not drifted,
        generated_at=str(generated_at) if generated_at else None,
    )


def render(report: PinReport) -> str:
    """Readable report; drift first — it is what an operator must act on."""
    lines = [f"supply-chain pins: {'PASS' if report.ok else 'FAIL'}"]
    if report.generated_at:
        lines.append(f"  pins generated at: {report.generated_at}")
    if report.drifted:
        lines.append(f"  drifted ({len(report.drifted)}):")
        for name, pinned, installed in report.drifted:
            lines.append(f"    - {name}: pinned {pinned} -> installed {installed}")
    if report.missing:
        lines.append(f"  missing ({len(report.missing)}): {', '.join(report.missing)}")
    if report.unpinned:
        lines.append(
            f"  unpinned ({len(report.unpinned)}, warning only): "
            + ", ".join(report.unpinned)
        )
    if report.ok and not report.unpinned:
        lines.append("  every installed distribution matches its pin")
    return "\n".join(lines)


def enabled() -> bool:
    """Whether pin verification is on. Default OFF.

    ``MAVERICK_SUPPLY_CHAIN_PINNING`` (1/true/yes/on vs anything else), when
    set, wins over ``[safety] supply_chain_pinning`` in config.toml. Config
    lookup never raises (a broken config means "off").
    """
    env = os.environ.get("MAVERICK_SUPPLY_CHAIN_PINNING")
    if env is not None and env.strip():
        return env.strip().lower() in {"1", "true", "yes", "on"}
    try:
        from .config import load_config
        return bool((load_config() or {}).get("safety", {}).get(
            "supply_chain_pinning", False))
    except Exception:  # pragma: no cover -- config never blocks the kernel
        return False


def check_or_warn(path: str | Path | None = None) -> PinReport | None:
    """Verify-and-warn convenience for kernel startup paths.

    Runs only when :func:`enabled` AND the pin file exists; on FAIL it logs a
    warning with the rendered report. Returns the :class:`PinReport` when a
    verification ran, else ``None`` (feature off, no pin file, or any error —
    fail-open: pin checking must never take the kernel down).
    """
    try:
        if not enabled():
            return None
        p = Path(path) if path is not None else _default_path()
        if not p.exists():
            log.debug("supply_chain: pinning enabled but no pin file at %s "
                      "(run write_pins() to create one)", p)
            return None
        report = verify(p)
        if not report.ok:
            log.warning("supply-chain pin verification FAILED:\n%s", render(report))
        return report
    except Exception as e:
        log.warning("supply_chain: check skipped (%s: %s)", type(e).__name__, e)
        return None


def startup_check(path: str | Path | None = None) -> PinReport | None:
    """What a starting server runs: with pinning on, record the installed
    packages the first time (the deploy-time snapshot), then verify against
    that record on every later start and warn on drift. Never raises."""
    try:
        if not enabled():
            return None
        p = Path(path) if path is not None else _default_path()
        if not p.exists():
            write_pins(p)
            log.info("supply_chain: recorded the installed packages at %s", p)
            return None
    except Exception as e:
        log.warning("supply_chain: pin record skipped (%s: %s)", type(e).__name__, e)
        return None
    return check_or_warn(path)


__all__ = [
    "PinReport",
    "canonical_name",
    "snapshot",
    "write_pins",
    "verify",
    "render",
    "enabled",
    "check_or_warn",
    "DEFAULT_PINS_FILENAME",
    "startup_check",
]
