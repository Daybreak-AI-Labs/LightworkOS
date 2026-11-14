"""Plugin version-pinning lockfile.

The plugin allowlist says *which* plugins may load; it says nothing about
*which version* — a routine ``pip install -U`` silently swaps the code the
operator vetted for whatever shipped last night. The lockfile closes that
gap: ``maverick plugin lock`` records each active plugin distribution's
version, and discovery verifies the installed versions against the lock,
refusing (or warning, per policy) on drift.

Scope: the distributions that provide maverick entry points — the deps tree
in general belongs to :mod:`maverick.supply_chain`. Policy knob::

    [plugins]
    lock_policy = "off" | "warn" | "enforce"     # default "off"

``warn`` logs drift and loads anyway; ``enforce`` skips the drifted plugin
(fail closed for that plugin only — the rest keep loading). The lockfile
lives at ``data_dir("plugins.lock.json")``, atomic write, 0600.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path

log = logging.getLogger(__name__)

_POLICIES = ("off", "warn", "enforce")


def _hashable_dist_path(path: str) -> bool:
    parts = Path(path).parts
    return (
        bool(parts)
        and not Path(path).is_absolute()
        and ".." not in parts
        and not path.endswith(".pyc")
        and "__pycache__" not in parts
    )


def _dist_content_hash(dist_name: str, *, portable_paths: bool = False) -> str | None:
    """SHA-256 over a distribution's installed load-affecting files.

    The lockfile is meant to detect a same-version plugin whose installed bytes
    changed. Plugin loading is controlled not only by Python source files, but
    also by distribution metadata (notably entry_points.txt), native extensions,
    package data, and occasionally generated files omitted from RECORD. Hash the
    recorded file list plus recursively discovered files under the distribution's
    package and metadata roots, excluding only nondeterministic bytecode caches.
    Returns None when the file list is not introspectable or any candidate file
    cannot be read, rather than pinning a partial hash.
    """
    try:
        from importlib.metadata import files as _meta_files
        pkg_files = _meta_files(dist_name) or []
    except Exception:
        return None
    if not pkg_files:
        return None

    candidates: dict[str, Path] = {}
    roots: set[tuple[str, Path]] = set()
    for f in pkg_files:
        rel = str(f).replace("\\", "/") if portable_paths else str(f)
        if not _hashable_dist_path(rel):
            continue
        try:
            path = Path(f.locate())
        except Exception:
            return None
        candidates[rel] = path
        first = Path(rel).parts[0]
        if first.endswith((".dist-info", ".egg-info")) or "." not in first:
            # The distribution's own top-level directory, never site-packages.
            root_index = len(Path(rel).parts) - 2
            roots.add((first, path if root_index < 0 else path.parents[root_index]))

    for root_name, root_path in roots:
        try:
            if root_path.is_dir():
                for child in root_path.rglob("*"):
                    if child.is_file():
                        relative = Path(root_name, child.relative_to(root_path))
                        rel = relative.as_posix() if portable_paths else str(relative)
                        if _hashable_dist_path(rel):
                            candidates.setdefault(rel, child)
        except Exception:
            return None

    if not candidates:
        return None
    h = hashlib.sha256()
    for rel in sorted(candidates):
        try:
            data = candidates[rel].read_bytes()
        except Exception:
            return None
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(data)
        h.update(b"\0")
    return h.hexdigest()


def lock_path() -> Path:
    from .paths import data_dir
    return data_dir() / "plugins.lock.json"


def _enterprise_default_policy() -> str:
    """Lock policy when nothing is configured: ``enforce`` under enterprise mode
    (a regulated deployment refuses drifted/unpinned plugins once a lockfile
    exists -- and it's a no-op with no lockfile, so it never breaks a fresh
    install), ``off`` for single-tenant/dev."""
    try:
        from .enterprise import enterprise_enabled
        return "enforce" if enterprise_enabled() else "off"
    except Exception:  # pragma: no cover -- config never blocks discovery
        return "off"


def lock_policy() -> str:
    """``MAVERICK_PLUGIN_LOCK_POLICY`` env wins over ``[plugins] lock_policy``.
    When neither is set the default depends on the deployment profile (see
    :func:`_enterprise_default_policy`); an explicit setting always wins.

    An unrecognised explicit value, or an unreadable config, resolves to
    ``enforce`` (logged): a misspelt ``"enforced"`` must not switch the lock
    off. ``enforce`` with no lockfile still changes nothing."""
    env = os.environ.get("MAVERICK_PLUGIN_LOCK_POLICY", "").strip().lower()
    if env in _POLICIES:
        return env
    if env:
        _warn_once("policy:env", f"unknown MAVERICK_PLUGIN_LOCK_POLICY {env!r}; using enforce")
        return "enforce"
    try:
        from .config import config_source_errors, load_config
        raw = ((load_config() or {}).get("plugins") or {}).get("lock_policy")
        unreadable = bool(config_source_errors(include_tenant=True))
    except Exception:
        raw, unreadable = None, True
    if unreadable:
        _warn_once("policy:config", "plugin lock policy unreadable (config error); using enforce")
        return "enforce"
    if raw is not None:
        pol = str(raw).strip().lower()
        if pol in _POLICIES:
            return pol
        _warn_once("policy:config", f"unknown [plugins] lock_policy {pol!r}; using enforce")
        return "enforce"
    return _enterprise_default_policy()


def _active_plugin_dists() -> dict[str, str]:
    """{distribution_name: version} for every dist providing maverick entry
    points (whether or not currently allowlisted — the lock should survive
    allowlist edits)."""
    from . import plugins as plugins_mod
    dists: dict[str, str] = {}
    for group in ("maverick.tools", "maverick.channels",
                  "maverick.skills", "maverick.personas"):
        for ep in plugins_mod._entry_points(group):
            name = plugins_mod._ep_dist_name(ep)
            if not name:
                continue
            version = ""
            dist = getattr(ep, "dist", None)
            if dist is not None:
                version = str(getattr(dist, "version", "") or "")
            if not version:
                try:
                    from importlib.metadata import version as _v
                    version = _v(name)
                except Exception:
                    version = "unknown"
            dists[name] = version
    return dists


def write_lock(path: Path | None = None) -> dict[str, str]:
    """Record the active plugin distributions' versions AND content hashes.

    Returns the version pins. The content hash (where introspectable) lets
    enforce mode detect a tampered-but-same-version plugin, not just a version
    bump. Additive: a lockfile without a ``hashes`` block simply keeps
    version-only semantics."""
    pins = _active_plugin_dists()
    hashes = {n: h for n in pins if (h := _dist_content_hash(n)) is not None}
    p = Path(path) if path else lock_path()
    # Unique temp + os.replace (0600): a fixed ".tmp" collides if two CLI
    # invocations regenerate the lockfile concurrently.
    from .file_lock import atomic_write_text
    atomic_write_text(p, json.dumps(
        {"generated_at": time.time(), "pins": pins, "hashes": hashes},
        indent=2, sort_keys=True,
    ))
    return pins


def read_hashes(path: Path | None = None) -> dict[str, str]:
    """The pinned ``{dist_name: content_hash}`` map (empty for legacy locks)."""
    p = Path(path) if path else lock_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        hashes = data.get("hashes")
        return {str(k): str(v) for k, v in hashes.items()} if isinstance(hashes, dict) else {}
    except (OSError, ValueError):
        return {}


def read_lock(path: Path | None = None) -> dict[str, str] | None:
    p = Path(path) if path else lock_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        pins = data.get("pins")
        return {str(k): str(v) for k, v in pins.items()} if isinstance(pins, dict) else None
    except (OSError, ValueError):
        return None


def _lock_malformed(path: Path) -> bool:
    """True when a lockfile is present but is not ``{pins: {..}, hashes?: {..}}``."""
    if not path.exists() and not path.is_symlink():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    return not (isinstance(data, dict) and isinstance(data.get("pins"), dict)
                and isinstance(data.get("hashes", {}), dict))


def verify_lock(path: Path | None = None) -> dict:
    """Compare installed plugin dists against the lock.

    Returns ``{ok, drifted: [(name, pinned, installed)], unpinned: [...],
    missing: [...]}`` — ``ok`` iff no drift, missing pins, or unpinned dists.
    No lockfile -> ``{ok: True, unlocked: True}`` (nothing to enforce).
    """
    pins = read_lock(path)
    if pins is None:
        return {"ok": True, "unlocked": True, "drifted": [], "unpinned": [], "missing": []}
    installed = _active_plugin_dists()
    drifted = [(n, pins[n], installed[n])
               for n in sorted(set(pins) & set(installed)) if pins[n] != installed[n]]
    missing = sorted(set(pins) - set(installed))
    unpinned = sorted(set(installed) - set(pins))
    return {"ok": not drifted and not missing and not unpinned, "unlocked": False,
            "drifted": drifted, "unpinned": unpinned, "missing": missing}


def lock_report(path: Path | None = None) -> dict:
    """Per-distribution reading of :func:`verify_lock`, for a person to scan.

    ``{locked, ok, rows: [{name, pinned, installed, state}]}`` with ``state``
    one of ``match`` (pinned and installed at the pinned version),
    ``drifted`` (installed at another version), ``missing`` (pinned, not
    installed) or ``unpinned`` (installed, not in the lock). The same set
    comparison ``verify_lock`` makes, kept row by row so the matching
    plugins are listed too, not only the problems. No lockfile: every
    installed distribution is ``unpinned`` and ``locked`` is False."""
    pins = read_lock(path)
    installed = _active_plugin_dists()
    known = dict(pins or {})
    rows: list[dict] = []
    for name in sorted(set(known) | set(installed)):
        pinned, have = known.get(name), installed.get(name)
        if pinned is None:
            state = "unpinned"
        elif have is None:
            state = "missing"
        elif have != pinned:
            state = "drifted"
        else:
            state = "match"
        rows.append({"name": name, "pinned": pinned, "installed": have, "state": state})
    ok = pins is None or all(r["state"] == "match" for r in rows)
    return {"locked": pins is not None, "ok": ok, "rows": rows}


def dist_allowed_by_lock(dist_name: str | None) -> bool:
    """Per-dist gate used by plugin discovery.

    - policy off, or no lockfile: always True (today's behavior).
    - warn: True, but drift logs a warning (once per process per dist).
    - enforce: a drifted or unpinned dist is refused; pinned-and-matching
      loads. Unknown dist names load (can't be pinned). A lockfile that is
      present but unreadable or malformed refuses every dist (warn: logs).
    """
    policy = lock_policy()
    if policy == "off" or not dist_name:
        return True
    if _lock_malformed(lock_path()):
        # A present but unreadable lock is not "no lock": it may have pinned
        # this plugin, so enforce refuses rather than allowing everything.
        msg = "plugins.lock is unreadable or malformed"
        if policy == "enforce":
            _warn_once("lock:malformed", msg + "; refusing plugins (enforce)")
            return False
        _warn_once("lock:malformed", msg)
        return True
    pins = read_lock()
    if pins is None:
        return True
    installed = _active_plugin_dists().get(dist_name)
    pinned = pins.get(dist_name)
    if pinned is None:
        if policy == "enforce":
            _warn_once(dist_name, f"plugin {dist_name} is not in plugins.lock; refusing (enforce)")
            return False
        return True
    if installed is not None and installed != pinned:
        msg = (f"plugin {dist_name} version drift: locked {pinned}, "
               f"installed {installed}")
        if policy == "enforce":
            _warn_once(dist_name, msg + "; refusing (enforce)")
            return False
        _warn_once(dist_name, msg)
    # Content-integrity check: a pinned hash that no longer matches means the
    # code changed even though the version did not -- a tampered or swapped
    # build. Only checked when a hash was pinned (newer lockfiles) and the
    # current files are introspectable; otherwise we fall back to version-only.
    pinned_hash = read_hashes().get(dist_name)
    if pinned_hash:
        current_hash = _dist_content_hash(dist_name)
        if current_hash != pinned_hash:
            # None means a RECORD-listed file could not be read (removed, or
            # replaced by a sourceless .pyc): the pinned build is gone, which
            # is drift, not a free pass.
            hmsg = (f"plugin {dist_name} content drift: code changed since lock "
                    f"(same version {pinned})" if current_hash is not None else
                    f"plugin {dist_name} content hash cannot be verified against "
                    f"the lock (same version {pinned})")
            hmsg += ("; if this install is trusted, run `maverick plugin lock` "
                     "to re-record the hashes")
            if policy == "enforce":
                _warn_once(dist_name + ":hash", hmsg + "; refusing (enforce)")
                return False
            _warn_once(dist_name + ":hash", hmsg)
    return True


_warned: set[str] = set()


def _warn_once(key: str, msg: str) -> None:
    if key not in _warned:
        _warned.add(key)
        log.warning("%s", msg)


def reset_warned() -> None:
    """Tests."""
    _warned.clear()


__all__ = ["lock_path", "lock_policy", "write_lock", "read_lock", "read_hashes",
           "verify_lock", "lock_report", "dist_allowed_by_lock", "reset_warned"]
