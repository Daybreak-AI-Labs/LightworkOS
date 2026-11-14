"""Plugin compatibility matrix.

One table answering, for every installed Lightwork plugin entry point: which
distribution provides it, which plugin-API major it declares, whether the
kernel loads that major (``SUPPORTED_API_MAJORS``), whether it's in the
deprecation window, whether it's allowlisted using the runtime plugin
allowlist semantics, and whether its requested permissions are granted.
The CI mode (``--ci``) exits non-zero when any **enabled** plugin is API-incompatible — the gate a
deployment runs so an upgrade that drops an API major can't ship silently
against plugins still pinned to it.

Pure inspection: nothing is imported or executed — entry points are listed,
manifests parsed. Offline and side-effect free.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MatrixRow:
    group: str
    name: str
    dist: str
    api_version: str        # declared, or "?" when no manifest
    compatible: bool
    deprecated: bool
    enabled: bool
    permissions_ok: bool    # requested permissions all granted (or none asked)
    notes: str = ""


def _manifest_for(ep):
    """``(manifest, declared)``: a declared but unparseable manifest is
    ``(None, True)``, which the runtime gate refuses."""
    from .plugins import _manifest_details
    try:
        return _manifest_details(ep)
    except Exception:
        return None, False


def _is_enabled(name: str, dist: str, allow: set[str] | None) -> bool:
    if allow is None:
        return True
    return name in allow or f"{name}@{dist}" in allow


def build_matrix() -> list[MatrixRow]:
    """Inspect every installed maverick entry point into matrix rows."""
    from .plugins import (
        _PLUGIN_GROUPS,
        _allowed_plugin_names,
        _entry_points,
        _ep_dist_name,
        _permission_policy,
    )

    allow = _allowed_plugin_names()
    granted, _enforce = _permission_policy()

    rows: list[MatrixRow] = []
    for group in _PLUGIN_GROUPS:
        for ep in _entry_points(group):
            name = getattr(ep, "name", "?")
            dist = _ep_dist_name(ep) or "?"
            manifest, declared = _manifest_for(ep)
            if manifest is None and declared:
                rows.append(MatrixRow(
                    group=group, name=name, dist=dist, api_version="?",
                    compatible=False, deprecated=False,
                    enabled=_is_enabled(name, dist, allow),
                    permissions_ok=True,
                    notes="manifest declared but unreadable (refused at load)",
                ))
                continue
            if manifest is None:
                rows.append(MatrixRow(
                    group=group, name=name, dist=dist, api_version="?",
                    compatible=True, deprecated=False,
                    enabled=_is_enabled(name, dist, allow),
                    permissions_ok=True,
                    notes="no manifest (treated as v1-era; ships none)",
                ))
                continue
            requested = _requested(manifest)
            rows.append(MatrixRow(
                group=group, name=name, dist=dist,
                api_version=manifest.api_version,
                compatible=manifest.is_compatible(),
                deprecated=manifest.is_deprecated_api(),
                enabled=_is_enabled(name, dist, allow),
                permissions_ok=not (set(requested) - set(granted)),
                notes="; ".join(manifest.warnings[:2]),
            ))
    return rows


def _requested(manifest) -> list[str]:
    # The runtime gate's own list, including RFC ``requires`` entries.
    from .plugins import _requested_permissions
    return _requested_permissions(manifest)


def render(rows: list[MatrixRow]) -> str:
    from .plugin_manifest import MAVERICK_API_VERSION, SUPPORTED_API_MAJORS
    if not rows:
        return (f"no maverick plugins installed "
                f"(kernel API v{MAVERICK_API_VERSION}, "
                f"loads majors {SUPPORTED_API_MAJORS})")
    lines = [
        f"kernel API v{MAVERICK_API_VERSION}; loads majors {SUPPORTED_API_MAJORS}",
        f"{'GROUP':<20} {'NAME':<18} {'DIST':<20} {'API':<5} "
        f"{'COMPAT':<7} {'ENABLED':<8} PERMS",
    ]
    for r in sorted(rows, key=lambda r: (r.group, r.name)):
        compat = ("DEPRECATED" if r.deprecated
                  else "ok" if r.compatible else "REFUSED")
        lines.append(
            f"{r.group:<20} {r.name:<18} {r.dist:<20} {r.api_version:<5} "
            f"{compat:<7} {'yes' if r.enabled else 'no':<8} "
            f"{'ok' if r.permissions_ok else 'UNGRANTED'}"
            + (f"   ({r.notes})" if r.notes else "")
        )
    return "\n".join(lines)


def problems(rows: list[MatrixRow]) -> list[str]:
    """CI gate: enabled plugins that the kernel would refuse or skip."""
    out = []
    for r in rows:
        if not r.enabled:
            continue
        if not r.compatible:
            out.append(f"{r.name}@{r.dist}: api_version {r.api_version} "
                       "is not loadable by this kernel")
        if not r.permissions_ok:
            out.append(f"{r.name}@{r.dist}: requests ungranted permissions "
                       "(would be skipped under enforcement)")
    return out


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick.plugin_matrix",
                                description="Plugin compatibility matrix.")
    p.add_argument("--ci", action="store_true",
                   help="exit 1 when any enabled plugin is incompatible")
    args = p.parse_args(argv)
    rows = build_matrix()
    print(render(rows))
    # Anti-vacuity. With no plugins installed this printed one line and exited
    # 0, which reads in a CI column as "plugin compatibility verified" when
    # nothing was compared. Zero plugins IS the expected state in this repo's
    # own CI, so it must not fail -- but it must be spelled differently from a
    # real pass, because those two mean opposite things to whoever reads the
    # green check. The gate's ability to reject an incompatible plugin is
    # asserted by a committed negative control in test_plugin_matrix.py rather
    # than implied by this run.
    if not rows:
        print("plugin matrix: 0 plugins installed -- nothing was compared. "
              "This is the expected state for a plugin-free install and is NOT "
              "evidence that plugin compatibility is enforced; the enforcement "
              "itself is covered by the negative control in the test suite.")
        return 0
    if args.ci:
        probs = problems(rows)
        for prob in probs:
            print(f"PROBLEM: {prob}")
        print(f"plugin matrix: {len(rows)} plugin(s) checked, {len(probs)} problem(s)")
        return 1 if probs else 0
    return 0


__all__ = ["MatrixRow", "build_matrix", "render", "problems"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
