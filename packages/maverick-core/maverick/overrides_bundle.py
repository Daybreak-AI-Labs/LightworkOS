"""Portable bundle of a workspace's per-client agent customizations.

A client tailors their workforce in the dashboard: domain-pack overrides
(:mod:`maverick.domain_edit`, written under the workspace ``domains/`` dir) and
per-role system-prompt addendums (:mod:`maverick.role_edit`, in ``roles.toml``).
This module packs those two halves into a plain directory and applies one back,
so the customizations are portable -- version-control them in a repo and load
them in CI, where the ``agent-on-pr`` reusable workflow applies the bundle so a
PR review runs as the client's *customized* workforce.

Bundle layout::

    <bundle>/domains/<name>.toml   # tenant domain-pack overrides
    <bundle>/roles.toml            # per-role system-prompt addendums

Both halves are optional. :func:`load_overrides` validates each item
(``lint_profile`` for packs, ``validate_role`` for roles) and skips anything
invalid -- a bad file in the bundle never aborts the load, and never lands an
override that would weaken the safety envelope.
"""
from __future__ import annotations

import shutil
from pathlib import Path

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from .agent_tests_policy import NEW_SPECIALIST_NEEDS_TESTS, require_for_new_specialists
from .domain import available_domains, lint_profile, load_domain, user_dir
from .role_edit import roles_file, validate_role, write_role_override


def _role_count(path: Path) -> int:
    try:
        with open(path, "rb") as f:
            return len(tomllib.load(f))
    except Exception:
        return 0


def export_overrides(dest: str | Path) -> dict:
    """Copy the active workspace's overrides into ``dest`` as a bundle.

    Returns ``{"domains": n, "roles": m}`` (items written). Existing bundle
    files are overwritten; nothing in the workspace is modified."""
    dest = Path(dest)
    out = {"domains": 0, "roles": 0}
    src_domains = user_dir()
    if src_domains.is_dir():
        packs = sorted(src_domains.glob("*.toml"))
        if packs:
            ddir = dest / "domains"
            ddir.mkdir(parents=True, exist_ok=True)
            for p in packs:
                shutil.copy2(p, ddir / p.name)
                out["domains"] += 1
    rf = roles_file()
    if rf.is_file():
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(rf, dest / "roles.toml")
        out["roles"] = _role_count(rf)
    return out


def load_overrides(src: str | Path) -> dict:
    """Apply a bundle into the active workspace, validating each item.

    Returns ``{"domains": n, "roles": m, "skipped": [...]}``. A pack that fails
    ``lint_profile`` or a role that fails ``validate_role`` is skipped (named in
    ``skipped``), never written."""
    src = Path(src)
    out: dict = {"domains": 0, "roles": 0, "skipped": []}

    bsrc = src / "domains"
    if bsrc.is_dir():
        dst = user_dir()
        dst.mkdir(parents=True, exist_ok=True)
        for p in sorted(bsrc.glob("*.toml")):
            try:
                profile = load_domain(p)
                if profile.name != p.stem:
                    raise ValueError("agent name does not match its file")
                errs, _ = lint_profile(profile)
            except Exception as e:  # malformed TOML, etc.
                out["skipped"].append(f"domains/{p.name}: {e}")
                continue
            if errs:
                out["skipped"].append(f"domains/{p.name}: {errs[0]}")
                continue
            # A specialist not published yet waits for its saved checks; one already published loads as before.
            if require_for_new_specialists() and profile.name not in available_domains():
                out["skipped"].append(f"domains/{p.name}: {NEW_SPECIALIST_NEEDS_TESTS}")
                continue
            shutil.copy2(p, dst / p.name)
            out["domains"] += 1

    rf = src / "roles.toml"
    if rf.is_file():
        try:
            with open(rf, "rb") as f:
                tables = tomllib.load(f)
        except Exception as e:
            out["skipped"].append(f"roles.toml: {e}")
            tables = {}
        for role, tbl in tables.items():
            patch = {k: str((tbl or {}).get(k) or "")
                     for k in ("system_addendum", "model", "effort")}
            errs = validate_role(role, patch)
            if errs:
                out["skipped"].append(f"roles.toml[{role}]: {errs[0]}")
                continue
            try:
                write_role_override(role, patch)
                out["roles"] += 1
            except ValueError as e:  # defensive; validate_role already gated
                out["skipped"].append(f"roles.toml[{role}]: {e}")
    return out


__all__ = ["export_overrides", "load_overrides"]
