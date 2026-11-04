"""Per-client customization of the core agent ROLES.

Each of the kernel's roles (orchestrator, researcher, coder, writer, analyst,
revisor, summarizer, verifier, ...) can be tailored per tenant along three axes,
all stored in one TOML file in the tenant workspace -- ``roles.toml``, a table
per role::

    [orchestrator]
    system_addendum = "For ACME, always open with the risk summary first."
    model = "anthropic:claude-opus-4-8"
    effort = "high"

Every field is optional:

  * ``system_addendum`` is appended to the role's base system template at spawn
    (:func:`role_addendum`, read by ``maverick.agent``).
  * ``model`` / ``effort`` override what the kernel would otherwise resolve from
    the global ``[models]`` / ``[effort]`` config -- :func:`maverick.config.
    get_role_model` and :func:`maverick.effort.effort_for_role` consult these
    per-tenant overrides first (:func:`override_model` / :func:`override_effort`).

A role with no override behaves exactly as before.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from .llm import ROLE_MODELS

# The roles a client may customize -- the kernel's known roles. Anything else
# (e.g. a domain-pack specialist whose role is its pack name) simply has no
# override and is unaffected.
ROLES: tuple[str, ...] = tuple(ROLE_MODELS.keys())

# An addendum rides on every spawn of that role, so keep it bounded; a model
# spec is short.
_MAX_ADDENDUM = 4000
_MAX_MODEL = 200
# Fields we persist per role, in stable order.
_FIELDS = ("system_addendum", "model", "effort")


def roles_file() -> Path:
    """The active tenant's role-override file. ``MAVERICK_ROLES_FILE`` wins
    (tests / custom layouts); otherwise ``<workspace>/roles.toml``."""
    override = os.environ.get("MAVERICK_ROLES_FILE")
    if override:
        return Path(override).expanduser()
    from .workspace import Workspace
    return Workspace.current().root / "roles.toml"


def _load(path: str | Path | None = None) -> dict:
    p = Path(path) if path else roles_file()
    if not p.is_file():
        return {}
    try:
        with open(p, "rb") as f:
            return tomllib.load(f)
    except Exception:  # a malformed file must never break a spawn
        return {}


def _table(role: str, path: str | Path | None = None) -> dict:
    return _load(path).get(role) or {}


def role_addendum(role: str) -> str:
    """The client's system-prompt addendum for ``role`` (``""`` if none).

    Read by ``maverick.agent`` at spawn and appended to the role's base system
    template -- the hook that makes a saved addendum actually shape behavior."""
    return str(_table(role).get("system_addendum") or "")


def override_model(role: str) -> str | None:
    """The client's per-role model override (``None`` if unset). Consulted by
    ``maverick.config.get_role_model`` ahead of the global ``[models]`` config."""
    return str(_table(role).get("model") or "") or None


def override_effort(role: str) -> str | None:
    """The client's per-role effort override (``None`` if unset). Consulted by
    ``maverick.effort.effort_for_role`` ahead of the global ``[effort]`` config."""
    return str(_table(role).get("effort") or "") or None


def validate_role(role: str, patch: dict) -> list[str]:
    """Errors that block a save: an unknown role, an over-long addendum or model
    spec, or an effort level the runtime doesn't know."""
    errors: list[str] = []
    if role not in ROLES:
        errors.append(f"unknown role {role!r} (expected one of {sorted(ROLES)})")
    addendum = str(patch.get("system_addendum") or "")
    if len(addendum) > _MAX_ADDENDUM:
        errors.append(f"system_addendum too long ({len(addendum)} > {_MAX_ADDENDUM} chars)")
    model = str(patch.get("model") or "")
    if len(model) > _MAX_MODEL:
        errors.append(f"model spec too long ({len(model)} > {_MAX_MODEL} chars)")
    effort = str(patch.get("effort") or "").strip()
    if effort:
        from .effort import _LEVELS
        if effort.lower() not in _LEVELS:
            errors.append(f"effort {effort!r} is not one of {list(_LEVELS)}")
    return errors


def _dump(tables: dict) -> str:
    """Serialize the whole roles file. A role table with no fields is dropped so
    the file only ever records real customizations."""
    lines: list[str] = []
    for role in sorted(tables):
        entry = tables[role] or {}
        kv = [(k, str(entry.get(k) or "").strip()) for k in _FIELDS]
        kv = [(k, v) for k, v in kv if v]
        if not kv:
            continue
        lines.append(f"[{role}]")
        for k, v in kv:
            lines.append(f"{k} = {json.dumps(v)}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n" if lines else ""


def write_role_override(role: str, patch: dict, path: str | Path | None = None) -> str:
    """Validate then persist a role's override (addendum / model / effort). The
    entry is replaced by the patch's non-empty fields; an all-empty patch clears
    the override. Raises ``ValueError`` on a validation error. Returns the path."""
    errors = validate_role(role, patch)
    if errors:
        raise ValueError("; ".join(errors))
    p = Path(path) if path else roles_file()
    tables = _load(p)
    entry = {k: str(patch.get(k) or "").strip() for k in _FIELDS}
    entry = {k: v for k, v in entry.items() if v}
    if entry:
        tables[role] = entry
    else:
        tables.pop(role, None)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_dump(tables), encoding="utf-8")
    return str(p)


def remove_role_override(role: str, path: str | Path | None = None) -> bool:
    """Drop a role's override, reverting it to the built-in defaults. Returns
    whether anything was removed."""
    p = Path(path) if path else roles_file()
    tables = _load(p)
    if role not in tables:
        return False
    tables.pop(role, None)
    p.write_text(_dump(tables), encoding="utf-8")
    return True


def _effective_model_effort(role: str) -> tuple[str | None, str | None]:
    """The model + reasoning effort the role actually resolves to -- through the
    kernel resolvers, so any per-tenant override is already reflected. Defensive:
    never raises into the view."""
    model = None
    try:
        from .config import get_role_model
        model = get_role_model(role) or ROLE_MODELS.get(role)
    except Exception:
        model = ROLE_MODELS.get(role)
    effort = None
    try:
        from .effort import effort_for_role
        effort = effort_for_role(role, model or "")
    except Exception:
        effort = None
    return model, effort


def resolved_role(role: str, path: str | Path | None = None) -> dict | None:
    """The merged view the editor renders: the role's *effective* model/effort
    (``model``/``effort``), the *editable* per-tenant overrides
    (``model_override``/``effort_override``/``system_addendum``), and provenance.
    ``None`` for an unknown role."""
    if role not in ROLES:
        return None
    table = _table(role, path)
    addendum = str(table.get("system_addendum") or "")
    model_ov = str(table.get("model") or "")
    effort_ov = str(table.get("effort") or "")
    eff_model, eff_effort = _effective_model_effort(role)
    return {
        "role": role,
        "model": eff_model,            # effective (resolved) -- display
        "effort": eff_effort,          # effective (resolved) -- display
        "system_addendum": addendum,
        "model_override": model_ov,    # editable; "" = inherit the config default
        "effort_override": effort_ov,  # editable; "" = inherit
        "is_override": bool(addendum or model_ov or effort_ov),
        "errors": validate_role(
            role, {"system_addendum": addendum, "model": model_ov, "effort": effort_ov}),
    }


def list_roles(path: str | Path | None = None) -> list[dict]:
    """Roster for the editor: every role, its effective model, and whether the
    client has overridden it (any of addendum / model / effort)."""
    tables = _load(path)
    out: list[dict] = []
    for role in ROLES:
        model, _ = _effective_model_effort(role)
        entry = tables.get(role) or {}
        out.append({
            "role": role,
            "model": model,
            "is_override": any(str(entry.get(k) or "").strip() for k in _FIELDS),
        })
    return out


__all__ = [
    "ROLES", "roles_file", "role_addendum", "override_model", "override_effort",
    "validate_role", "write_role_override", "remove_role_override",
    "resolved_role", "list_roles",
]
