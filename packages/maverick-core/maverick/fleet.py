"""Agent fleets -- Layer C of the enterprise control plane.

(See ``docs/enterprise/architecture.md``.) A **Fleet** is the per-employee unit
of the product: an *owner* (a human principal) plus a roster of named,
role-scoped **agents** that do ongoing work. Each agent's role drives its
capability (via ``[roles.<role>]`` RBAC) and the whole fleet runs under the
oversight control plane (``maverick.governance``).

This module is the persistent model + lifecycle (create / list / show / remove).
Binding a fleet's agents to live runs (spawn, schedule, supervise) is built on
top of this registry.

Fleets are stored as JSON at ``~/.maverick/fleets/<name>.json``, tenant-aware via
:func:`maverick.paths.data_dir`, so one tenant's fleet roster never leaks to
another.
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

# Concurrent runs of the same fleet append to one ``<name>.runs.json`` index.
# Serialize the read-modify-write so simultaneous dispatches don't clobber each
# other's entries (in-process; the dashboard runs goals as background threads).
_runs_lock = threading.Lock()

# Fleet + agent names become file + principal components, so constrain them to a
# safe, predictable charset (blocks path traversal and audit-id ambiguity).
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def valid_name(name: str) -> bool:
    return bool(isinstance(name, str) and _NAME_RE.match(name))


@dataclass(frozen=True)
class FleetAgent:
    """One agent in a fleet: a name + the RBAC role that scopes its capability."""

    name: str
    role: str
    description: str = ""
    domain: str = ""   # optional specialist pack; binds the agent to that
    #                    pack's capability envelope at run time (department deploys)

    def to_dict(self) -> dict:
        d = {"name": self.name, "role": self.role, "description": self.description}
        if self.domain:
            d["domain"] = self.domain
        return d

    @classmethod
    def from_dict(cls, d: dict) -> FleetAgent:
        if not isinstance(d, dict):
            raise ValueError("fleet agent must be an object")
        return cls(
            name=str(d.get("name", "")),
            role=str(d.get("role", "")),
            description=str(d.get("description", "") or ""),
            domain=str(d.get("domain", "") or ""),
        )


@dataclass(frozen=True)
class Fleet:
    """An owner's roster of role-scoped agents."""

    name: str
    owner: str
    agents: tuple[FleetAgent, ...] = ()
    created_at: float = field(default_factory=lambda: time.time())
    # Catalog specialists this department deployment already offered. Keeping
    # the names after an admin removes an agent prevents a later sync from
    # silently undoing that choice. Generic fleets leave this empty.
    department_members_added: tuple[str, ...] = ()
    # Original accepted update metadata shares the roster's atomic replacement.
    # Ordinary roster edits retain the bounded history; it contains no prompts.
    department_update_receipts: tuple[dict, ...] = ()

    def principal_for(self, agent_name: str) -> str:
        """The audit/capability principal for one of this fleet's agents."""
        return f"agent:{self.name}.{agent_name}"

    def to_dict(self) -> dict:
        result = {
            "name": self.name,
            "owner": self.owner,
            "agents": [a.to_dict() for a in self.agents],
            "created_at": self.created_at,
        }
        if self.department_members_added:
            result["department_members_added"] = list(self.department_members_added)
        if self.department_update_receipts:
            result["department_update_receipts"] = list(self.department_update_receipts)
        return result

    @classmethod
    def from_dict(cls, d: dict) -> Fleet:
        if not isinstance(d, dict):
            raise ValueError("fleet must be an object")
        agents = d.get("agents", []) or []
        if not isinstance(agents, list | tuple):
            raise ValueError("fleet agents must be a list")
        added = d.get("department_members_added", []) or []
        if (not isinstance(added, list | tuple)
                or any(not isinstance(name, str) or not valid_name(name) for name in added)):
            raise ValueError("department members must be valid names")
        receipts = d.get("department_update_receipts", []) or []
        if not isinstance(receipts, list | tuple) or len(receipts) > 32 or any(not isinstance(row, dict) for row in receipts):
            raise ValueError("department update receipts must be a bounded list")
        try:
            created_at = float(d.get("created_at", 0.0) or 0.0)
        except (TypeError, ValueError) as exc:
            raise ValueError("fleet created_at must be numeric") from exc
        return cls(
            name=str(d.get("name", "")),
            owner=str(d.get("owner", "")),
            agents=tuple(FleetAgent.from_dict(a) for a in agents),
            created_at=created_at,
            department_members_added=tuple(added),
            department_update_receipts=tuple(receipts),
        )


def fleets_dir(*, tenant: str | None = "__active__") -> Path:
    from .paths import data_dir
    return data_dir("fleets", tenant=tenant)


def ensure_dispatch_allowed(principal: str | None, agent: FleetAgent) -> None:
    """Kernel gate: may ``principal`` dispatch this fleet agent?

    A department-deployed agent carries its specialist pack (``agent.domain``);
    a dispatcher scoped to other departments may not run it, even on a fleet
    they own (e.g. a grant narrowed after deploy). Raises
    :class:`maverick.suite_grants.DepartmentAccessError` on denial. Generic
    agents (no domain, or a pack outside every suite), an empty principal
    (host operator / auth off), and configured admins always pass — the same
    fail-open invariant as :func:`maverick.departments.deploy_department`."""
    if not agent.domain:
        return
    from .domain import suites_for_domain
    from .suite_grants import ensure_suite_allowed
    for suite in suites_for_domain(agent.domain):
        ensure_suite_allowed(principal, suite)


def save_fleet(fleet: Fleet, *, tenant: str | None = "__active__") -> Path:
    """Persist a fleet (0600). Raises ValueError on an invalid name."""
    if not valid_name(fleet.name):
        raise ValueError(f"invalid fleet name: {fleet.name!r}")
    from .file_lock import atomic_write_text, cross_process_lock, ensure_private_directory

    d = fleets_dir(tenant=tenant)
    ensure_private_directory(d)
    path = d / f"{fleet.name}.json"
    with cross_process_lock(path):
        # The ordinary fleet editor and specialist-hiring paths rebuild Fleet
        # objects. Preserve the department marker across those edits.
        prior = load_fleet(fleet.name, tenant=tenant)
        if prior is not None and prior.owner == fleet.owner:
            fleet = replace(fleet,
                department_members_added=fleet.department_members_added or prior.department_members_added,
                department_update_receipts=fleet.department_update_receipts or prior.department_update_receipts)
        atomic_write_text(path, json.dumps(fleet.to_dict(), indent=2, sort_keys=True))
    return path


def load_fleet(name: str, *, tenant: str | None = "__active__") -> Fleet | None:
    if not valid_name(name):
        return None
    path = fleets_dir(tenant=tenant) / f"{name}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return Fleet.from_dict(data)
    except ValueError:
        return None


def list_fleets(*, tenant: str | None = "__active__") -> list[Fleet]:
    d = fleets_dir(tenant=tenant)
    if not d.exists():
        return []
    out: list[Fleet] = []
    for path in sorted(d.glob("*.json")):
        f = load_fleet(path.stem, tenant=tenant)
        if f is not None:
            out.append(f)
    return out


def remove_fleet(name: str, *, tenant: str | None = "__active__") -> bool:
    if not valid_name(name):
        return False
    path = fleets_dir(tenant=tenant) / f"{name}.json"
    from .file_lock import cross_process_lock
    with cross_process_lock(path):
        try:
            path.unlink()
        except OSError:
            return False
        try:
            runs_path(name, tenant=tenant).unlink()
        except OSError:
            pass
    return True


def runs_path(name: str, *, tenant: str | None = "__active__") -> Path:
    """The per-fleet run index (``<name>.runs.json``), tenant-aware."""
    return fleets_dir(tenant=tenant) / f"{name}.runs.json"


def load_runs(name: str, *, tenant: str | None = "__active__") -> list[dict]:
    """Recent runs for a fleet (oldest first), or ``[]`` if none/unreadable."""
    if not valid_name(name):
        return []
    try:
        data = json.loads(runs_path(name, tenant=tenant).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def record_run(
    name: str, agent: str, goal_id: int, *, tenant: str | None = "__active__"
) -> None:
    """Append a ``{agent, goal_id, ts}`` entry to the fleet's run index (0600).

    Atomic under ``_runs_lock`` + a temp-file rename, so concurrent runs of the
    same fleet never lose each other's entries to a read-modify-write race."""
    if not valid_name(name):
        raise ValueError(f"invalid fleet name: {name!r}")
    from .file_lock import atomic_write_text, cross_process_lock, ensure_private_directory

    d = fleets_dir(tenant=tenant)
    ensure_private_directory(d)
    path = runs_path(name, tenant=tenant)
    with _runs_lock, cross_process_lock(path):
        runs = load_runs(name, tenant=tenant)
        runs.append({"agent": agent, "goal_id": goal_id, "ts": time.time()})
        atomic_write_text(path, json.dumps(runs, indent=2))


__all__ = [
    "FleetAgent",
    "Fleet",
    "valid_name",
    "fleets_dir",
    "save_fleet",
    "load_fleet",
    "list_fleets",
    "remove_fleet",
    "runs_path",
    "load_runs",
    "record_run",
]
