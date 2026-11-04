"""RBAC authorization checker.

Evaluates whether a subject is permitted an action under a role-based access-
control policy: resolve the user's roles (with transitive role inheritance),
union their permissions, and decide ALLOW/DENY — honoring ``*`` (all) and
prefix wildcards like ``doc:*``. A decision tool the agent can use to reason
about a *target system's* authorization, distinct from ``capability_query``
(Lightwork's own run grant). Pure set/graph work — deterministic and offline.

ops:
  - check(roles, assignments, user, permission, [inherits])  — ``roles`` is
    ``{role: [permissions]}``, ``assignments`` ``{user: [roles]}``, ``inherits``
    an optional ``{role: [parent_roles]}`` hierarchy. Reports ALLOW (with the
    granting role) or DENY (with the reason).
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _expand(roles_of_user: list[str], inherits: dict[str, list[str]]) -> list[str]:
    """Transitive closure of a user's roles over the inheritance graph."""
    seen: set[str] = set()
    stack = list(roles_of_user)
    while stack:
        r = stack.pop()
        if r in seen:
            continue
        seen.add(r)
        stack.extend(inherits.get(r, []))
    return sorted(seen)


def _grants(perm: str, requested: str) -> bool:
    if perm == "*" or perm == requested:
        return True
    if perm.endswith(":*") and requested.startswith(perm[:-1]):  # "doc:*" -> "doc:"
        return True
    return False


def _check(roles: dict, assignments: dict, inherits: dict, user: str, permission: str) -> str:
    assigned = assignments.get(user)
    if not assigned:
        return f"DENY: user {user!r} has no roles assigned"

    effective = _expand([str(r) for r in assigned], inherits)
    granting = []
    for role in effective:
        for perm in roles.get(role, []):
            if _grants(str(perm), permission):
                granting.append(role)
                break

    if granting:
        return f"ALLOW: user {user!r} has {permission!r} via role {min(granting)!r}"
    return f"DENY: user {user!r} lacks {permission!r} (roles: {', '.join(effective)})"


def _normalize_list_map(value: dict, name: str, item_name: str) -> tuple[dict[str, list[str]] | None, str | None]:
    normalized: dict[str, list[str]] = {}
    for key, items in value.items():
        if not isinstance(items, list):
            return None, f"ERROR: {name} entry {str(key)!r} must be a list of {item_name}"
        normalized[str(key)] = [str(item) for item in items]
    return normalized, None


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    roles = args.get("roles")
    if not isinstance(roles, dict):
        return "ERROR: roles must be an object {role: [permissions]}"
    assignments = args.get("assignments")
    if not isinstance(assignments, dict):
        return "ERROR: assignments must be an object {user: [roles]}"
    inherits = args.get("inherits", {})
    if not isinstance(inherits, dict):
        return "ERROR: inherits must be an object {role: [parent_roles]}"
    user = args.get("user")
    if not isinstance(user, str) or not user:
        return "ERROR: user must be a non-empty string"
    permission = args.get("permission")
    if not isinstance(permission, str) or not permission:
        return "ERROR: permission must be a non-empty string"

    norm_roles, error = _normalize_list_map(roles, "roles", "permissions")
    if error:
        return error
    norm_assignments, error = _normalize_list_map(assignments, "assignments", "roles")
    if error:
        return error
    norm_inherits, error = _normalize_list_map(inherits, "inherits", "parent roles")
    if error:
        return error
    return _check(norm_roles or {}, norm_assignments or {}, norm_inherits or {}, user, permission)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "roles": {
            "type": "object",
            "additionalProperties": {"type": "array", "items": {"type": "string"}},
            "description": "role -> list of permissions ('*' and 'prefix:*' wildcards allowed)",
        },
        "assignments": {
            "type": "object",
            "additionalProperties": {"type": "array", "items": {"type": "string"}},
            "description": "user -> list of assigned roles",
        },
        "inherits": {
            "type": "object",
            "additionalProperties": {"type": "array", "items": {"type": "string"}},
            "description": "optional role -> list of parent roles (child inherits parent perms)",
        },
        "user": {"type": "string", "description": "the subject to authorize"},
        "permission": {"type": "string", "description": "the permission being requested"},
    },
    "required": ["roles", "assignments", "user", "permission"],
}


def rbac_check() -> Tool:
    return Tool(
        name="rbac_check",
        description=(
            "Evaluate an RBAC authorization decision. op=check with 'roles' "
            "({role: [permissions]}), 'assignments' ({user: [roles]}), 'user', "
            "'permission', and optional 'inherits' ({role: [parent_roles]}). "
            "Resolves role inheritance transitively, honors '*' and 'prefix:*' "
            "wildcards, and reports ALLOW (granting role) or DENY (reason). "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
