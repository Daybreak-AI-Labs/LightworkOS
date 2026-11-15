"""Tenant markers for the world model's raw, SQLite-paramstyle reads.

``WorldModel.tenant_query`` (and its Postgres mirror) takes SQL that names its
tenant boundary with markers instead of hand-written predicates:

* ``{tenant:COL}`` -- the backend's normal read scope on a root table's tenant
  column (``goals``, ``approvals``, ``conversations``, ...).
* ``{tenant_exact:COL}`` -- the exact scope: legacy rows without a tenant are
  not visible to a bound tenant.
* ``{tenant_goal:COL}`` -- a child row (episodes, turns, questions, ...) whose
  ``COL`` is a goal id in the active tenant.

The SQLite store is one file per tenant, so every marker becomes ``1=1`` there;
the Postgres store substitutes its tenant predicate. Expansion keeps the
positional ``?`` parameters in order.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from typing import Any

_MARKER = re.compile(r"\{tenant(|_exact|_goal):([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)\}")

#: ``resolve(kind, column)`` returns a ``?``-paramstyle fragment and its values.
Resolver = Callable[[str, str], tuple[str, Sequence[Any]]]


class TenantScopeRequired(PermissionError):
    """An unscoped raw read was refused because the store is tenant-scoped."""


def expand(sql: str, params: Sequence[Any], resolve: Resolver, *,
           require: bool = True) -> tuple[str, tuple]:
    """Replace every tenant marker in ``sql`` and splice its values into place.

    ``require`` refuses a statement without any marker: a call moved to the
    tenant-scoped accessor must say where its boundary is.
    """
    params = tuple(params)
    if not _MARKER.search(sql):
        if require:
            raise ValueError("a tenant-scoped read must name its tenant boundary with a {tenant...} marker")
        return sql, params
    out: list[str] = []
    values: list[Any] = []
    used = 0
    in_literal = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            in_literal = not in_literal
        elif ch == "?" and not in_literal:
            if used >= len(params):
                raise ValueError("statement has more placeholders than values")
            values.append(params[used])
            used += 1
        elif ch == "{" and not in_literal:
            match = _MARKER.match(sql, i)
            if match:
                fragment, extra = resolve(match.group(1).lstrip("_") or "read", match.group(2))
                out.append(f"({fragment})")
                values.extend(extra)
                i = match.end()
                continue
        out.append(ch)
        i += 1
    if used != len(params):
        raise ValueError("statement has fewer placeholders than values")
    return "".join(out), tuple(values)


def unscoped(_kind: str, _column: str) -> tuple[str, tuple]:
    """Resolver for a store whose tenancy is its file path (SQLite)."""
    return "1=1", ()
