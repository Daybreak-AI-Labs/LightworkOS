"""The persona inbox model: a domain-scoped view of what the fleet delivers.

Where ``/goals`` is one flat list of every run, this groups runs by the
*deliverable* their pack declares (a 13-week cash forecast, a CECL allowance)
and scopes them to the persona role that consumes them -- so an FP&A analyst
sees "my forecasts" and a risk officer sees "assessments awaiting my sign-off"
rather than the same undifferentiated stream.

Pure and presentation-only: the route gathers the pack contracts (specs) and
the recent runs per domain; this shapes them into the view model. A run is
"awaiting sign-off" when its pack declares a gate, the run has finished
(``done``) and no sign-off decision is recorded for it; a recorded decision
(approved or rejected) takes the run out of the waiting list.
"""
from __future__ import annotations

import functools
import logging
from typing import Any

log = logging.getLogger(__name__)

_DONE = "done"
# Deliverables per page: a catalog of 2,031 packs rendered at once was a 1.16 MB
# page, hundreds of thousands of pixels tall on a phone.
PAGE_SIZE = 25


def persona_roles_for(principal: str | None) -> list[str]:
    """The persona consumer roles bound to a principal, from the ``[personas]``
    config table (``"user:alice" = ["fpa_analyst", "treasurer"]``), falling back
    to a ``default`` entry for single-user/no-auth deployments. ``[]`` when no
    binding exists -- the inbox then shows everything, as before.

    Distinct from the dashboard's RBAC role (admin/operator/viewer, which gates
    *actions*): this says which deliverables are *yours* to consume."""
    try:
        from maverick.config import load_config
        table = (load_config() or {}).get("personas") or {}
    except Exception:  # pragma: no cover -- config never blocks the inbox
        return []
    roles = table.get(principal) if principal else None
    if roles is None:
        roles = table.get("default")
    if isinstance(roles, str):
        roles = [roles]
    return [str(r) for r in roles] if isinstance(roles, list) else []


def _run_view(g: Any, gate: str | None, signoff: str | None) -> dict:
    """One run as the inbox shows it. ``awaiting`` = a gated deliverable that
    has finished and has no sign-off recorded yet, so it is sitting for its
    human review; once signed off (approved/rejected) it drops out."""
    status = getattr(g, "status", "") or ""
    return {
        "id": getattr(g, "id", None),
        "title": getattr(g, "title", "") or "",
        "status": status,
        "updated_at": getattr(g, "updated_at", 0) or 0,
        "signoff": signoff,
        "awaiting": bool(gate) and status == _DONE and not signoff,
    }


def recent_runs_by_domain(world: Any, domains: list[str], *, owner: str | None = None,
                          per_domain: int = 5) -> dict[str, list]:
    """Each domain's newest runs, newest first, for the whole catalog at once.

    One grouped read answers every pack together. A store that cannot group
    (an older adapter, or a database without window functions) is asked one
    pack at a time as before, and a pack whose query fails simply has no runs:
    a bad query never breaks the page."""
    wanted = [d for d in domains if d]
    grouped = getattr(world, "recent_goals_by_domain", None)
    if callable(grouped):
        try:
            return dict(grouped(wanted, owner=owner, per_domain=per_domain))
        except Exception:
            log.warning("grouped read of recent runs failed; asking one pack at a time",
                        exc_info=True)
    runs: dict[str, list] = {}
    for domain in wanted:
        try:
            runs[domain] = world.list_goals(domain=domain, owner=owner,
                                            limit=per_domain, order="desc")
        except Exception:  # pragma: no cover -- a bad domain query never breaks the page
            runs[domain] = []
    return runs


def paginate(items: list[dict], page: Any = 1, per_page: int = PAGE_SIZE) -> dict:
    """One page of ``items`` and where it sits in the whole list.

    ``page`` is whatever the visitor typed, so it is forgiving: junk or an
    out-of-range number lands on a real page rather than an error. Returns
    ``page_items`` (the slice), ``page``, ``pages``, ``total``, ``first``/
    ``last`` (1-based positions shown, 0 when empty) and ``prev``/``next`` page
    numbers (``None`` at either end)."""
    per_page = max(1, int(per_page))
    pages = max(1, -(-len(items) // per_page))
    try:
        number = int(page)
    except (TypeError, ValueError):
        number = 1
    number = min(max(number, 1), pages)
    start = (number - 1) * per_page
    chunk = items[start:start + per_page]
    return {"page_items": chunk, "page": number, "pages": pages, "total": len(items),
            "first": start + 1 if chunk else 0, "last": start + len(chunk),
            "prev": number - 1 if number > 1 else None,
            "next": number + 1 if number < pages else None}


def build_inbox(specs: list[dict], runs_by_domain: dict[str, list],
                role: str | None = None,
                signoffs: dict[int, str] | None = None,
                mine: set[str] | None = None) -> dict:
    """Shape the persona inbox.

    ``specs`` are the packs that declare a deliverable (each a dict with
    ``domain``/``deliverable``/``consumers``/``cadence``/``gate``/``shape``/
    ``suite``); ``runs_by_domain`` maps a pack name to its recent runs (newest
    first). ``role`` scopes to deliverables that role consumes. ``signoffs``
    maps a goal id to its recorded decision, so a reviewed deliverable drops
    out of the awaiting queue. ``mine`` is the caller's own persona roles: when
    no explicit ``role`` is chosen, the inbox defaults to deliverables any of
    those roles consume (the "mine" view) -- so a logged-in analyst lands on
    their forecasts without picking a chip.

    Returns ``roles`` (every consumer role, for the filter), the selected
    ``role``, ``mine``/``showing_mine`` (the default-to-my-roles state),
    ``items`` (one per deliverable in view, runs attached; gated-and-finished
    first, then deliverables with results, then ones nobody has produced yet),
    and ``awaiting`` (the flat sign-off queue, newest first). ``items`` is the
    whole view; ``paginate(page)`` is :func:`paginate` over it, for the page to
    render one slice at a time."""
    signoffs = signoffs or {}
    # Full consumer set (for the searchable "jump to any role" control) and the
    # much smaller set of roles that actually have live work right now (the only
    # ones worth rendering as chips -- otherwise a 2,000-pack workspace dumps its
    # entire role catalogue as a wall of chips).
    roles = sorted({r for s in specs for r in s.get("consumers", [])})
    active_roles = sorted({
        r for s in specs if runs_by_domain.get(s["domain"])
        for r in s.get("consumers", [])
    })
    showing_mine = bool(mine) and not role
    if role:
        # Exact role first; otherwise a case-insensitive substring so "billing"
        # reaches billing_analyst the way the Permissions and connector searches do.
        q = role.strip().lower()
        exact = [s for s in specs if q in {c.lower() for c in s.get("consumers", [])}]
        specs = exact or [
            s for s in specs if any(q in c.lower() for c in s.get("consumers", []))
        ]
    elif mine:
        specs = [s for s in specs if set(s.get("consumers", [])) & mine]

    items: list[dict] = []
    awaiting: list[dict] = []
    for s in specs:
        runs = [_run_view(g, s.get("gate"), signoffs.get(getattr(g, "id", None)))
                for g in runs_by_domain.get(s["domain"], [])]
        awaiting_count = 0
        for r in runs:
            if r["awaiting"]:
                awaiting_count += 1
                awaiting.append({**r, "deliverable": s["deliverable"],
                                 "domain": s["domain"], "gate": s.get("gate")})
        items.append({**s, "runs": runs, "latest": runs[0] if runs else None,
                      "awaiting_count": awaiting_count})

    # Deliverables that need a human float to the top, then the ones with
    # results (a catalog of thousands must not bury them on a late page); then
    # alphabetical.
    items.sort(key=lambda it: (it["awaiting_count"] == 0, it["latest"] is None,
                               it["deliverable"].lower()))
    awaiting.sort(key=lambda r: r["updated_at"], reverse=True)
    return {"roles": roles, "active_roles": active_roles, "role": role or "",
            "mine": sorted(mine or []), "showing_mine": showing_mine,
            "items": items, "awaiting": awaiting,
            "paginate": functools.partial(paginate, items)}


__all__ = ["PAGE_SIZE", "build_inbox", "paginate", "persona_roles_for",
           "recent_runs_by_domain"]
