"""Owner-scoped data projections for executive dashboard boards.

The API authorizes each request before calling these functions. The world and
owner are explicit inputs so aggregation can be used without importing the API.
"""
from __future__ import annotations

import time

_BOARD_DAYS = (30, 90, 180, 365)


def _board_days(days: int | None) -> int:
    return days if days in _BOARD_DAYS else 90


def _board_day_list(days: int):
    from datetime import datetime, timedelta, timezone

    # SQLite's date(..., 'unixepoch') buckets timestamps in UTC. Use the same
    # clock here so late-evening requests west of UTC do not build a local-day
    # key set that drops today's UTC rows.
    today = datetime.now(timezone.utc).date()
    day_list = [today - timedelta(days=i) for i in range(days - 1, -1, -1)]
    since = datetime.combine(day_list[0], datetime.min.time(), tzinfo=timezone.utc).timestamp()
    return day_list, since, since - days * 86400


def _owner_sql(owner, column: str = "owner"):
    """(extra WHERE clause, params) for goal-owner scoping."""
    return ("", ()) if owner is None else (f" AND {column} = ?", (owner,))


def _board_overview(w, owner, days: int) -> dict:
    day_list, since, prev_since = _board_day_list(days)
    own, params = _owner_sql(owner)
    by_status = {
        r[0]: int(r[1])
        for r in w.query(
            "SELECT status, COUNT(*) FROM goals WHERE 1=1" + own + " GROUP BY status", params
        )
    }
    daily = {d.isoformat(): {"d": d.isoformat(), "started": 0, "delivered": 0} for d in day_list}
    for col, key, extra in (
        ("created_at", "started", ""),
        ("updated_at", "delivered", " AND status = 'done'"),
    ):
        rows = w.query(
            f"SELECT {w.sql_day_from_epoch(col)} AS day, COUNT(*) FROM goals "
            f"WHERE {col} >= ?" + extra + own + " GROUP BY day",
            (since, *params),
        )
        for day, n in rows:
            if day in daily:
                daily[day][key] += int(n)

    def _count(col: str, lo: float, hi: float, extra: str = "") -> int:
        return int(
            w.query(
                f"SELECT COUNT(*) FROM goals WHERE {col} >= ? AND {col} < ?" + extra + own,
                (lo, hi, *params),
            )[0][0]
        )

    now = time.time()
    window = {
        "started": _count("created_at", since, now),
        "delivered": _count("updated_at", since, now, " AND status = 'done'"),
        "started_prev": _count("created_at", prev_since, since),
        "delivered_prev": _count("updated_at", prev_since, since, " AND status = 'done'"),
    }
    from maverick.departments import department_title
    from maverick.domain import suite_for

    domains: dict[str, dict] = {}
    for dom, total, done in w.query(
        "SELECT domain, COUNT(*), SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) FROM goals "
        "WHERE 1=1" + own + " GROUP BY domain",
        params,
    ):
        suite = suite_for(dom or "") if dom else None
        label = department_title(suite) if suite else "General"
        row = domains.setdefault(label, {"label": label, "total": 0, "done": 0})
        row["total"] += int(total)
        row["done"] += int(done or 0)
    recent = [
        {"id": g.id, "title": g.title, "status": g.status, "updated_at": g.updated_at}
        for g in w.list_goals(owner=owner, limit=12, order="desc")
    ]
    return {
        "totals": {
            "total": sum(by_status.values()),
            "active": by_status.get("active", 0),
            "done": by_status.get("done", 0),
            "blocked": by_status.get("blocked", 0),
        },
        # Every status with its own count, so the page can show queued, failed,
        # cancelled and draft goals separately instead of lumping the rest.
        "by_status": by_status,
        "window": window,
        "daily": list(daily.values()),
        "domains": sorted(domains.values(), key=lambda r: r["total"], reverse=True)[:8],
        "recent": recent,
    }


def _board_spend(w, owner, days: int) -> dict:
    day_list, since, prev_since = _board_day_list(days)
    join = (
        "FROM episodes e JOIN goals g ON e.goal_id = g.id"
        if owner is not None
        else "FROM episodes e"
    )
    own, params = ("", ()) if owner is None else (" AND g.owner = ?", (owner,))
    ended = " WHERE e.ended_at IS NOT NULL"

    daily = {d.isoformat(): {"d": d.isoformat(), "cost": 0.0, "runs": 0} for d in day_list}
    for day, cost, runs in w.query(
        "SELECT " + w.sql_day_from_epoch("e.started_at") + " AS day, "
        "SUM(COALESCE(e.cost_dollars, 0)), COUNT(*) "
        + join
        + ended
        + " AND e.started_at >= ?"
        + own
        + " GROUP BY day",
        (since, *params),
    ):
        if day in daily:
            daily[day] = {"d": day, "cost": float(cost or 0), "runs": int(runs)}

    def _tot(lo: float) -> dict:
        r = w.query(
            "SELECT COALESCE(SUM(e.cost_dollars), 0), COUNT(*), "
            "COALESCE(SUM(e.input_tokens), 0), COALESCE(SUM(e.output_tokens), 0), "
            "COALESCE(SUM(e.tool_calls), 0) "
            + join
            + ended
            + " AND e.started_at >= ? AND e.started_at < ?"
            + own,
            (lo, lo + days * 86400 + 1, *params),
        )[0]
        return {
            "dollars": float(r[0]),
            "runs": int(r[1]),
            "input_tokens": int(r[2]),
            "output_tokens": int(r[3]),
            "tool_calls": int(r[4]),
        }

    totals, prev = _tot(since), _tot(prev_since)
    episodes = w.list_episodes(limit=200, owner=owner)
    outcomes = {"success": 0, "failed": 0, "running": 0}
    from maverick.episode_reporting import iter_episodes
    from maverick.workforce_value import _is_done
    for e in iter_episodes(w, owner=owner, since=since, until=since + days * 86400 + 1):
        if e.ended_at is None:
            outcomes["running"] += 1
        elif _is_done(e.outcome):
            outcomes["success"] += 1
        else:
            outcomes["failed"] += 1
    per_run = [
        {"id": e.id, "goal_id": e.goal_id, "cost": float(e.cost_dollars or 0)}
        for e in episodes[:60]
    ]
    top_goals = []
    for gid, cost, runs in w.query(
        "SELECT e.goal_id, SUM(COALESCE(e.cost_dollars, 0)) AS c, COUNT(*) "
        + join
        + ended
        + " AND e.started_at >= ?"
        + own
        + " GROUP BY e.goal_id ORDER BY c DESC LIMIT 8",
        (since, *params),
    ):
        g = w.get_goal(int(gid)) if gid is not None else None
        top_goals.append(
            {
                "goal_id": gid,
                "title": g.title if g else f"#{gid}",
                "cost": float(cost or 0),
                "runs": int(runs),
            }
        )
    return {
        "totals": totals,
        "prev": prev,
        "daily": list(daily.values()),
        "outcomes": outcomes,
        "outcomes_population": "All authorized episode attempts started in the selected period; running attempts are separate from the finished-attempt cost totals.",
        "per_run": per_run,
        "top_goals": top_goals,
        "by_platform": _external_platform_spend(w, owner, since),
    }


def _external_platform_spend(w, owner, since: float) -> list[dict]:
    """Spend by external-agent platform (bring-your-own-agent runs).

    Forces the episodes⋈goals join unconditionally — the admin/auth-off view
    passes ``owner is None``, and that is precisely the view where
    ``agent:*`` rows exist. Individual humans keep owner scoping and simply
    see an empty segment."""
    if owner is not None:
        return []
    from maverick.external_agents import PLATFORMS, roster

    platform_of = {f"agent:{r['id']}": r["platform"] for r in roster()}
    if not platform_of:
        return []
    agg: dict[str, dict] = {}
    for own_id, cost, runs in w.query(
        "SELECT g.owner, SUM(COALESCE(e.cost_dollars, 0)), COUNT(*) "
        "FROM episodes e JOIN goals g ON e.goal_id = g.id "
        "WHERE e.ended_at IS NOT NULL AND e.started_at >= ? "
        "AND g.owner LIKE 'agent:%' GROUP BY g.owner",
        (since,),
    ):
        platform = platform_of.get(str(own_id))
        if platform is None:
            continue
        row = agg.setdefault(
            platform, {"label": PLATFORMS.get(platform, platform), "cost": 0.0, "runs": 0}
        )
        row["cost"] += float(cost or 0)
        row["runs"] += int(runs)
    return sorted(agg.values(), key=lambda r: r["cost"], reverse=True)[:8]


def _board_workforce(w, owner, days: int) -> dict:
    from maverick.departments import list_departments
    from maverick.marketplace.storefront import connector_marketplace
    from maverick.operating_record import assemble
    from maverick.outcomes import firm_totals, worker_cards

    _, since, prev_since = _board_day_list(days)
    own, params = _owner_sql(owner)
    # One Operating Record for both (each assembly decodes up to 5,000 approvals).
    records = assemble(w, owner=owner)
    firm = firm_totals(records).to_dict()
    cards = worker_cards(w, owner=owner, records=records)
    depts: dict[str, dict] = {}
    for c in cards:
        row = depts.setdefault(
            c.suite_title or "General",
            {"label": c.suite_title or "General", "completed": 0, "total": 0, "spend": 0.0},
        )
        row["completed"] += c.goals_completed
        row["total"] += c.goals_total
        row["spend"] += c.spend_dollars

    def _delivered(lo: float, hi: float) -> int:
        return int(
            w.query(
                "SELECT COUNT(*) FROM goals WHERE status = 'done' "
                "AND updated_at >= ? AND updated_at < ?" + own,
                (lo, hi, *params),
            )[0][0]
        )

    return {
        "kpis": {
            "departments": len(depts),
            "specialists": sum(d.headcount for d in list_departments()),
            "connectors": connector_marketplace()["total"],
            "goals_completed": firm["goals_completed"],
            "goals_total": firm["goals_total"],
            "spend_dollars": firm["spend_dollars"],
            "delivered_window": _delivered(since, time.time()),
            "delivered_prev": _delivered(prev_since, since),
        },
        "depts": sorted(depts.values(), key=lambda r: (r["completed"], r["total"]), reverse=True)[
            :8
        ],
        "leaders": [c.to_dict() for c in cards[:6]],
        "platforms": _external_platform_workforce(w, owner),
    }


def _external_platform_workforce(w, owner) -> list[dict]:
    """Goals by external-agent platform for the workforce board. Same
    admin-view-only rule as the spend segment: individual humans keep owner
    scoping and see an empty segment."""
    if owner is not None:
        return []
    from maverick.external_agents import PLATFORMS, roster

    platform_of = {f"agent:{r['id']}": r["platform"] for r in roster()}
    if not platform_of:
        return []
    agg: dict[str, dict] = {}
    for own_id, completed, total, spend in w.query(
        "SELECT g.owner, "
        "SUM(CASE WHEN g.status = 'done' THEN 1 ELSE 0 END), COUNT(*), "
        "(SELECT COALESCE(SUM(e.cost_dollars), 0) FROM episodes e "
        " JOIN goals g2 ON e.goal_id = g2.id WHERE g2.owner = g.owner) "
        "FROM goals g WHERE g.owner LIKE 'agent:%' GROUP BY g.owner"
    ):
        platform = platform_of.get(str(own_id))
        if platform is None:
            continue
        row = agg.setdefault(
            platform,
            {"label": PLATFORMS.get(platform, platform), "completed": 0, "total": 0, "spend": 0.0},
        )
        row["completed"] += int(completed or 0)
        row["total"] += int(total or 0)
        row["spend"] += float(spend or 0)
    return sorted(agg.values(), key=lambda r: (r["completed"], r["total"]), reverse=True)[:8]


def _board_savings(w, owner, days: int) -> dict:
    """The value board: the same honest math as /savings (client-set
    assumptions x completed work - agent spend), plus a daily delivered
    series so the page can show work over time."""
    from maverick import savings as savings_mod
    from maverick.config import get_value

    day_list, since, _prev = _board_day_list(days)
    own, params = _owner_sql(owner)
    daily = {d.isoformat(): {"d": d.isoformat(), "n": 0} for d in day_list}
    for day, n in w.query(
        "SELECT " + w.sql_day_from_epoch("updated_at") + " AS day, COUNT(*) FROM goals "
        "WHERE status = 'done' AND updated_at >= ?" + own + " GROUP BY day",
        (since, *params),
    ):
        if day in daily:
            daily[day]["n"] = int(n)
    report = savings_mod.to_dict(savings_mod.compute(w, window_days=days, cfg=get_value(), owner=owner))
    return {"report": report, "daily_done": list(daily.values())}



def _board_workspace(department: str, *, base) -> dict:
    """Compact department board (privacy / finance / security): the same
    assessment records the workspace pages list, rolled into KPIs, a residual-
    risk mix, a 12-month opened-vs-decided series, and per-framework volume.
    The deep executive view stays /privacy/board; this is the at-a-glance."""
    from datetime import datetime, timezone

    from maverick.assessment import custom_template_records, list_saved

    types = set(base) | {
        t
        for t, rec in custom_template_records().items()
        if rec.get("department", "privacy") == department
    }
    sessions = [x for x in list_saved() if x.get("type") in types]

    kpis = {
        "total": len(sessions),
        "open": 0,
        "needs_more": 0,
        "approved": 0,
        "rejected": 0,
        "due_review": 0,
    }
    for x in sessions:
        st = x.get("status")
        if st == "pending_review":
            kpis["open"] += 1
        elif st in ("needs_more", "needs_answers"):
            kpis["needs_more"] += 1
        elif st in kpis:
            kpis[st] += 1
        if x.get("review_due"):
            kpis["due_review"] += 1

    risk = {"high": 0, "medium": 0, "low": 0, "minimal": 0, "unrated": 0}
    for x in sessions:
        risk[x.get("residual_risk") if x.get("residual_risk") in risk else "unrated"] += 1

    def _month(ts: float) -> str:
        d = datetime.fromtimestamp(ts, tz=timezone.utc)
        return f"{d.year}-{d.month:02d}"

    now = datetime.now(tz=timezone.utc)
    months: list[str] = []
    y, m = now.year, now.month
    for _ in range(12):
        months.insert(0, f"{y}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    monthly = {k: {"d": k, "opened": 0, "decided": 0} for k in months}
    for x in sessions:
        for field, key in (("created_at", "opened"), ("decided_at", "decided")):
            ts = x.get(field)
            if ts and _month(float(ts)) in monthly:
                monthly[_month(float(ts))][key] += 1

    by_type: dict[str, dict] = {}
    for x in sessions:
        row = by_type.setdefault(
            x.get("type") or "?",
            {"label": (x.get("type") or "?").replace("_", " "), "total": 0, "approved": 0},
        )
        row["total"] += 1
        if x.get("status") == "approved":
            row["approved"] += 1
    return {
        "kpis": kpis,
        "risk": risk,
        "monthly": list(monthly.values()),
        "types": sorted(by_type.values(), key=lambda r: r["total"], reverse=True)[:6],
    }



def _board_oversight(w, owner, days: int, request=None, *, visible, is_intervention) -> dict:
    """Scoped guardrail metadata with explicit availability for each source."""
    from datetime import datetime, timedelta, timezone

    day_list, since, _prev = _board_day_list(days)
    daily = {d.isoformat(): {"d": d.isoformat(), "n": 0} for d in day_list}
    by_kind: dict[str, int] = {}
    total = 0
    owner_cache = {}
    sources = {name: {"state": "available", "checked_at": time.time(), "repair_href": href}
               for name, href in (("audit", "/audit"), ("approvals", "/action-center"), ("halt", "/oversight"))}
    try:
        from maverick.audit.export import iter_audit_events
        from maverick.audit.segments import ReadReport

        since_day = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()
        report = ReadReport()
        scanned = 0
        for e in iter_audit_events(since=since_day, report=report):
            scanned += 1
            if scanned > 100_000:
                sources["audit"]["state"] = "partial"
                break
            if not is_intervention(e) or not visible(
                e, principal=owner, owner_filter=owner, world=w, goal_owner_cache=owner_cache,
            ):
                continue
            total += 1
            kind = str(e.get("kind") or "event")
            by_kind[kind] = by_kind.get(kind, 0) + 1
            ts = e.get("ts")
            if ts:
                day = datetime.fromtimestamp(float(ts), tz=timezone.utc).date().isoformat()
                if day in daily:
                    daily[day]["n"] += 1
        if report.as_dict().get("failures"):
            sources["audit"]["state"] = "partial"
    except Exception:  # pragma: no cover -- fail-soft like the page
        total = None
        sources["audit"]["state"] = "unavailable"
    try:
        clauses = "a.status = 'pending'"
        values = ()
        if owner is not None:
            clauses += " AND COALESCE(a.requested_by, '') = ?"
            values = (owner,)
        if request is None:
            pending = int(w.query("SELECT COUNT(*) FROM approvals a WHERE " + clauses, values)[0][0])
        else:
            from .content_access import can_read_approval
            pending = sum(can_read_approval(request, row, world=w) for row in w.pending_approvals())
    except Exception:  # pragma: no cover
        pending = None
        sources["approvals"]["state"] = "unavailable"
    try:
        halted = bool(w.active_halt())
    except Exception:  # pragma: no cover
        halted = None
        sources["halt"]["state"] = "unavailable"
    kinds = sorted(
        ({"kind": k.replace("_", " "), "n": n} for k, n in by_kind.items()),
        key=lambda r: r["n"],
        reverse=True,
    )[:8]
    return {
        "interventions": total,
        "by_kind": kinds,
        "daily": list(daily.values()),
        "pending_approvals": pending,
        "halted": halted,
        "sources": sources,
        "degraded": any(source["state"] != "available" for source in sources.values()),
    }
