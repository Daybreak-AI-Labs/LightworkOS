"""Synthetic sources for the real outcome-value browser acceptance path.

The fixture creates local WorldModel tasks only. Pilots, admissions,
observations, accounting projections, value evidence, and exports still travel
through the dashboard's production HTTP routes in the Playwright spec.
"""
from __future__ import annotations

from fastapi import HTTPException, Request
from maverick.paths import tenant_scope
from maverick_dashboard import outcome_pilots
from maverick_dashboard.auth import caller_principal
from maverick_dashboard.draft_api import context_for


def _create_groups(world, principal: str) -> list[list[dict]]:
    definitions = (
        (
            "Primary value case",
            (("accepted", "3"), ("failed", "5"),
             ("cancelled", "2"), ("unresolved", "1")),
        ),
        (
            "Isolation control case",
            (("accepted", "13"), ("rejected", "17"),
             ("failed", "19"), ("cancelled", "23")),
        ),
    )
    groups = []
    for prefix, outcomes in definitions:
        group = []
        for index, (outcome, cost) in enumerate(outcomes, 1):
            title = f"{prefix} {index}"
            identifier = world.create_goal(
                title,
                "Synthetic local outcome-value case; no provider or customer work.",
                owner=principal,
            )
            group.append({
                "kind": "goal", "reference": str(identifier), "label": title,
                "fixture_outcome": outcome, "fixture_cost": cost,
            })
        groups.append(group)
    return groups


def install(app, world, tenant: str, principal: str) -> None:
    # Fixture state is kept per synthetic caller so a journey can seed sources
    # for its own owner, isolated from the records other journeys admit for the
    # shared reviewer during the same server session.
    state: dict[str, dict] = {}

    def fixture_owner(request: Request) -> tuple[str, dict]:
        caller = caller_principal(request)
        if caller != principal and not str(caller or "").startswith("user:browser-"):
            raise HTTPException(
                403,
                "Only a synthetic browser principal can change outcome-value fixture state.",
            )
        return caller, state.setdefault(caller, {"groups": [], "finished": False})

    def fixture_context(request: Request) -> str:
        with tenant_scope(tenant=tenant):
            return context_for(request)

    @app.post("/__browser_fixture/outcome-value/setup", include_in_schema=False)
    async def setup(request: Request):
        owner, own = fixture_owner(request)
        groups = own["groups"]
        if not groups:
            with tenant_scope(tenant=tenant):
                groups.extend(_create_groups(world, owner))
        return {
            "synthetic": True,
            "provider_calls": 0,
            "context": fixture_context(request),
            "groups": groups,
        }

    @app.post("/__browser_fixture/outcome-value/finish", include_in_schema=False)
    async def finish(request: Request, body: dict):
        owner, own = fixture_owner(request)
        groups = own["groups"]
        identifiers = body.get("pilot_ids") if isinstance(body, dict) else None
        if (
            not groups
            or not isinstance(identifiers, list)
            or len(identifiers) != len(groups)
            or any(not isinstance(value, str) for value in identifiers)
        ):
            raise HTTPException(422, "Supply the two fixture pilot identities.")
        context = fixture_context(request)
        with tenant_scope(tenant=tenant):
            for identifier, group in zip(identifiers, groups, strict=True):
                try:
                    pilot = outcome_pilots.get(identifier, context)
                    outcome_pilots.validate_admission_manifest(
                        pilot, require_complete=True,
                    )
                except Exception as exc:
                    raise HTTPException(
                        409,
                        "Create and completely admit both fixture pilots before starting their cases.",
                    ) from exc
                expected = [row["reference"] for row in group]
                actual = [case.get("reference") for case in pilot.get("cases", [])]
                if pilot.get("actor") != owner or actual != expected:
                    raise HTTPException(
                        409,
                        "A supplied pilot does not match this fixture's frozen cases.",
                    )
            if not own["finished"]:
                for group in groups:
                    for row in group:
                        identifier = int(row["reference"])
                        goal = world.get_goal(identifier)
                        if goal is None or goal.owner != owner or goal.status != "pending":
                            raise HTTPException(409, "A fixture source changed before execution.")
                for group in groups:
                    for row in group:
                        identifier = int(row["reference"])
                        episode = world.start_episode(identifier)
                        world.end_episode(
                            episode,
                            "Synthetic local episode completed without any provider call.",
                            row["fixture_outcome"],
                            cost_dollars=0,
                        )
                        outcome = row["fixture_outcome"]
                        status = "done" if outcome in {"accepted", "rejected", "unresolved"} else outcome
                        world.set_goal_status(
                            identifier,
                            status,
                            result=f"Synthetic {outcome} result for browser acceptance.",
                        )
                        if outcome in {"accepted", "rejected"}:
                            world.record_signoff(
                                identifier,
                                "approved" if outcome == "accepted" else "rejected",
                                decided_by=owner,
                                note="Synthetic named-human decision for local browser acceptance.",
                            )
                own["finished"] = True
        return {
            "synthetic": True,
            "provider_calls": 0,
            "pilot_ids": identifiers,
            "finished": own["finished"],
        }
