"""Synthetic goal producers for the real pilot/browser learning boundary.

Only the disposable browser server imports this helper. No provider runs.
"""
from fastapi import HTTPException, Request
from maverick import pilot_learning
from maverick.paths import data_dir, tenant_scope
from maverick.trajectory_store import TrajectoryStep, TrajectoryStore
from maverick_dashboard import outcome_pilots
from maverick_dashboard.auth import caller_principal


def install(app, world, tenant, principal):
    prepared = set()

    def owner(request):
        if caller_principal(request) != principal:
            raise HTTPException(403, "Only the synthetic fixture owner can change fixture state.")

    def holdout(identifier):
        record = outcome_pilots.STORE.get(identifier)
        if not record or record.get("actor") != principal:
            raise HTTPException(404, "Synthetic pilot unavailable")
        selected = [int(case["reference"]) for case in record["cases"] if case["allocation"] == "holdout"]
        if not selected or any(int(case["reference"]) not in prepared for case in record["cases"]):
            raise HTTPException(409, "Only this fixture's prepared cases can be exercised.")
        return selected[0]

    @app.post("/__browser_fixture/pilot-learning/setup", include_in_schema=False)
    async def setup(request: Request):
        owner(request)
        with tenant_scope(tenant=tenant):
            goals = [world.create_goal("Learning fixture case " + str(index),
                     "Synthetic case; no model or customer outcome.", owner=principal) for index in range(1, 5)]
        prepared.update(goals)
        return {"synthetic": True, "goals": goals, "provider_calls": 0}

    @app.post("/__browser_fixture/pilot-learning/{identifier}/probe", include_in_schema=False)
    async def probe(identifier: str, request: Request):
        owner(request)
        with tenant_scope(tenant=tenant):
            parent = holdout(identifier)
            child = world.create_goal("Synthetic protected child", "No external work", parent_id=parent, owner=principal)
            development = world.create_goal("Synthetic development control", "No external work", owner=principal)
            store = TrajectoryStore(path=data_dir("browser-learning", identifier + ".ndjson"))
            held = store.record(TrajectoryStep(ts=1, goal_id=child, episode_id=1, step=1, role="worker"))
            allowed = store.record(TrajectoryStep(ts=1, goal_id=development, episode_id=2, step=1, role="worker"))
            return {"synthetic": True, "provider_calls": 0, "parent_excluded": pilot_learning.excluded(parent),
                    "child_excluded": pilot_learning.excluded(child), "held_capture": held,
                    "development_capture": allowed, "stored_goal_ids": [row.goal_id for row in store.iter_steps()],
                    "development_goal": development, "business_child_exists": world.get_goal(child) is not None}

    @app.post("/__browser_fixture/pilot-learning/{identifier}/change", include_in_schema=False)
    async def change(identifier: str, request: Request):
        owner(request)
        with tenant_scope(tenant=tenant):
            selected = holdout(identifier)
            world.set_goal_title(selected, "Changed synthetic evaluation input")
        return {"synthetic": True, "provider_calls": 0}
