"""Disposable native task-result review journey; outbound services are blocked."""
from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

import server
from fastapi import HTTPException, Request


def main():
    server.exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server.CONFIG = server.CONFIG.replace('[features]', '[features]\ncopilot_operations = true').replace(
        'operation_families = ["learning", "commitments"]', 'operation_families = ["learning", "commitments", "reviews"]')
    with tempfile.TemporaryDirectory(prefix="lightwork-task-signoff-") as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        app = server.build_app(directory)
        from maverick.paths import tenant_scope
        from maverick_dashboard import api, auth

        observed = {"learning": [], "handoff": []}
        api._record_signoff_outcome = lambda _world, goal_id, decision: observed["learning"].append((goal_id, decision))
        api._handoff_approved_deliverable = lambda goal, actor: observed["handoff"].append((goal.id, actor))

        def owner(request):
            if auth.caller_principal(request) != "user:browser-reviewer":
                raise HTTPException(403, "Synthetic fixture owner required.")

        @app.post("/__browser_fixture/task-signoff/setup", include_in_schema=False)
        async def setup(request: Request):
            owner(request)
            body = await request.json()
            with tenant_scope(tenant="browser-workspace"):
                world = api._world()
                goal_id = world.create_goal("Review the synthetic cash forecast", "", domain="finance_cash13w", owner="user:browser-reviewer")
                world.set_goal_status(goal_id, "done", result="UNREVIEWED_SYNTHETIC_PREFACE\n| Week | Net |\n| --- | ---: |\n| W1 | 300 |\n| W2 | 100 |\n")
                if body.get("prior_reviewer"):
                    world.record_signoff(goal_id, "approved", decided_by="user:browser-colleague", note="Earlier review", expected_updated_at=world.get_goal(goal_id).updated_at)
                return {"goal_id": goal_id, "updated_at": world.get_goal(goal_id).updated_at}

        @app.post("/__browser_fixture/task-signoff/change/{goal_id}", include_in_schema=False)
        def change(request: Request, goal_id: int):
            owner(request)
            world = api._world()
            world.set_goal_status(goal_id, "done", result="| Week | Net |\n| --- | ---: |\n| W1 | 900 |\n")
            return {"changed": True}

        @app.post("/__browser_fixture/task-signoff/later-review/{goal_id}", include_in_schema=False)
        def later_review(request: Request, goal_id: int):
            owner(request)
            world = api._world()
            world.record_signoff(goal_id, "rejected", decided_by="user:browser-colleague", note="A later native review",
                                 expected_updated_at=world.get_goal(goal_id).updated_at)
            return {"reviewed": True}

        @app.get("/__browser_fixture/task-signoff/state/{goal_id}", include_in_schema=False)
        def state(request: Request, goal_id: int):
            owner(request)
            world = api._world()
            rows = world.query("SELECT operation_id,actor FROM goal_mutation_receipts WHERE goal_id=? AND kind='deliverable_signoff'", (goal_id,))
            return {"review": world.signoff_for(goal_id), "receipts": [dict(row) for row in rows],
                    "learning": [row for row in observed["learning"] if row[0] == goal_id],
                    "handoff": [row for row in observed["handoff"] if row[0] == goal_id], "external_calls": 0}

        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="critical", timeout_keep_alive=server.KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
