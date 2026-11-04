"""Disposable native department boards, prices and changing grant authority."""
from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

import server
from fastapi import Request


def main():
    server.exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server.CONFIG = server.CONFIG.replace('[features]', '[features]\ncopilot_operations = true').replace(
        'operation_families = ["learning", "commitments"]', 'operation_families = ["tasks", "budget"]')
    with tempfile.TemporaryDirectory(prefix="lightwork-department-boards-") as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        from maverick.domain import available_domains
        from maverick.domain_edit import write_override
        from maverick.paths import tenant_scope
        from maverick.suite_grants import set_suites
        from maverick.tenant.registry import create_tenant
        from maverick_dashboard import auth

        create_tenant("browser-workspace", display_name="Synthetic board workspace")
        app = server.build_app(directory)
        from maverick_dashboard._shared import _world
        with tenant_scope(tenant="browser-workspace"):
            world = _world()
            packs = available_domains()
            allowed = next(name for name in sorted(packs) if name.startswith("proc_"))
            refused = next(name for name in sorted(packs) if name.startswith("finance_"))
            fork = "board_fixture_specialist"
            write_override(fork, {"extends": allowed}, expected_generation="new")
            owner = "user:browser-colleague"
            set_suites(owner, ["procurement"], actor="user:browser-reviewer")
            set_suites("user:browser-outcome-owner", ["procurement"], actor="user:browser-reviewer")
            def finished(title, domain, who, price):
                goal = world.create_goal(title, domain=domain, owner=who)
                world.set_goal_status(goal, "done", result="Private synthetic result " + title)
                episode = world.start_episode(goal)
                world.end_episode(episode, "Private synthetic summary", "success", cost_dollars=price,
                                  input_tokens=10, output_tokens=2, tool_calls=1)
                return goal
            allowed_goal = finished("Prepare the supplier review", fork, owner, 2.0)
            general_goal = finished("Plan my week", "", owner, None)
            for unsupported in (float("inf"), -1.0):
                world.end_episode(world.start_episode(allowed_goal), "Synthetic unsupported historical price",
                                  "success", cost_dollars=unsupported)
            refused_goal = finished("Private finance forecast", refused, owner, 999.0)
            foreign_goal = finished("Another employee private negotiation", allowed, "user:browser-outcome-owner", 777.0)
            removed_goal = finished("Removed specialist private work", "proc_missing_fixture", owner, 444.0)
            running = world.create_goal("Follow up with our supplier", domain=allowed, owner=owner)
            world.start_episode(running)
            world.set_goal_status(running, "active")
            from maverick.logging_config import reset_goal_context, set_goal_context
            for identifier, label in ((allowed_goal, "Review the supplier commitment"),
                                      (refused_goal, "Private finance payment approval"),
                                      (foreign_goal, "Other employee confidential approval")):
                tokens = set_goal_context(goal_id=identifier)
                try:
                    world.create_approval("send", detail=label, requested_by=world.get_goal(identifier).owner)
                finally:
                    reset_goal_context(tokens)

        @app.post("/__browser_fixture/department-boards/stops", include_in_schema=False)
        def seed_stops(request: Request):
            auth.require_global_permission(request, "admin")
            from maverick.goal_stop import stop
            for title, domain, who in (("Stop my supplier follow-up", allowed, owner),
                                       ("Private stopped finance work", refused, owner),
                                       ("Other employee stopped confidential work", allowed, "user:browser-outcome-owner")):
                identifier = world.create_goal(title, domain=domain, owner=who)
                world.set_goal_status(identifier, "active")
                goal = world.get_goal(identifier)
                stop(world, identifier, actor=who, operation_id="browser_board_stop_" + str(identifier),
                     expected_updated_at=goal.updated_at, expected_owner=who)
            return {"created": True}

        # Deterministic interruption at the native projection/read boundary:
        # the real workspace fork changes inherited department, not a fake ACL.
        from maverick_dashboard import department_boards
        original_spend = department_boards._spend
        pending = {"change_pack": False}
        def interrupt_projection(request, native_world, native_owner, days, goals=None):
            projection = original_spend(request, native_world, native_owner, days, goals)
            if pending["change_pack"]:
                pending["change_pack"] = False
                write_override(fork, {"extends": refused})
            return projection
        department_boards._spend = interrupt_projection

        @app.post("/__browser_fixture/department-boards/pack-race", include_in_schema=False)
        def arm(request: Request):
            auth.require_global_permission(request, "admin")
            pending["change_pack"] = True
            return {"armed": True}

        @app.post("/__browser_fixture/department-boards/restore-pack", include_in_schema=False)
        def restore(request: Request):
            auth.require_global_permission(request, "admin")
            write_override(fork, {"extends": allowed})
            return {"restored": True}

        @app.post("/__browser_fixture/department-boards/change-grant", include_in_schema=False)
        def change(request: Request):
            auth.require_global_permission(request, "admin")
            set_suites(owner, ["finance"], actor=auth.caller_principal(request))
            return {"changed": True}

        @app.post("/__browser_fixture/department-boards/role", include_in_schema=False)
        def role(request: Request, body: dict):
            auth.require_global_permission(request, "admin")
            from maverick_dashboard import rbac
            if body.get("role") not in {"operator", "viewer"}:
                from fastapi import HTTPException
                raise HTTPException(422, "Choose a fixture operator or viewer.")
            rbac.set_tenant_role("browser-workspace", owner, body["role"], actor=auth.caller_principal(request))
            return {"changed": True}

        @app.get("/__browser_fixture/department-boards", include_in_schema=False)
        def selected(request: Request):
            auth.require_permission(request, "view")
            return {"allowed": allowed_goal, "general": general_goal, "refused": refused_goal,
                    "foreign": foreign_goal, "removed": removed_goal, "running": running}

        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="critical", timeout_keep_alive=server.KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
