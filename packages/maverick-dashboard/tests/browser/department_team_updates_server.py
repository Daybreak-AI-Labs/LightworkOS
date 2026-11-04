"""Disposable native team catalog, manual roster edits and accepted receipts."""
from __future__ import annotations

import argparse
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

import server
from fastapi import Request


def main():
    server.exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server.CONFIG = server.CONFIG.replace('[features]', '[features]\ncopilot_operations = true').replace(
        'operation_families = ["learning", "commitments"]', 'operation_families = ["tasks"]')
    with tempfile.TemporaryDirectory(prefix="lightwork-team-updates-", ignore_cleanup_errors=True) as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        from maverick.departments import deploy_department, fleet_name_for, get_department
        from maverick.domain import available_domains
        from maverick.domain_edit import list_agents, write_override
        from maverick.fleet import FleetAgent, load_fleet, save_fleet
        from maverick.paths import tenant_scope
        from maverick.suite_grants import set_suites
        from maverick_dashboard import auth

        app = server.build_app(directory)
        tenant, owner, key = "browser-workspace", "user:browser-reviewer", "sales_gtm"
        name = fleet_name_for(key, owner)
        fork = "gtm_team_journey_specialist"
        with tenant_scope(tenant=tenant):
            rows = {row["name"]: row for row in list_agents()}
            dept = get_department(key)
            ready = [member for member in dept.members if rows[member]["readiness"]["state"] == "action_ready"]
            assert len(ready) > 1, "Native fixture needs two genuinely action-ready specialists."
            original = deploy_department(key, owner, save=False)
            kept = next(agent for agent in original.agents if agent.name == ready[0])
            removed = ready[1]
            save_fleet(replace(original, agents=(replace(kept, role="viewer", description="Preserve my customer review role"),
                        FleetAgent("meeting_assistant", "operator", "Manual meeting follow-up")),
                        department_members_added=tuple(dept.members)))
            write_override(fork, {"extends": ready[0], "description": "New customer follow-up specialist"}, expected_generation="new")
            set_suites("user:browser-colleague", ["procurement"], actor=owner)

        from maverick import audit
        stock_audit = audit.audit_event
        source_race = {"armed": False, "blocked": False, "finished": False, "error": ""}
        def observed_audit(event, **metadata):
            if event == "department_team_update_reviewed" and source_race["armed"]:
                source_race["armed"] = False
                started, finished = threading.Event(), threading.Event()
                def writer():
                    try:
                        with tenant_scope(tenant=tenant):
                            profile = available_domains()[fork]
                            started.set()
                            write_override(fork, {"extends": ready[0], "description": profile.description,
                                "persona": profile.persona + "\nA later catalog edit follows this accepted save."})
                    except Exception as exc:
                        source_race["error"] = type(exc).__name__
                    finally:
                        source_race["finished"] = True
                        finished.set()
                threading.Thread(target=writer, daemon=True).start()
                assert started.wait(2), "Native source writer did not start."
                source_race["blocked"] = not finished.wait(0.15)
                assert source_race["blocked"], "Native source mutation escaped the reviewed save fence."
            return stock_audit(event, **metadata)
        audit.audit_event = observed_audit

        @app.post("/__browser_fixture/department-team/arm-source-race", include_in_schema=False)
        def arm_source_race(request: Request):
            auth.require_global_permission(request, "admin")
            source_race.update(armed=True, blocked=False, finished=False, error="")
            return {"armed": True}

        @app.get("/__browser_fixture/department-team", include_in_schema=False)
        def state(request: Request):
            auth.require_global_permission(request, "admin")
            fleet = load_fleet(name)
            return {"department": key, "fork": fork, "removed": removed, "source_race": source_race,
                    "agents": [agent.to_dict() for agent in fleet.agents],
                    "receipts": list(fleet.department_update_receipts)}

        changes = {"roster": 0}

        @app.post("/__browser_fixture/department-team/change-roster", include_in_schema=False)
        def change_roster(request: Request):
            auth.require_global_permission(request, "admin")
            fleet = load_fleet(name)
            # An ordinary editor that omits receipt fields still retains them.
            data = fleet.to_dict()
            data.pop("department_update_receipts", None)
            from maverick.fleet import Fleet
            fresh = Fleet.from_dict(data)
            changes["roster"] += 1
            label = "Customer revised this job" + (" again" if changes["roster"] > 1 else "")
            save_fleet(replace(fresh, agents=tuple(replace(agent, description=label)
                        if agent.name == "meeting_assistant" else agent for agent in fresh.agents)))
            return {"changed": True}

        @app.post("/__browser_fixture/department-team/change-source", include_in_schema=False)
        def change_source(request: Request):
            auth.require_global_permission(request, "admin")
            profile = available_domains()[fork]
            # Instructions change while the saved roster's description is stable.
            write_override(fork, {"extends": ready[0], "description": profile.description,
                                  "persona": profile.persona + "\nUse the current customer follow-up instructions."})
            return {"changed": True}

        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="critical", timeout_keep_alive=server.KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
