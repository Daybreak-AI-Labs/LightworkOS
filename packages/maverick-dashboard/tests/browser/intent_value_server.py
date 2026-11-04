"""Isolated real dashboard for the work-value journey; outbound calls blocked."""
from __future__ import annotations

import argparse
import tempfile
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

import server


def install_execution_fixture(app):
    """Keep native workflow controls; stub the agent runner and its paid calls."""
    from maverick import audit, runner
    from maverick_dashboard import api

    calls = []

    def synthetic_provider(gid, **kwargs):
        world = api._world()
        calls.append(gid)
        eid = world.start_episode(gid)
        result = "Synthetic financial analysis: supplied revenue exceeds expenses by 20. Human review required."
        world.end_episode(eid, result, "success", cost_dollars=1)
        world.set_goal_status(gid, "done", result=result)
        audit.audit_event("goal_end", goal_id=gid, agent="orchestrator", status="succeeded")
        kwargs["usage_observer"](1)
        return result

    runner.run_goal_in_thread = synthetic_provider

    @app.post("/__browser_fixture/intent-value-execution", include_in_schema=False)
    def seed_execution():
        world = api._world()
        for _ in range(4):
            gid = world.create_goal("Analyze financial analysis", owner="user:browser-reviewer")
            if _ < 3:
                eid = world.start_episode(gid)
                world.end_episode(eid, "Synthetic prior analysis", "success", cost_dollars=2)
                world.set_goal_status(gid, "done")
                audit.audit_event("goal_end", goal_id=gid, agent="orchestrator", status="succeeded")
        return {"synthetic": True, "provider_calls": len(calls)}

    @app.get("/__browser_fixture/intent-value-execution", include_in_schema=False)
    def execution_state():
        return {"synthetic": True, "provider_calls": len(calls)}

    @app.post("/__browser_fixture/intent-value-ekko", include_in_schema=False)
    def seed_ekko():
        """Use the real consented store and discovery path with synthetic events."""
        from maverick.config import get_ekko_policy
        from maverick.work_discovery import SessionState, WorkEvent
        from maverick.work_discovery_store import WorkDiscoveryStore

        store = WorkDiscoveryStore("user:browser-reviewer", "local-device")
        first_day = datetime.now(timezone.utc).date() - timedelta(days=2)
        base = datetime.combine(first_day, time(hour=12), tzinfo=timezone.utc).timestamp()
        policy = get_ekko_policy()
        store.enroll(policy, at=base - 1)
        for day in range(2):
            started = base + day * 86_400
            session = store.create_session(
                policy=policy, session_id=f"browser-repeat-{day}", started_at=started,
            )
            collector = f"browser-collector-{day}"
            store.claim_collector(session.session_id, collector, policy=policy, ttl_seconds=30)
            for sequence, app_name, offset, duration in (
                (1, "excel", 10, 120), (2, "powerpoint", 140, 480),
            ):
                store.append_event(WorkEvent(
                    event_id=f"browser-event-{day}-{sequence}", session_id=session.session_id,
                    sequence=sequence, occurred_at=started + offset, app=app_name,
                    action="switch", object_type="none", duration_seconds=duration,
                ), policy=policy, collector_id=collector)
            store.transition_session(session.session_id, SessionState.STOPPED, at=started + 700)
        return {"synthetic": True, "candidates": len(store.governed_candidate_projection()["candidates"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server.CONFIG = server.CONFIG.replace('[features]', '[features]\ncopilot_operations=true')
    server.CONFIG += '\n[value]\nhourly_rate=60.0\n[audit]\nsign=true\n'
    server.CONFIG += '\n[ekko]\nenable=true\nplanning_enabled=true\nbuild_enabled=true\nallowed_apps=["excel", "powerpoint"]\nmin_occurrences=2\nmin_distinct_days=2\n'
    with tempfile.TemporaryDirectory(prefix="lightwork-intent-value-") as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        app = server.build_app(directory)
        install_execution_fixture(app)
        from maverick import audit
        from maverick.paths import tenant_scope
        from maverick_dashboard import api

        with tenant_scope(tenant="browser-workspace"):
            world = api._world()
            for index in range(4):
                gid = world.create_goal("Draft an RFP", owner="user:browser-reviewer")
                if index < 3:
                    eid = world.start_episode(gid)
                    world.end_episode(eid, "Synthetic fixture", "success", cost_dollars=2)
                    world.set_goal_status(gid, "done")
                    audit.audit_event("goal_end", goal_id=gid, agent="orchestrator", status="succeeded")

        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="critical",
                    timeout_keep_alive=server.KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
