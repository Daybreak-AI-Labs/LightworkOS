"""Disposable native retention journey; only synthetic messages are deleted."""
from __future__ import annotations

import argparse
import tempfile
import time
from pathlib import Path

import server
from fastapi import HTTPException, Request


def main():
    server.exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server.CONFIG += '\n[retention]\nmessages_days = 30\n'
    server.CONFIG = server.CONFIG.replace('[features]', '[features]\ncopilot_operations = true').replace(
        'operation_families = ["learning", "commitments"]', 'operation_families = ["learning", "preferences"]')
    with tempfile.TemporaryDirectory(prefix="lightwork-retention-journey-") as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        from maverick.tenant.registry import create_tenant

        create_tenant("browser-workspace", display_name="Synthetic records workspace")
        app = server.build_app(directory)
        from maverick import audit
        from maverick.audit import retention
        from maverick_dashboard import api, auth, product_operations

        seen = set()
        for module in product_operations._adapter_modules():
            for entry in module.entries():
                if entry.id in seen or entry.family not in product_operations.FAMILIES:
                    raise RuntimeError(f"Fixture registry invalid: {module.__name__} {entry.id} {entry.family}")
                seen.add(entry.id)

        control = {"unknown": False, "audit_refused": False, "dispatches": 0, "race_goal": None, "writer_blocked": False}
        real_enforce, real_audit = retention.enforce, audit.audit_event

        def enforce(**kwargs):
            value = real_enforce(**kwargs)
            if not kwargs.get("dry_run"):
                control["dispatches"] += 1
                if control["unknown"]:
                    control["unknown"] = False
                    raise OSError("Synthetic lost native outcome after actual deletion")
            return value

        def record(kind, *args, **kwargs):
            return False if kind == "retention_review_accepted" and control["audit_refused"] else real_audit(kind, *args, **kwargs)

        retention.enforce, audit.audit_event = enforce, record
        from maverick import retention_review_bindings
        real_guard = retention_review_bindings.guard_sql

        def guard(connection, table, predicate, params, binding, **kwargs):
            # An ordinary independent SQLite writer arrives precisely after
            # candidate verification, before native DELETE. It must be blocked
            # by the native writer reservation, rather than an app-only fence.
            real_guard(connection, table, predicate, params, binding, **kwargs)
            if table == "messages" and not kwargs.get("dry_run") and control["race_goal"]:
                import sqlite3

                from maverick.world_model import default_db_path

                peer = sqlite3.connect(str(default_db_path()), timeout=0)
                try:
                    peer.execute("INSERT INTO messages(goal_id,role,content,ts) VALUES(?,?,?,?)",
                        (control["race_goal"], "user", "Synthetic arriving writer", time.time() - 60 * 86400))
                    peer.commit()
                    raise RuntimeError("The independent writer escaped retention reservation")
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc):
                        raise
                    control["writer_blocked"] = True
                finally:
                    peer.close()
                    control["race_goal"] = None

        retention_review_bindings.guard_sql = guard

        def owner(request):
            if auth.caller_principal(request) != "user:browser-reviewer":
                raise HTTPException(403, "Synthetic owner required")

        @app.post("/__browser_fixture/retention/setup", include_in_schema=False)
        async def setup(request: Request):
            owner(request)
            body = await request.json()
            world = api._world()
            identity = world.create_goal("Synthetic retention records", "", owner="user:browser-reviewer")
            for index in range(3):
                world.append_message(identity, "user", "Synthetic record " + str(index))
            with world._writing() as connection:
                connection.execute("UPDATE messages SET ts=? WHERE goal_id=? AND id IN (SELECT id FROM messages WHERE goal_id=? ORDER BY id LIMIT 2)",
                                   (time.time() - 60 * 86400, identity, identity))
            control["unknown"], control["audit_refused"] = bool(body.get("unknown")), bool(body.get("audit_refused"))
            control["race_goal"] = identity if body.get("race_writer") else None
            control["writer_blocked"] = False
            return {"goal_id": identity}

        @app.post("/__browser_fixture/retention/change/{identity}", include_in_schema=False)
        def change(request: Request, identity: int):
            owner(request)
            with api._world()._writing() as connection:
                connection.execute("UPDATE messages SET content=? WHERE goal_id=? AND ts<?",
                    ("Synthetic changed after preview", identity, time.time() - 30 * 86400))
            return {"changed": True}

        @app.get("/__browser_fixture/retention/state/{identity}", include_in_schema=False)
        def state(request: Request, identity: int):
            owner(request)
            rows = api._world().query("SELECT ts FROM messages WHERE goal_id=?", (identity,))
            return {"remaining": len(rows), "dispatches": control["dispatches"], "outbound_calls": 0, "writer_blocked": control["writer_blocked"]}

        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="critical", timeout_keep_alive=server.KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
