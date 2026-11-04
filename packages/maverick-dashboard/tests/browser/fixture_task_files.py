"""Synthetic local files only; this helper is never loaded by the product."""
from pathlib import Path
from tempfile import TemporaryDirectory


def install(app, world, tenant, principal):
    from maverick import task_file_recovery as recovery
    from maverick.paths import tenant_scope
    from maverick.sandbox.local import LocalBackend
    from maverick.tools.fs import write_text_contained

    storage = TemporaryDirectory(prefix="lightwork-browser-task-files-")
    app.state.synthetic_task_file_directory = storage
    root = Path(storage.name)
    target = root / "customer-draft.txt"
    target.write_text("Synthetic original customer draft\n")
    with tenant_scope(tenant=tenant):
        goal = world.create_goal("Synthetic captured file task", owner=principal)
    sandbox = LocalBackend(root)

    @app.get("/__task_file_fixture", include_in_schema=False)
    async def status():
        return {"goal_id": goal, "content": target.read_text(), "synthetic": True}

    @app.post("/__task_file_fixture/run", include_in_schema=False)
    async def run():
        with tenant_scope(tenant=tenant):
            with recovery.run_scope(world, goal, sandbox):
                recovery.begin_capture(world, goal)
                write_text_contained(sandbox, target, "Synthetic task revision\n")
            world.set_goal_status(goal, "done", result="Synthetic local write complete")
        return {"synthetic": True}

    @app.post("/__task_file_fixture/edit", include_in_schema=False)
    async def edit():
        target.write_text("Synthetic manual correction after review\n")
        return {"synthetic": True}
