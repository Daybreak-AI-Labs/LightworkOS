"""One synthetic, shared-source proposal for real-browser admission checks."""
from __future__ import annotations


def install(app, world, tenant: str) -> None:
    from maverick.paths import tenant_scope

    state = {"goal_id": None}

    @app.post("/__browser_fixture/learned-skills/setup", include_in_schema=False)
    async def setup():
        from maverick.skill.distillation_local import save_skill

        with tenant_scope(tenant=tenant):
            if state["goal_id"] is None:
                state["goal_id"] = world.create_goal("Check customer renewal timing", owner="")
                save_skill({
                    "name": "customer-renewal-timing",
                    "triggers": ["check customer renewal timing"],
                    "tools_needed": [],
                    "summary": "Check customer renewal timing with the account owner",
                    "n_examples": 2,
                    "source_goal_ids": [state["goal_id"]],
                })
        return {"synthetic": True, "goal_id": state["goal_id"]}
