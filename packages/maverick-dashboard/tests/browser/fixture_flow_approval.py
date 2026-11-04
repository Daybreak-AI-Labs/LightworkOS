"""A disposable paused flow for an assignee's real dashboard review journey."""
from __future__ import annotations

from fastapi import HTTPException, Request
from maverick.flow import execution, store
from maverick.flow.ir import Flow, FlowNode
from maverick.paths import tenant_scope
from maverick_dashboard.auth import caller_principal


def install(app, tenant: str, reviewer: str) -> None:
    @app.post("/__browser_fixture/flow-approval/setup", include_in_schema=False)
    async def setup(request: Request):
        if caller_principal(request) != reviewer:
            raise HTTPException(403, "Only the synthetic reviewer can seed this fixture.")
        with tenant_scope(tenant=tenant):
            saved = store.save_flow(Flow(
                id="browser-assigned-approval", name="Payment review",
                owner="user:browser-colleague", start="gate",
                nodes={"gate": FlowNode(
                    id="gate", kind="approval",
                    prompt="Approve paying {{vendor}} {{amount}}?",
                    assignee=reviewer,
                )},
            ))
            store.publish_flow(
                saved.id,
                expected_version=saved.version,
                expected_revision=saved.revision,
            )

            def no_action(*_args):
                raise AssertionError("The fixture must never call a provider")

            paused = execution.execute(
                saved, owner="user:browser-colleague", record_outcomes=False,
                data={"vendor": "Acme Corp", "amount": 5000,
                      "owner_private": "OWNER-PRIVATE-DATA"},
                agent_runner=lambda *_args: ("", None),
                action_runner=no_action,
            )
        if paused.status != "paused_approval":
            raise HTTPException(500, "The fixture did not pause for review.")
        return {"synthetic": True, "flow_id": paused.flow_id,
                "run_id": paused.run_id, "provider_calls": 0}
