"""Synthetic pending approvals for the real Approvals page.

Only the disposable browser server imports this helper. No provider runs and
no action is executed: nothing consumes the decision.
"""
import time

from fastapi import HTTPException, Request
from maverick.approval_cards import build_approval_card, encode_approval_detail
from maverick.paths import tenant_scope
from maverick_dashboard.auth import caller_principal


def install(app, world, tenant, principal):
    def owner(request):
        if caller_principal(request) != principal:
            raise HTTPException(403, "Only the synthetic fixture owner can change fixture state.")

    @app.post("/__browser_fixture/approvals/setup", include_in_schema=False)
    async def setup(request: Request):
        owner(request)
        kind = request.query_params.get("kind", "")
        rehearsal = kind == "rehearsal"
        if kind not in ("", "rehearsal", "immediate"):
            raise HTTPException(422, "unsupported fixture kind")
        card = build_approval_card(
            action="write_file" if rehearsal else "salesforce.update_records",
            summary=("Lightwork has too little reliable experience with this step. Review it before work continues."
                     if rehearsal else "Update 12 Salesforce account records"),
            target_label="Task 42: save a file" if rehearsal else "Salesforce: 12 account records",
            target=({"goal_id": 42, "tool": "write_file"} if rehearsal
                    else {"object": "Account", "ids": ["001A", "001B"]}),
            parameters=({"goal_id": 42, "tool": "write_file", "arguments": {"path": "report.txt"}}
                        if rehearsal else {"field": "owner"}),
            parameter_summary=(["Allow Lightwork to save a file once in this task.",
                                "Other safety checks still apply."] if rehearsal
                               else ["Change the owner of 12 accounts to Priya"]),
            actor="user:browser-reviewer",
            workspace=tenant,
            role="operator",
            authority_versions={"role_revision": "role-v1"},
            input_versions={"crm_snapshot": "snap-1"},
            credential_versions={"salesforce_token_sha256": "a" * 64},
            budget={"currency": "USD", "maximum": 2.0},
            expires_at=time.time() + 3600,
            known_effects=(["Lightwork may try the reviewed step once."] if rehearsal
                           else ["Account owners change in Salesforce."]),
            unresolved_assumptions=(["Approval does not guarantee the step will succeed."]
                                    if rehearsal else []),
            before="The proposed step has not run." if rehearsal else "The 12 accounts belong to Sam.",
            after=("The reviewed step is eligible for the remaining safety checks."
                   if rehearsal else "The 12 accounts belong to Priya."),
            irreversible=True,
        )
        with tenant_scope(tenant=tenant):
            approval_id = world.create_approval(
                "write_file" if rehearsal else "salesforce.update_records", risk="high",
                scope="Task 42: save a file" if rehearsal else "Salesforce accounts",
                detail=encode_approval_detail(card), provenance="rehearsal" if rehearsal else "consent",
                requested_by=principal,
                # The default fixture models a consent requester still waiting
                # through the undo window. Other consumers do not promise that
                # hold, so their decisions must remain final.
                undoable=kind == "",
            )
        return {"synthetic": True, "approval_id": approval_id, "provider_calls": 0}
