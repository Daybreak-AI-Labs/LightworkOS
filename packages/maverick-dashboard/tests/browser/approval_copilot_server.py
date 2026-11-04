"""Disposable native queue/Copilot decision journey, no external execution."""
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
    server.CONFIG = server.CONFIG.replace('[features]', '[features]\ncopilot_operations = true').replace(
        'operation_families = ["learning", "commitments"]', 'operation_families = ["learning", "commitments", "reviews"]') + '\n[audit]\nsign = true\n'
    with tempfile.TemporaryDirectory(prefix="lightwork-approval-copilot-") as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        app = server.build_app(directory)
        from maverick import audit
        from maverick.approval_cards import build_approval_card, encode_approval_detail
        from maverick.paths import tenant_scope
        from maverick_dashboard import api, api_keys, auth

        mode = {"change": False, "late_claim": False, "hold_audit": False, "attempts": 0}
        original_ack, original_delivery = api._require_acknowledgement, api._audit_approval_decision
        original_vote = api._record_vote_or_raise

        def acknowledge(world, approval_id, payload, who, *, channel):
            original_ack(world, approval_id, payload, who, channel=channel)
            if mode["change"]:
                mode["change"] = False
                with world._writing() as conn:
                    conn.execute("UPDATE approvals SET risk = 'critical' WHERE id = ?", (approval_id,))

        def delivery(world, event):
            mode["attempts"] += 1
            return False if mode["hold_audit"] else original_delivery(world, event)

        api._require_acknowledgement, api._audit_approval_decision = acknowledge, delivery

        def vote(world, approval_id, status, who, **kwargs):
            if mode["late_claim"]:
                mode["late_claim"] = False
                world.claim_approval(approval_id, "user:browser-colleague")
            return original_vote(world, approval_id, status, who, **kwargs)

        api._record_vote_or_raise = vote

        def owner(request):
            if auth.caller_principal(request) != "user:browser-reviewer":
                raise HTTPException(403, "Synthetic fixture owner required.")

        @app.post("/__browser_fixture/approval-copilot/setup", include_in_schema=False)
        async def setup(request: Request):
            owner(request)
            body = await request.json()
            risk, required = body.get("risk", "high"), int(body.get("required", 1))
            legacy = body.get("legacy") is True
            card = build_approval_card(action="synthetic.update_records", summary="Update the three reviewed customer records",
                target_label="Three synthetic customer records", target={"ids": ["A", "B", "C"]},
                parameters={"private_argument": "synthetic-hidden-private-value"}, parameter_summary=["Assign these three records to Priya"],
                actor="user:browser-reviewer", workspace="browser-workspace", role="operator",
                authority_versions={"role": "synthetic-version"}, input_versions={"data": "reviewed-v1"},
                credential_versions={"connection": "b" * 64}, budget={"currency": "USD", "maximum": 2.0},
                expires_at=time.time() + 3600, known_effects=["The requested account owner changes."],
                unresolved_assumptions=["The downstream service may refuse the change."],
                before="The records are assigned to Sam.", after="The records are assigned to Priya.", irreversible=False)
            with tenant_scope(tenant="browser-workspace"):
                world = api._world()
                approval_id = world.create_approval("synthetic.update_records", risk=risk, scope="Synthetic customer records",
                    detail="Older review: reject and request a fresh card." if legacy else encode_approval_detail(card),
                    provenance="consent", approvals_required=required, requested_by="user:browser-reviewer")
            return {"synthetic": True, "approval_id": approval_id, "binding": card["binding_sha256"]}

        @app.post("/__browser_fixture/approval-copilot/mode", include_in_schema=False)
        async def set_mode(request: Request):
            owner(request)
            body = await request.json()
            mode["change"] = body.get("change") is True
            mode["late_claim"] = body.get("late_claim") is True
            mode["hold_audit"] = body.get("hold_audit") is True
            return {"synthetic": True}

        @app.get("/__browser_fixture/approval-copilot/state/{approval_id}", include_in_schema=False)
        def state(request: Request, approval_id: int):
            owner(request)
            world = api._world()
            return {"state": world.approval_state(approval_id), "delivery_attempts": mode["attempts"],
                    "events": [row for row in audit.default_audit_log().tail(1000) if row.get("approval_id") == approval_id],
                    "signed": audit.default_audit_log().signing_enabled, "external_calls": 0}

        @app.post("/__browser_fixture/approval-copilot/keys", include_in_schema=False)
        def keys(request: Request):
            owner(request)
            tokens = {}
            for kind, scope in (("approval", "approvals:decide"), ("task", "tasks:write")):
                _key, secret = api_keys.create_key(label="Synthetic " + kind, scopes=[scope], owner="user:browser-reviewer", created_by="user:browser-reviewer", workspace="browser-workspace")
                tokens[kind] = secret
            return tokens

        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="critical", timeout_keep_alive=server.KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
