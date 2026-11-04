from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import third_party_collaboration as collaboration
from maverick_dashboard import third_party_collaboration_api as api

INTERNAL = "/api/v1/third-party/collaboration"
EXTERNAL = "/api/v1/external/third-party-collaboration"
PORTAL = "portal_ref_1234567890"
TOKEN = "tpc1." + "A" * 43


class Store:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.invitation = {
            "schema": collaboration.INVITATION_SCHEMA,
            "tenant_id": "tenant-a",
            "invitation_id": "invite-1",
            "assessment_id": "assessment-1",
            "vendor_ref": "vendor-1",
            "respondent_ref": "vendor-respondent",
            "allowed_question_ids": ["security-control"],
            "notice_ref": "notice-v1",
            "notice_sha256": "a" * 64,
            "artifact_policy": {
                "allowed_kinds": ["audit_report"],
                "maximum_artifacts": 2,
                "maximum_total_bytes": 10_000,
            },
            "status": "active",
            "revision": 1,
        }

    def issue_invitation(self, tenant_id: str, invitation_id: str, **kwargs: Any):
        self.calls.append(("issue", tenant_id, invitation_id, kwargs))
        return collaboration.InvitationIssue(
            invitation=self.invitation,
            token=TOKEN,
            token_disclosed=True,
            idempotent_replay=False,
        )

    def list_invitations(self, tenant_id: str, **kwargs: Any):
        self.calls.append(("list", tenant_id, kwargs))
        return {
            "items": [self.invitation],
            "count": 1,
            "truncated": False,
            "next_after": None,
        }

    def get_invitation(self, tenant_id: str, invitation_id: str):
        self.calls.append(("get", tenant_id, invitation_id))
        return self.invitation

    def rotate_invitation(self, tenant_id: str, invitation_id: str, **kwargs: Any):
        self.calls.append(("rotate", tenant_id, invitation_id, kwargs))
        return collaboration.InvitationIssue(
            invitation={**self.invitation, "revision": 2},
            token="tpc1." + "B" * 43,
            token_disclosed=True,
            idempotent_replay=False,
        )

    def revoke_invitation(self, tenant_id: str, invitation_id: str, **kwargs: Any):
        self.calls.append(("revoke", tenant_id, invitation_id, kwargs))
        return {**self.invitation, "status": "revoked", "revision": 2}

    def request_follow_up(self, tenant_id: str, invitation_id: str, **kwargs: Any):
        self.calls.append(("follow_up", tenant_id, invitation_id, kwargs))
        return {**self.invitation, "status": "follow_up_required", "revision": 2}

    def reopen_follow_up(self, tenant_id: str, invitation_id: str, **kwargs: Any):
        self.calls.append(("reopen", tenant_id, invitation_id, kwargs))
        return self.rotate_invitation(tenant_id, invitation_id, **kwargs)

    def set_legal_hold(self, tenant_id: str, invitation_id: str, **kwargs: Any):
        self.calls.append(("hold", tenant_id, invitation_id, kwargs))
        return {**self.invitation, "legal_hold": kwargs["active"], "revision": 2}

    def purge_expired(self, tenant_id: str, **kwargs: Any):
        self.calls.append(("purge", tenant_id, kwargs))
        return {"invitations": 0, "drafts": 0}

    def verify_integrity(self, tenant_id: str):
        self.calls.append(("integrity", tenant_id))
        return collaboration.CollaborationIntegrityVerification(
            tenant_id=tenant_id,
            verified_records=4,
            history_events=1,
            terminal_history_sha256="c" * 64,
        )

    def contract_for_token(self, tenant_id: str, token: str):
        self.calls.append(("contract", tenant_id, token))
        if token != TOKEN:
            raise collaboration.ThirdPartyCollaborationAuthError("invalid invitation")
        return {
            "schema": collaboration.CONTRACT_SCHEMA,
            "tenant_id": tenant_id,
            "invitation_id": "invite-1",
            "vendor_ref": "vendor-1",
            "assessment_id": "assessment-1",
            "notice_ref": "notice-v1",
            "notice_sha256": "a" * 64,
            "artifact_policy": self.invitation["artifact_policy"],
            "questions": [
                {
                    "question_id": "security-control",
                    "domain": "security",
                    "prompt_ref": "prompt-security-control",
                    "response_type": "boolean",
                    "required": True,
                    "options": [],
                }
            ],
            "required_question_ids": ["security-control"],
            "answered_question_ids": [],
            "draft_revision": 0,
            "draft_artifacts": [],
            "expires_at": 2_000_086_400.0,
            "limitations": [
                "respondent_attestations_are_unverified",
                "artifact_manifests_only_no_upload_bytes",
                "no_network_or_email_delivery",
                "no_model_inference",
            ],
        }

    def save_draft(self, tenant_id: str, token: str, **kwargs: Any):
        self.calls.append(("draft", tenant_id, token, kwargs))
        return {
            "tenant_id": tenant_id,
            "invitation_id": "invite-1",
            "revision": 1,
            "draft_sha256": "d" * 64,
            "active_question_ids": ["security-control"],
            "required_question_ids": ["security-control"],
            "artifact_count": len(kwargs["artifacts"]),
            "idempotent_replay": False,
        }

    def finalize_submission(self, tenant_id: str, token: str, **kwargs: Any):
        self.calls.append(("finalize", tenant_id, token, kwargs))
        return {
            "schema": collaboration.RECEIPT_SCHEMA,
            "tenant_id": tenant_id,
            "invitation_id": "invite-1",
            "assessment_id": "assessment-1",
            "assessment_revision": 3,
            "assessment_integrity_sha256": "e" * 64,
            "question_ids": ["security-control"],
            "attestation_sha256": "f" * 64,
            "evidence_status": "respondent_attestation_unverified",
            "idempotent_replay": False,
        }


@pytest.fixture()
def environment(monkeypatch: pytest.MonkeyPatch):
    state: dict[str, Any] = {
        "enabled": True,
        "tenant": "tenant-a",
        "permissions": [],
        "factories": [],
        "resolvers": [],
        "rate": [],
    }
    store = Store()

    def require_enabled() -> None:
        if not state["enabled"]:
            raise collaboration.ThirdPartyCollaborationConfigError("disabled")

    monkeypatch.setattr(collaboration, "enabled", lambda: state["enabled"] is True)
    monkeypatch.setattr(collaboration, "require_enabled", require_enabled)
    monkeypatch.setattr(api, "_tenant_id", lambda: state["tenant"])
    monkeypatch.setattr(
        api,
        "require_permission",
        lambda _request, permission: state["permissions"].append(permission),
    )

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            principal=request.headers.get("X-Test-Principal", "owner")
        )
        return await call_next(request)

    def store_factory(tenant_id: str, principal_ref: str):
        state["factories"].append((tenant_id, principal_ref))
        return store

    def portal_resolver(portal_ref: str, request: Request):
        state["resolvers"].append((portal_ref, request.url.path))
        return api.ExternalPortalAuthority(tenant_id="tenant-a", store=store)

    def rate_limit(credential_sha256: str, action: str) -> None:
        state["rate"].append((credential_sha256, action))

    dependencies = api.ThirdPartyCollaborationDependencies(
        store_for=store_factory,
        portal_resolver=portal_resolver,
        external_rate_limit=rate_limit,
    )
    app.include_router(api.create_third_party_collaboration_router(dependencies), prefix="/api/v1")
    app.include_router(api.create_external_third_party_collaboration_router(dependencies))
    return TestClient(app, base_url="http://127.0.0.1"), store, state


def issue_body() -> dict[str, Any]:
    return {
        "invitation_id": "invite-1",
        "assessment_id": "assessment-1",
        "respondent_ref": "vendor-respondent",
        "allowed_question_ids": ["security-control"],
        "notice_ref": "notice-v1",
        "notice_sha256": "a" * 64,
        "artifact_policy": {
            "allowed_kinds": ["audit_report"],
            "maximum_artifacts": 2,
            "maximum_total_bytes": 10_000,
        },
        "expires_in_seconds": 86_400,
        "retention_seconds": 172_800,
        "idempotency_key": "issue-one",
    }


def invitation_headers(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"ThirdPartyInvitation {token}"}


def test_internal_surface_derives_tenant_and_returns_credential_once_privately(environment) -> None:
    client, store, state = environment
    forged = client.post(
        f"{INTERNAL}/invitations",
        json={**issue_body(), "tenant_id": "tenant-b", "actor_ref": "attacker"},
    )
    assert forged.status_code == 422
    assert store.calls == []

    created = client.post(f"{INTERNAL}/invitations", json=issue_body())
    assert created.status_code == 201, created.text
    assert created.headers["cache-control"] == "no-store, private"
    assert created.json()["token"] == TOKEN
    assert store.calls[0][1:3] == ("tenant-a", "invite-1")
    assert state["factories"][0][0] == "tenant-a"
    assert state["factories"][0][1].startswith("tpc-principal-")
    assert state["permissions"][-1] == "admin"

    listed = client.get(f"{INTERNAL}/invitations")
    assert listed.status_code == 200
    assert "token" not in repr(listed.json())
    assert "token_sha256" not in repr(listed.json())


def test_external_surface_uses_token_header_public_ref_and_strips_tenant(environment) -> None:
    client, store, state = environment
    assert client.get(f"{EXTERNAL}/{PORTAL}/contract").status_code == 404
    assert (
        client.get(
            f"{EXTERNAL}/{PORTAL}/contract?tenant_id=tenant-a",
            headers=invitation_headers(),
        ).status_code
        == 404
    )
    assert state["resolvers"] == []

    contract = client.get(
        f"{EXTERNAL}/{PORTAL}/contract",
        headers=invitation_headers(),
    )
    assert contract.status_code == 200, contract.text
    assert contract.headers["cache-control"] == "no-store, private"
    assert "tenant_id" not in contract.json()
    assert "risk_rules" not in repr(contract.json())
    assert state["resolvers"] == [(PORTAL, f"{EXTERNAL}/{PORTAL}/contract")]
    assert state["rate"][0][1] == "contract"
    assert state["rate"][0][0] != TOKEN

    rejected = client.put(
        f"{EXTERNAL}/{PORTAL}/draft",
        headers=invitation_headers(),
        json={
            "answers": {
                "security-control": {"value": True, "artifact_ids": []},
            },
            "artifacts": [],
            "expected_revision": 0,
            "idempotency_key": "draft-one",
            "tenant_id": "tenant-b",
            "token": TOKEN,
        },
    )
    assert rejected.status_code == 422

    draft = client.put(
        f"{EXTERNAL}/{PORTAL}/draft",
        headers=invitation_headers(),
        json={
            "answers": {
                "security-control": {"value": True, "artifact_ids": []},
            },
            "artifacts": [],
            "expected_revision": 0,
            "idempotency_key": "draft-one",
        },
    )
    assert draft.status_code == 200, draft.text
    assert "tenant_id" not in draft.json()
    draft_call = next(call for call in store.calls if call[0] == "draft")
    assert draft_call[1:3] == ("tenant-a", TOKEN)

    unverified = client.post(
        f"{EXTERNAL}/{PORTAL}/finalize",
        headers=invitation_headers(),
        json={
            "answers": {
                "security-control": {"value": True, "artifact_ids": []},
            },
            "artifacts": [],
            "attested": False,
            "expected_draft_revision": 1,
            "idempotency_key": "final-one",
        },
    )
    assert unverified.status_code == 422
    final = client.post(
        f"{EXTERNAL}/{PORTAL}/finalize",
        headers=invitation_headers(),
        json={
            "answers": {
                "security-control": {"value": True, "artifact_ids": []},
            },
            "artifacts": [],
            "attested": True,
            "expected_draft_revision": 1,
            "idempotency_key": "final-one",
        },
    )
    assert final.status_code == 200, final.text
    assert "tenant_id" not in final.json()
    assert final.json()["evidence_status"] == "respondent_attestation_unverified"


def test_external_response_contract_rejects_nested_or_unknown_authority_data(
    environment,
) -> None:
    client, store, _state = environment
    original = store.contract_for_token

    def compromised_contract(tenant_id: str, token: str):
        result = dict(original(tenant_id, token))
        result["questions"] = [
            {
                **result["questions"][0],
                "provider_credential": "secret-provider-token",
            }
        ]
        result["internal_risk_rules"] = {"tenant_id": "tenant-b"}
        return result

    store.contract_for_token = compromised_contract  # type: ignore[method-assign]
    response = client.get(
        f"{EXTERNAL}/{PORTAL}/contract",
        headers=invitation_headers(),
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "invitation authority unavailable"}
    assert "secret-provider-token" not in response.text
    assert "tenant-b" not in response.text


def test_external_failures_are_non_enumerating_and_disabled_is_hidden(environment) -> None:
    client, _store, state = environment
    wrong = client.get(
        f"{EXTERNAL}/{PORTAL}/contract",
        headers=invitation_headers("tpc1." + "Z" * 43),
    )
    assert wrong.status_code == 404
    assert wrong.json()["detail"] == "invitation unavailable"
    state["enabled"] = False
    disabled = client.get(
        f"{EXTERNAL}/{PORTAL}/contract",
        headers=invitation_headers(),
    )
    assert disabled.status_code == 404
    assert disabled.json()["detail"] == "invitation unavailable"
    status = client.get(f"{INTERNAL}/status")
    assert status.status_code == 200
    assert status.json()["enabled"] is False


def test_sharing_reports_portal_address_and_limits_for_admins(environment, monkeypatch) -> None:
    client, _store, state = environment
    monkeypatch.setattr(collaboration, "load_policy", lambda: collaboration.ThirdPartyCollaborationPolicy())
    client.app.state.third_party_collaboration_current_portal_ref = lambda: PORTAL
    body = client.get(f"{INTERNAL}/sharing").json()
    assert body["portal_path"] == f"{EXTERNAL}/{PORTAL}/portal"
    assert set(body["limits"]) == {"invitation_seconds", "retention_seconds", "max_artifacts",
                                   "max_artifact_bytes"}
    assert state["permissions"][-1] == "admin"
    assert TOKEN not in repr(body)


def test_sharing_without_a_portal_still_reports_limits(environment, monkeypatch) -> None:
    client, _store, _state = environment
    monkeypatch.setattr(collaboration, "load_policy", lambda: collaboration.ThirdPartyCollaborationPolicy())

    def broken():
        raise RuntimeError("no routing key")

    client.app.state.third_party_collaboration_current_portal_ref = broken
    body = client.get(f"{INTERNAL}/sharing").json()
    assert body["portal_path"] is None and body["limits"]["max_artifacts"] >= 0


def test_sharing_is_off_with_the_feature(environment) -> None:
    client, _store, state = environment
    state["enabled"] = False
    assert client.get(f"{INTERNAL}/sharing").status_code == 403
