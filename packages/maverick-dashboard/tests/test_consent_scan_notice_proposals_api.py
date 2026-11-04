from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import consent_scan_notice_proposals as proposals
from maverick_dashboard import consent_scan_notice_proposals_api as api

API = "/api/v1/consent/scan-notice-proposals"
NOW = 2_100_000_000.0
SIGNING_KEY = b"scan-proposal-test-signing-key-32-bytes-minimum"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _snapshot(
    *,
    label: str = "a",
    classification: str = "analytics",
) -> proposals.ReviewedScanSnapshot:
    discoveries = (
        proposals.ReviewedScanDiscovery(
            tracker_key=_digest(f"tracker-{label}"),
            classification=classification,
            kind="network",
            first_party=False,
            resource_type="script",
            review_version=2,
            review_sha256=_digest(f"review-{label}-v2"),
            evidence_sha256=_digest(f"review-evidence-{label}"),
            finding_evidence_sha256=_digest(f"finding-evidence-{label}"),
            valid_until=NOW + 50_000,
        ),
    )
    return proposals.ReviewedScanSnapshot(
        tenant_id="tenant-a",
        property_id="primary-web",
        report_id=f"report-reviewed-{label}",
        report_sha256=_digest(f"report-record-{label}"),
        scanner_report_sha256=_digest(f"scanner-report-{label}"),
        property_revision=4,
        property_sha256=_digest("property-a-v4"),
        inventory_revision=9 if label == "a" else 10,
        inventory_sha256=_digest(f"inventory-{label}"),
        classification_sha256=(
            proposals.ConsentScanNoticeProposalStore.classification_sha256(discoveries)
        ),
        completed_at=NOW - 100,
        valid_until=NOW + 50_000,
        complete=True,
        truncated=False,
        revoked=False,
        discoveries=discoveries,
    )


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {
        "enabled": True,
        "subject": "creator",
        "factory_calls": [],
        "permission_calls": [],
        "factory_error": None,
        "store_override": None,
        "snapshot": _snapshot(),
    }
    database = tmp_path / "scan-notice-proposals.sqlite3"
    ids = itertools.count(1)

    def require_enabled() -> None:
        if not state["enabled"]:
            raise proposals.NoticeProposalDisabled("private configuration detail")

    def tenant_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("tenant", permission))

    def global_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("global", permission))

    monkeypatch.setattr(proposals, "require_notice_proposals_enabled", require_enabled)
    monkeypatch.setattr(api, "_enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "require_permission", tenant_permission)
    monkeypatch.setattr(api, "require_global_permission", global_permission)

    def store_for(**kwargs):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append(kwargs)
        error = state["factory_error"]
        if isinstance(error, BaseException):
            raise error
        override = state["store_override"]
        if override is not None:
            return override
        return proposals.ConsentScanNoticeProposalStore(
            database,
            snapshot_resolver=lambda: state["snapshot"],
            actor_resolver=kwargs["actor_resolver"],
            signing_key_resolver=lambda _tenant: SIGNING_KEY,
            clock=lambda: NOW,
            id_factory=lambda prefix: f"{prefix}-{next(ids)}",
            gate=lambda: None,
        )

    deps = api.ConsentScanNoticeProposalDependencies(store_for=store_for)
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        if request.headers.get("X-Test-No-Principal") != "1":
            selected = request.headers.get("X-Test-Subject")
            subject = selected if selected is not None else str(state["subject"])
            request.state.principal = SimpleNamespace(principal=f"user:{subject}")
        return await call_next(request)

    app.include_router(
        api.create_consent_scan_notice_proposals_router(deps),
        prefix="/api/v1",
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    return client, database, state


def _create(client: TestClient, *, actor: str = "creator") -> dict:
    response = client.post(
        f"{API}/proposals",
        headers={"X-Test-Subject": actor},
        json={
            "expected_head_revision": 0,
            "idempotency_key": "proposal-create-a",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_status_is_store_free_honest_and_requires_authenticated_principal(
    environment, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _database, state = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200, response.text
    status = response.json()
    assert status["enabled"] is True
    assert status["status_invoked_inventory"] is False
    assert status["status_performed_network_io"] is False
    assert status["proposal_boundaries"]["legal_prose_generation"] is False
    assert status["proposal_boundaries"]["automatic_publication"] is False
    assert status["proposal_boundaries"]["provider_write"] is False
    assert status["inventory_adapter_boundaries"]["maximum_exact_discoveries"] == 10_000
    assert status["inventory_adapter_boundaries"]["inventory_cursor_pagination"] is True
    assert status["server_authority"] == {
        "store_factory_configured": True,
        "binding_resolver_configured": True,
        "revocation_resolver_configured": True,
        "signing_key_resolver_configured": True,
        "browser_may_select_tenant": False,
        "browser_may_select_property_or_report": False,
    }
    assert state["factory_calls"] == []
    assert "tenant_id" not in status
    assert "property_id" not in json.dumps(status)
    assert "report_id" not in json.dumps(status)

    state["enabled"] = False
    assert client.get(f"{API}/status").json()["enabled"] is False
    blocked = client.post(
        f"{API}/proposals",
        json={"expected_head_revision": 0, "idempotency_key": "disabled"},
    )
    assert blocked.status_code == 403
    assert blocked.json() == {"detail": "scan disclosure proposals are disabled"}
    assert "private" not in blocked.text
    assert state["factory_calls"] == []

    state["enabled"] = True
    monkeypatch.setattr("maverick_dashboard.auth.anonymous_local_access_allowed", lambda: False)
    monkeypatch.setattr("maverick_dashboard.auth._dashboard_token_authenticated", lambda _r: False)
    unauthenticated = client.get(
        f"{API}/status",
        headers={"X-Test-No-Principal": "1"},
    )
    assert unauthenticated.status_code == 401


def test_status_grants_a_synthetic_operator_ref_under_genuine_auth_off(environment) -> None:
    """A missing principal is not ALWAYS a 401: genuine local auth-off mode
    and a valid static dashboard bearer are both already-authenticated
    shapes require_permission() itself accepts."""
    client, _database, _state = environment
    response = client.get(
        f"{API}/status",
        headers={"X-Test-No-Principal": "1"},
    )
    assert response.status_code == 200


def test_hashed_principal_and_factory_never_receive_browser_scope(environment) -> None:
    client, _database, state = environment
    created = _create(client)
    expected = (
        "csnp-principal-"
        + hashlib.sha256(
            b"lightwork.consent-scan-notice-proposal.identity.v1:tenant-a:user:creator"
        ).hexdigest()[:32]
    )
    assert created["created_by_sha256"] == hashlib.sha256(expected.encode()).hexdigest()
    calls = state["factory_calls"]
    assert isinstance(calls, list) and calls
    call = calls[-1]
    assert call["tenant_id"] == "tenant-a"
    assert call["principal_ref"] == expected
    assert call["actor_resolver"]() == expected
    assert "property_id" not in call
    assert "report_id" not in call
    assert "inventory_revision" not in call

    state["subject"] = "操作者-Δ"
    status = client.get(f"{API}/status").json()
    expected_unicode = (
        "csnp-principal-"
        + hashlib.sha256(
            "lightwork.consent-scan-notice-proposal.identity.v1:tenant-a:user:操作者-Δ".encode()
        ).hexdigest()[:32]
    )
    assert status["principal_ref"] == expected_unicode
    assert "操作者" not in status["principal_ref"]


@pytest.mark.parametrize(
    "field",
    [
        "tenant_id",
        "principal_ref",
        "property_id",
        "report_id",
        "inventory_revision",
        "raw_scan_data",
        '"scanner_report":',
        "legal_copy",
        "notice_text",
        "signing_key",
        "provider_target",
        "site_target",
        "publication_target",
        "url",
    ],
)
def test_request_contract_rejects_authority_content_and_targets_generically(
    environment,
    field: str,
) -> None:
    client, _database, state = environment
    response = client.post(
        f"{API}/proposals",
        json={
            "expected_head_revision": 0,
            "idempotency_key": "unsafe-field",
            field: "private scan or legal content",
        },
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "scan disclosure-proposal request is invalid"}
    assert "private scan" not in response.text
    assert state["factory_calls"] == []


def test_strict_types_paths_and_local_acceptance_acknowledgement(environment) -> None:
    client, _database, _state = environment
    wrong_type = client.post(
        f"{API}/proposals",
        json={
            "expected_head_revision": "0",
            "idempotency_key": "wrong-type",
        },
    )
    assert wrong_type.status_code == 422
    assert wrong_type.json() == {"detail": "scan disclosure-proposal request is invalid"}
    invalid_path = client.get(f"{API}/proposals/%20private%20path")
    assert invalid_path.status_code == 422
    assert invalid_path.json() == {"detail": "scan disclosure-proposal request is invalid"}

    created = _create(client)
    approved = client.post(
        f"{API}/proposals/{created['proposal_id']}/approve",
        headers={"X-Test-Subject": "reviewer"},
        json={
            "expected_proposal_revision": 1,
            "idempotency_key": "approve-a",
        },
    ).json()
    missing_ack = client.post(
        f"{API}/proposals/{created['proposal_id']}/accept-local",
        headers={"X-Test-Subject": "acceptor"},
        json={
            "expected_proposal_revision": approved["proposal_revision"],
            "expected_head_revision": created["head_revision"],
            "idempotency_key": "accept-without-ack",
        },
    )
    assert missing_ack.status_code == 422


def test_full_three_person_lifecycle_idempotency_recovery_export_and_permissions(
    environment,
) -> None:
    client, database, state = environment
    created = _create(client)
    replay = _create(client)
    assert replay == created
    assert created["action"] == "desired"
    assert created["metadata"]["legal_prose_included"] is False
    assert created["metadata"]["disclosure_count"] == 1
    serialized = json.dumps(created)
    for forbidden in (
        "tracker.example",
        "https://",
        '"scanner_report":',
        "legal_copy",
        "publication_target",
    ):
        assert forbidden not in serialized

    self_approval = client.post(
        f"{API}/proposals/{created['proposal_id']}/approve",
        headers={"X-Test-Subject": "creator"},
        json={
            "expected_proposal_revision": 1,
            "idempotency_key": "self-approve",
        },
    )
    assert self_approval.status_code == 409
    assert self_approval.json() == {"detail": "scan disclosure-proposal state conflict"}

    approved_response = client.post(
        f"{API}/proposals/{created['proposal_id']}/approve",
        headers={"X-Test-Subject": "reviewer"},
        json={
            "expected_proposal_revision": 1,
            "idempotency_key": "approve-a",
        },
    )
    assert approved_response.status_code == 200, approved_response.text
    approved = approved_response.json()
    assert approved["proposal_state"] == "approved"
    same_reviewer_accept = client.post(
        f"{API}/proposals/{created['proposal_id']}/accept-local",
        headers={"X-Test-Subject": "reviewer"},
        json={
            "expected_proposal_revision": approved["proposal_revision"],
            "expected_head_revision": created["head_revision"],
            "acknowledge_local_baseline_only": True,
            "idempotency_key": "reviewer-accept",
        },
    )
    assert same_reviewer_accept.status_code == 409

    accepted_response = client.post(
        f"{API}/proposals/{created['proposal_id']}/accept-local",
        headers={"X-Test-Subject": "acceptor"},
        json={
            "expected_proposal_revision": approved["proposal_revision"],
            "expected_head_revision": created["head_revision"],
            "acknowledge_local_baseline_only": True,
            "idempotency_key": "accept-a",
        },
    )
    assert accepted_response.status_code == 200, accepted_response.text
    accepted = accepted_response.json()
    assert accepted["local_baseline_only"] is True
    assert accepted["published"] is False
    assert accepted["site_mutated"] is False

    fetched = client.get(f"{API}/proposals/{created['proposal_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["state"] == "locally_accepted"
    exported = client.post(
        f"{API}/proposals/{created['proposal_id']}/exports",
        headers={"X-Test-Subject": "exporter"},
        json={"idempotency_key": "export-a"},
    )
    assert exported.status_code == 201, exported.text
    assert exported.json()["payload"]["boundaries"]["automatic_publication"] is False
    assert SIGNING_KEY.decode() not in exported.text
    integrity = client.get(
        f"{API}/integrity",
        headers={"X-Test-Subject": "auditor"},
    )
    assert integrity.status_code == 200, integrity.text
    assert integrity.json()["valid"] is True

    state["snapshot"] = _snapshot(label="b", classification="advertising")
    reconciled = client.post(
        f"{API}/proposals",
        headers={"X-Test-Subject": "second-creator"},
        json={
            "expected_head_revision": accepted["head_revision"],
            "idempotency_key": "proposal-create-b",
        },
    ).json()
    assert reconciled["action"] == "reconcile"
    second_approved = client.post(
        f"{API}/proposals/{reconciled['proposal_id']}/approve",
        headers={"X-Test-Subject": "second-reviewer"},
        json={
            "expected_proposal_revision": reconciled["revision"],
            "idempotency_key": "approve-b",
        },
    ).json()
    second_accepted = client.post(
        f"{API}/proposals/{reconciled['proposal_id']}/accept-local",
        headers={"X-Test-Subject": "second-acceptor"},
        json={
            "expected_proposal_revision": second_approved["proposal_revision"],
            "expected_head_revision": reconciled["head_revision"],
            "acknowledge_local_baseline_only": True,
            "idempotency_key": "accept-b",
        },
    ).json()
    rollback = client.post(
        f"{API}/rollback-proposals/{created['proposal_id']}",
        headers={"X-Test-Subject": "rollback-author"},
        json={
            "expected_head_revision": second_accepted["head_revision"],
            "idempotency_key": "rollback-proposal-a",
        },
    )
    assert rollback.status_code == 201, rollback.text
    assert rollback.json()["action"] == "rollback"
    assert rollback.json()["rollback_target_proposal_id"] == created["proposal_id"]

    persisted = database.read_bytes()
    wal = Path(f"{database}-wal")
    if wal.exists():
        persisted += wal.read_bytes()
    assert SIGNING_KEY not in persisted
    assert b"tracker.example" not in persisted
    calls = state["permission_calls"]
    assert isinstance(calls, list)
    assert ("tenant", "view") in calls
    assert ("tenant", "operate") in calls
    assert ("global", "admin") in calls
    assert ("global", "audit") in calls


def test_approval_revocation_is_bound_to_original_approver(environment) -> None:
    client, _database, _state = environment
    created = _create(client)
    approved = client.post(
        f"{API}/proposals/{created['proposal_id']}/approve",
        headers={"X-Test-Subject": "reviewer"},
        json={
            "expected_proposal_revision": 1,
            "idempotency_key": "approve-revocable",
        },
    ).json()
    wrong_actor = client.post(
        f"{API}/proposals/{created['proposal_id']}/approval/revoke",
        headers={"X-Test-Subject": "other-admin"},
        json={
            "expected_proposal_revision": approved["proposal_revision"],
            "expected_approval_revision": approved["revision"],
            "idempotency_key": "wrong-revoker",
        },
    )
    assert wrong_actor.status_code == 409
    revoked = client.post(
        f"{API}/proposals/{created['proposal_id']}/approval/revoke",
        headers={"X-Test-Subject": "reviewer"},
        json={
            "expected_proposal_revision": approved["proposal_revision"],
            "expected_approval_revision": approved["revision"],
            "idempotency_key": "right-revoker",
        },
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["proposal_state"] == "proposed"


def test_integrity_unexpected_factory_and_unsafe_outputs_are_generic(environment) -> None:
    client, _database, state = environment

    class IntegrityStore:
        @staticmethod
        def get(_proposal_id: str):
            raise proposals.NoticeProposalIntegrityError("private row digest")

    state["store_override"] = IntegrityStore()
    integrity = client.get(f"{API}/proposals/CSNP-missing")
    assert integrity.status_code == 503
    assert integrity.json() == {"detail": "scan disclosure-proposal integrity verification failed"}
    assert "private row" not in integrity.text

    class UnexpectedStore:
        @staticmethod
        def get(_proposal_id: str):
            raise RuntimeError("database password and path")

    state["store_override"] = UnexpectedStore()
    unexpected = client.get(f"{API}/proposals/CSNP-missing")
    assert unexpected.status_code == 503
    assert unexpected.json() == {"detail": "scan disclosure-proposal operation failed"}
    assert "password" not in unexpected.text

    class UnsafeStore:
        @staticmethod
        def get(_proposal_id: str):
            return {"proposal_id": "CSNP-unsafe", "url": "https://private.example/path"}

    state["store_override"] = UnsafeStore()
    unsafe = client.get(f"{API}/proposals/CSNP-unsafe")
    assert unsafe.status_code == 503
    assert unsafe.json() == {"detail": "scan disclosure-proposal operation failed"}
    assert "private.example" not in unsafe.text

    state["store_override"] = None
    state["factory_error"] = RuntimeError("constructor secret")
    factory = client.get(f"{API}/proposals/CSNP-missing")
    assert factory.status_code == 503
    assert factory.json() == {"detail": "scan disclosure-proposal authority is unavailable"}
    assert "constructor secret" not in factory.text


def test_all_core_operations_are_mounted_and_adapter_has_no_network_client(environment) -> None:
    client, _database, _state = environment
    paths = set(client.app.openapi()["paths"])
    assert {
        f"{API}/status",
        f"{API}/proposals",
        f"{API}/proposals/{{proposal_id}}",
        f"{API}/rollback-proposals/{{target_proposal_id}}",
        f"{API}/proposals/{{proposal_id}}/approve",
        f"{API}/proposals/{{proposal_id}}/approval/revoke",
        f"{API}/proposals/{{proposal_id}}/accept-local",
        f"{API}/proposals/{{proposal_id}}/exports",
        f"{API}/integrity",
    } <= paths
    source = Path(api.__file__).read_text(encoding="utf-8")
    for method in (
        "propose",
        "propose_rollback",
        "get",
        "approve",
        "revoke_approval",
        "accept_local",
        "export_signed_metadata",
        "verify_integrity",
    ):
        assert f"store.{method}" in source
    for primitive in ("requests.", "httpx.", "urllib.request", "socket."):
        assert primitive not in source


def test_default_authority_fails_closed_without_server_resolvers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "_enabled", lambda: True)
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(proposals, "require_notice_proposals_enabled", lambda: None)
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:operator")
        return await call_next(request)

    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.get(f"{API}/proposals/CSNP-missing")
    assert response.status_code == 503
    assert response.json() == {"detail": "scan disclosure-proposal runtime is unavailable"}


def test_list_shows_stage_head_and_only_the_viewers_own_role(environment) -> None:
    client, _database, state = environment
    empty = client.get(f"{API}/proposals")
    assert empty.status_code == 200, empty.text
    assert empty.json() == {"head_revision": 0, "items": [], "truncated": False}

    created = _create(client)
    approved = client.post(
        f"{API}/proposals/{created['proposal_id']}/approve",
        headers={"X-Test-Subject": "reviewer"},
        json={"expected_proposal_revision": 1, "idempotency_key": "approve-list"},
    )
    assert approved.status_code == 200, approved.text

    as_creator = client.get(f"{API}/proposals", headers={"X-Test-Subject": "creator"}).json()
    assert as_creator["head_revision"] == created["head_revision"]
    row = as_creator["items"][0]
    assert row["proposal_id"] == created["proposal_id"]
    assert row["state"] == "approved"
    assert row["revision"] == 2
    assert row["disclosure_count"] == 1
    assert row["classification_counts"]["analytics"] == 1
    assert row["created_by_me"] is True
    assert row["approval"]["approved_by_me"] is False
    assert row["approval"]["revision"] == 1
    assert row["is_current"] is True and row["is_effective"] is False

    as_reviewer = client.get(f"{API}/proposals", headers={"X-Test-Subject": "reviewer"}).json()
    assert as_reviewer["items"][0]["created_by_me"] is False
    assert as_reviewer["items"][0]["approval"]["approved_by_me"] is True

    serialized = json.dumps(as_creator)
    for forbidden in ("actor_sha256", "created_by_sha256", "tenant", "tracker_key", "disclosures"):
        assert forbidden not in serialized
    assert ("tenant", "view") in state["permission_calls"]
