from __future__ import annotations

import itertools
import sqlite3
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick.policy_publication_links import PolicyPublicationStore
from maverick_dashboard.policy_publication_links_api import (
    PolicyPublicationDependencies,
    PublicLinkRegistryError,
    PublicPolicyLinkRegistry,
    PublicPolicyRateLimiter,
    PublicPolicyRateLimitExceeded,
    create_policy_publication_routers,
)

NOW = 1_800_000_000.0
ADMIN = "/api/v1/policy-publication-links"
PUBLIC = "/api/v1/public/policies"


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class Capabilities:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> str:
        self.value += 1
        return chr(64 + self.value) * 43


@pytest.fixture()
def environment(tmp_path: Path):
    clock = Clock()
    identifiers = itertools.count(1)
    capabilities = Capabilities()
    tenant = {"value": "tenant-a"}
    stores: dict[str, PolicyPublicationStore] = {}

    def store_for(tenant_id: str) -> PolicyPublicationStore:
        if tenant_id not in stores:
            stores[tenant_id] = PolicyPublicationStore(
                tmp_path / f"{tenant_id}.sqlite3",
                clock=clock,
                id_factory=lambda prefix: f"{prefix}-{next(identifiers):08d}",
                capability_factory=capabilities,
                config_gate=lambda: True,
            )
        return stores[tenant_id]

    registry = PublicPolicyLinkRegistry(tmp_path / "registry.sqlite3", clock=clock)
    rate_limiter = PublicPolicyRateLimiter(
        per_key=50,
        global_limit=1_000,
        max_keys=100,
        clock=clock,
    )
    dependencies = PolicyPublicationDependencies(
        tenant_resolver=lambda: tenant["value"],
        store_for=store_for,
        registry_factory=lambda: registry,
        actor_resolver=lambda request: request.headers.get("x-test-actor", "actor-a"),
        rate_limiter=rate_limiter,
    )
    admin_router, public_router = create_policy_publication_routers(dependencies)
    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    app.include_router(public_router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Actor": "actor-a"},
    )
    return client, stores, registry, clock, tenant, tmp_path


def _ok(response, expected: int = 200):
    assert response.status_code == expected, response.text
    return response.json()


def _artifact(
    client: TestClient,
    *,
    policy_id: str = "security-policy",
    approval_mode: str = "none",
    body_text: str = "Use approved systems only.",
) -> dict:
    return _ok(
        client.post(
            f"{ADMIN}/artifacts",
            json={
                "policy_id": policy_id,
                "version": 1,
                "title": "Information Security Policy",
                "body_text": body_text,
                "approval_mode": approval_mode,
                "idempotency_key": f"artifact-{policy_id}-v1",
            },
        ),
        201,
    )


def _link(
    client: TestClient,
    *,
    policy_id: str = "security-policy",
    visibility: str = "public",
) -> dict:
    return _ok(
        client.post(
            f"{ADMIN}/links",
            json={
                "policy_id": policy_id,
                "visibility": visibility,
                "idempotency_key": f"link-{policy_id}-{visibility}",
            },
        ),
        201,
    )


def _publish(client: TestClient, link_id: str, *, key: str = "publish-v1") -> dict:
    return _ok(
        client.post(
            f"{ADMIN}/links/{link_id}/publish",
            json={
                "version": 1,
                "expected_pointer_revision": 0,
                "idempotency_key": key,
            },
        )
    )


def test_tenant_is_server_derived_and_four_eyes_are_independent(environment) -> None:
    client, _stores, _registry, _clock, _tenant, _tmp = environment
    forged = client.post(
        f"{ADMIN}/artifacts",
        json={
            "tenant_id": "tenant-b",
            "policy_id": "forged",
            "version": 1,
            "title": "Forged",
            "body_text": "Not accepted.",
            "approval_mode": "none",
            "idempotency_key": "forged-v1",
        },
    )
    assert forged.status_code == 422

    _artifact(client, policy_id="four-eyes", approval_mode="four_eyes")
    self_review = client.post(
        f"{ADMIN}/artifacts/four-eyes/versions/1/reviews",
        json={"decision": "approve", "idempotency_key": "self-review"},
    )
    assert self_review.status_code == 409
    first = _ok(
        client.post(
            f"{ADMIN}/artifacts/four-eyes/versions/1/reviews",
            headers={"X-Test-Actor": "reviewer-b"},
            json={"decision": "approve", "idempotency_key": "review-b"},
        )
    )
    assert first["ready_to_publish"] is False
    second = _ok(
        client.post(
            f"{ADMIN}/artifacts/four-eyes/versions/1/reviews",
            headers={"X-Test-Actor": "reviewer-c"},
            json={"decision": "approve", "idempotency_key": "review-c"},
        )
    )
    assert second["approval_count"] == 2
    assert second["ready_to_publish"] is True
    status = _ok(client.get(f"{ADMIN}/artifacts/four-eyes/versions/1"))
    assert status["ready_to_publish"] is True


def test_private_stable_link_retrieval_rotation_and_revocation(environment) -> None:
    client, stores, _registry, _clock, _tenant, tmp_path = environment
    _artifact(
        client,
        body_text='<script>alert("unsafe")</script> & operations',
    )
    link = _link(client, visibility="private")
    link_id = link["link_id"]
    old_capability = link["private_capability"]
    assert link["stable_path"] == f"{PUBLIC}/{link_id}"
    assert "tenant" not in link["stable_path"]
    assert link["capability_returned"] is True
    assert link["raw_capability_persisted"] is False
    _publish(client, link_id)

    assert client.get(f"{PUBLIC}/{link_id}").status_code == 404
    assert client.get(
        f"{PUBLIC}/{link_id}",
        headers={"Authorization": f"Bearer {'Z' * 43}"},
    ).status_code == 404
    html = client.get(
        f"{PUBLIC}/{link_id}",
        headers={"Authorization": f"Bearer {old_capability}"},
    )
    assert html.status_code == 200
    assert html.headers["content-type"] == "text/html; charset=utf-8"
    assert "<script>" not in html.text
    assert "&lt;script&gt;" in html.text
    assert html.headers["cache-control"] == "private, no-store, max-age=0"
    assert "frame-ancestors 'none'" in html.headers["content-security-policy"]
    text = client.get(
        f"{PUBLIC}/{link_id}?format=text",
        headers={"Authorization": f"Bearer {old_capability}"},
    )
    assert text.status_code == 200
    assert text.text.endswith("\n")
    assert "<script>" in text.text

    rotated = _ok(
        client.post(
            f"{ADMIN}/links/{link_id}/rotate-capability",
            json={"expected_revision": 0, "idempotency_key": "rotate-private-v1"},
        )
    )
    new_capability = rotated["private_capability"]
    assert new_capability != old_capability
    replay = _ok(
        client.post(
            f"{ADMIN}/links/{link_id}/rotate-capability",
            json={"expected_revision": 0, "idempotency_key": "rotate-private-v1"},
        )
    )
    assert replay["private_capability"] is None
    assert replay["capability_returned"] is False
    assert client.get(
        f"{PUBLIC}/{link_id}",
        headers={"Authorization": f"Bearer {old_capability}"},
    ).status_code == 404
    assert client.get(
        f"{PUBLIC}/{link_id}",
        headers={"Authorization": f"Bearer {new_capability}"},
    ).status_code == 200

    revoked = _ok(
        client.post(
            f"{ADMIN}/links/{link_id}/revoke",
            json={"expected_revision": 1, "idempotency_key": "revoke-private-v1"},
        )
    )
    assert revoked["status"] == "revoked"
    assert client.get(
        f"{PUBLIC}/{link_id}",
        headers={"Authorization": f"Bearer {new_capability}"},
    ).status_code == 404

    for path in (stores["tenant-a"].path, tmp_path / "registry.sqlite3"):
        with sqlite3.connect(path) as connection:
            dump = "\n".join(connection.iterdump())
        assert old_capability not in dump
        assert new_capability not in dump
    access = _ok(client.get(f"{ADMIN}/access"))
    serialized = repr(access)
    assert old_capability not in serialized
    assert new_capability not in serialized
    assert access["raw_capabilities_logged"] is False


def test_scheduler_claim_apply_retry_and_fail_closed_expiry(environment) -> None:
    client, _stores, _registry, clock, _tenant, _tmp = environment
    _artifact(client)
    first_link = _link(client)
    first_id = first_link["link_id"]
    scheduled = _ok(
        client.post(
            f"{ADMIN}/links/{first_id}/schedules/publication",
            json={
                "version": 1,
                "scheduled_for": NOW + 10,
                "expected_pointer_revision": 0,
                "idempotency_key": "schedule-first",
                "max_attempts": 3,
            },
        ),
        201,
    )
    assert scheduled["state"] == "pending"
    clock.advance(10)
    claimed = _ok(
        client.post(
            f"{ADMIN}/jobs/claim",
            json={"limit": 1, "lease_seconds": 60.0},
        )
    )
    claim = claimed["claims"][0]
    assert "tenant_id" not in claim and "worker_id" not in claim
    assert claim["lease_token_returned_once"] is True
    lease_token = claim.pop("lease_token")
    claim.pop("lease_token_returned_once")
    applied = _ok(
        client.post(
            f"{ADMIN}/jobs/{claim.pop('job_id')}/apply",
            json={**claim, "lease_token": lease_token},
        )
    )
    assert applied["state"] == "applied"
    assert client.get(f"{PUBLIC}/{first_id}").status_code == 200

    second_link = _link(client, policy_id="security-policy", visibility="private")
    second_id = second_link["link_id"]
    scheduled_second = _ok(
        client.post(
            f"{ADMIN}/links/{second_id}/schedules/publication",
            json={
                "version": 1,
                "scheduled_for": clock.value + 10,
                "expected_pointer_revision": 0,
                "idempotency_key": "schedule-second",
                "max_attempts": 3,
            },
        ),
        201,
    )
    assert scheduled_second["state"] == "pending"
    clock.advance(10)
    retry_claim = _ok(
        client.post(
            f"{ADMIN}/jobs/claim",
            json={"limit": 1, "lease_seconds": 60.0},
        )
    )["claims"][0]
    job_id = retry_claim.pop("job_id")
    retry_claim.pop("lease_token_returned_once")
    retried = _ok(
        client.post(
            f"{ADMIN}/jobs/{job_id}/fail",
            json={
                **retry_claim,
                "error_code": "transient_local_error",
                "retryable": True,
                "retry_after_seconds": 5.0,
            },
        )
    )
    assert retried["state"] == "pending"
    clock.advance(5)
    run = _ok(
        client.post(
            f"{ADMIN}/jobs/run-due",
            json={
                "limit": 10,
                "lease_seconds": 60.0,
                "approval_retry_seconds": 5.0,
            },
        )
    )
    assert run["outcomes"][0]["state"] == "applied"
    assert run["network_side_effect"] is False

    expiry = _ok(
        client.post(
            f"{ADMIN}/links/{first_id}/schedules/expiry",
            json={
                "version": 1,
                "scheduled_for": clock.value + 10,
                "expected_pointer_revision": 1,
                "idempotency_key": "expire-first",
            },
        ),
        201,
    )
    assert expiry["action"] == "expire"
    clock.advance(10)
    assert client.get(f"{PUBLIC}/{first_id}").status_code == 404


def test_audit_retention_integrity_bounds_and_public_rate_limit(
    environment,
) -> None:
    client, stores, registry, clock, _tenant, tmp_path = environment
    _artifact(client)
    link = _link(client)
    _publish(client, link["link_id"])
    assert client.get(f"{PUBLIC}/{link['link_id']}").status_code == 200
    assert _ok(client.get(f"{ADMIN}/audit"))["events"]
    assert _ok(client.get(f"{ADMIN}/access"))["events"]
    integrity = _ok(client.get(f"{ADMIN}/integrity"))
    assert integrity["status"] == "verified"
    assert integrity["public_registry"] == {
        "binding_status": "verified",
        "binding_count": 1,
    }
    assert integrity["local_storage_only"] is True
    clock.advance(100)
    purged = _ok(
        client.post(
            f"{ADMIN}/retention/access",
            json={"before": clock.value, "limit": 100},
        )
    )
    assert purged["purged"] >= 1
    assert _ok(client.get(f"{ADMIN}/integrity"))["status"] == "verified"

    oversized = client.post(
        f"{ADMIN}/links",
        headers={"Content-Length": str(321 * 1024)},
        json={
            "policy_id": "security-policy",
            "visibility": "public",
            "idempotency_key": "oversized",
        },
    )
    assert oversized.status_code == 413

    limited = PublicPolicyRateLimiter(
        per_key=2,
        global_limit=10,
        max_keys=10,
        clock=clock,
    )
    deps = PolicyPublicationDependencies(
        tenant_resolver=lambda: "tenant-a",
        store_for=lambda tenant_id: stores[tenant_id],
        registry_factory=lambda: registry,
        actor_resolver=lambda _request: "actor-a",
        rate_limiter=limited,
    )
    _admin, public_router = create_policy_publication_routers(deps)
    app = FastAPI()
    app.include_router(public_router, prefix="/api/v1")
    public_client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert public_client.get(f"{PUBLIC}/{link['link_id']}").status_code == 200
    assert public_client.get(f"{PUBLIC}/{link['link_id']}").status_code == 200
    limited_response = public_client.get(f"{PUBLIC}/{link['link_id']}")
    assert limited_response.status_code == 429
    assert limited_response.headers["retry-after"] == "60"
    # Changing the link ID cannot reset a client's anonymous request budget.
    assert public_client.get(f"{PUBLIC}/another-link").status_code == 429

    with sqlite3.connect(tmp_path / "registry.sqlite3") as connection:
        row = connection.execute(
            "SELECT tenant_id FROM public_policy_link_registry WHERE link_id=?",
            (link["link_id"],),
        ).fetchone()
    assert row == ("tenant-a",)


def test_rate_limiter_has_a_hard_cardinality_bound() -> None:
    clock = Clock()
    limiter = PublicPolicyRateLimiter(
        per_key=10,
        global_limit=100,
        max_keys=2,
        window_seconds=60,
        clock=clock,
    )
    limiter.check("first")
    limiter.check("second")
    with pytest.raises(PublicPolicyRateLimitExceeded, match="cardinality"):
        limiter.check("third")
    clock.advance(61)
    limiter.check("third")


def test_opaque_registry_rejects_cross_tenant_rebinding(tmp_path: Path) -> None:
    registry = PublicPolicyLinkRegistry(tmp_path / "registry.sqlite3", clock=lambda: NOW)
    first = registry.bind("PPL-global-link", "tenant-a")
    assert first["bound"] is True
    assert registry.bind("PPL-global-link", "tenant-a")["idempotent_replay"] is True
    with pytest.raises(PublicLinkRegistryError, match="another tenant"):
        registry.bind("PPL-global-link", "tenant-b")
    assert registry.resolve("PPL-global-link") == "tenant-a"


def test_lists_are_audit_gated_tenant_scoped_and_secret_free(
    environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maverick_dashboard import policy_publication_links_api as api_module

    client, _stores, _registry, _clock, tenant, _tmp = environment
    _artifact(client, policy_id="four-eyes", approval_mode="four_eyes")
    _artifact(client)
    link = _link(client, visibility="private")
    _publish(client, link["link_id"])
    current = _ok(client.get(f"{ADMIN}/links/{link['link_id']}"))
    _ok(
        client.post(
            f"{ADMIN}/links/{link['link_id']}/schedules/revocation",
            json={
                "scheduled_for": NOW + 3600,
                "expected_revision": current["revision"],
                "idempotency_key": "schedule-revoke",
            },
        ),
        201,
    )
    permissions: list[str] = []
    monkeypatch.setattr(
        api_module,
        "require_global_permission",
        lambda _request, permission: permissions.append(permission),
    )

    artifacts = _ok(client.get(f"{ADMIN}/artifacts"))["items"]
    by_policy = {item["policy_id"]: item for item in artifacts}
    assert by_policy["four-eyes"]["required_approvals"] == 2
    assert by_policy["four-eyes"]["ready_to_publish"] is False
    assert by_policy["security-policy"]["ready_to_publish"] is True

    links = _ok(client.get(f"{ADMIN}/links"))["items"]
    assert [item["link_id"] for item in links] == [link["link_id"]]
    assert links[0]["current_version"] == 1
    assert links[0]["pointer_revision"] == 1
    assert links[0]["stable_path"] == f"{PUBLIC}/{link['link_id']}"

    jobs = _ok(client.get(f"{ADMIN}/jobs"))["items"]
    assert [job["action"] for job in jobs] == ["revoke"]
    assert jobs[0]["state"] == "pending"
    for rows in (artifacts, links, jobs):
        for row in rows:
            for secret in ("capability_sha256", "private_capability", "lease_token",
                           "lease_token_sha256", "lease_owner"):
                assert secret not in row
    assert permissions == ["audit", "audit", "audit"]

    tenant["value"] = "tenant-b"
    assert _ok(client.get(f"{ADMIN}/artifacts"))["items"] == []
    assert _ok(client.get(f"{ADMIN}/links"))["items"] == []
    assert _ok(client.get(f"{ADMIN}/jobs"))["items"] == []
