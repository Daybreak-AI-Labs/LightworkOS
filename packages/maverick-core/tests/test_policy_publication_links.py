from __future__ import annotations

import concurrent.futures
import hashlib
import sqlite3
from pathlib import Path

import pytest
from maverick.policy_publication_links import (
    PolicyPublicationAccessDenied,
    PolicyPublicationApprovalRequired,
    PolicyPublicationConfigError,
    PolicyPublicationConflict,
    PolicyPublicationIntegrityError,
    PolicyPublicationLeaseLost,
    PolicyPublicationNotFound,
    PolicyPublicationStore,
    PolicyPublicationValidationError,
    enabled,
)

TENANT = "tenant-a"


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class Ids:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, prefix: str) -> str:
        self.value += 1
        return f"{prefix}-{self.value:08d}"


class Capabilities:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> str:
        self.value += 1
        return chr(64 + self.value) * 43


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: Path, clock: Clock) -> PolicyPublicationStore:
    return PolicyPublicationStore(
        tmp_path / "policy-links.sqlite3",
        clock=clock,
        id_factory=Ids(),
        capability_factory=Capabilities(),
        config_gate=lambda: True,
    )


def _artifact(
    store: PolicyPublicationStore,
    *,
    policy_id: str = "security-policy",
    version: int = 1,
    approval_mode: str = "none",
    body: str = "Use approved systems only.",
) -> dict:
    return store.publish_artifact(
        TENANT,
        policy_id=policy_id,
        version=version,
        title="Information Security Policy",
        body_text=body,
        author_id="author-1",
        approval_mode=approval_mode,
        idempotency_key=f"artifact-{policy_id}-{version}",
    )


def _link(
    store: PolicyPublicationStore,
    *,
    policy_id: str = "security-policy",
    visibility: str = "public",
) -> dict:
    return store.create_link(
        TENANT,
        policy_id=policy_id,
        visibility=visibility,
        created_by="publisher-1",
        idempotency_key=f"link-{policy_id}-{visibility}",
    )


def _publish(
    store: PolicyPublicationStore,
    link_id: str,
    *,
    version: int = 1,
    expected: int = 0,
    key: str | None = None,
    expires_at: float | None = None,
) -> dict:
    return store.publish_version(
        TENANT,
        link_id=link_id,
        version=version,
        expected_pointer_revision=expected,
        actor_id="publisher-1",
        idempotency_key=key or f"publish-{link_id}-{version}",
        expires_at=expires_at,
    )


def test_config_gate_is_explicit_and_fail_closed(monkeypatch, tmp_path: Path):
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "tech_risk_compliance": {
                "enable": True,
                "policy_publication_links": {"enable": True},
            }
        },
    )
    assert enabled() is True

    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "tech_risk_compliance": {
                "enable": True,
                "policy_publication_links": {"enable": False},
            }
        },
    )
    assert enabled() is False
    with pytest.raises(PolicyPublicationConfigError):
        PolicyPublicationStore(tmp_path / "disabled.sqlite3")

    monkeypatch.setattr(config, "config_source_errors", lambda: ["bad config"])
    assert enabled() is False


def test_artifacts_are_canonical_immutable_and_idempotent(
    store: PolicyPublicationStore,
):
    created = store.publish_artifact(
        TENANT,
        policy_id="workplace-policy",
        version=1,
        title="Café Policy",
        body_text="First line\r\nSecond line",
        author_id="author-1",
        approval_mode="none",
        idempotency_key="artifact-one",
    )
    replay = store.publish_artifact(
        TENANT,
        policy_id="workplace-policy",
        version=1,
        title="Café Policy",
        body_text="First line\nSecond line",
        author_id="author-1",
        approval_mode="none",
        idempotency_key="artifact-one",
    )
    assert replay["idempotent_replay"] is True
    assert replay["artifact_sha256"] == created["artifact_sha256"]
    assert store.artifact_status(
        TENANT, policy_id="workplace-policy", version=1
    )["ready_to_publish"] is True

    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE policy_publication_artifacts SET title='changed'"
            )


def test_canonical_tenant_ids_normalize_unicode_and_preserve_isolation(
    store: PolicyPublicationStore,
) -> None:
    decomposed = "Acme Cafe\u0301 Corp"
    canonical = "Acme Caf\u00e9 Corp"
    created = store.publish_artifact(
        decomposed,
        policy_id="privacy-policy",
        version=1,
        title="Privacy Policy",
        body_text="Use personal data only for approved purposes.",
        author_id="author-1",
        approval_mode="none",
        idempotency_key="acme-policy-create",
    )

    status = store.artifact_status(canonical, policy_id="privacy-policy", version=1)
    assert status["artifact_sha256"] == created["artifact_sha256"]
    with pytest.raises(PolicyPublicationNotFound):
        store.artifact_status("Other Corp", policy_id="privacy-policy", version=1)
    with pytest.raises(PolicyPublicationValidationError, match="opaque identifier"):
        store.artifact_status(canonical, policy_id="privacy policy", version=1)


def test_plain_text_contract_rejects_controls_and_bounds(
    store: PolicyPublicationStore,
):
    with pytest.raises(PolicyPublicationValidationError):
        store.publish_artifact(
            TENANT,
            policy_id="bad",
            version=1,
            title="Bad\nTitle",
            body_text="body",
            author_id="author-1",
            approval_mode="none",
            idempotency_key="bad-title",
        )
    with pytest.raises(PolicyPublicationValidationError):
        store.publish_artifact(
            TENANT,
            policy_id="bad",
            version=1,
            title="Title",
            body_text="direction\u202eoverride",
            author_id="author-1",
            approval_mode="none",
            idempotency_key="bad-body",
        )
    with pytest.raises(PolicyPublicationValidationError):
        _artifact(store, policy_id="too-big", body="x" * (256 * 1024 + 1))


def test_independent_approval_and_four_eyes_gates(store: PolicyPublicationStore):
    _artifact(store, policy_id="single", approval_mode="approval")
    single = _link(store, policy_id="single")
    with pytest.raises(PolicyPublicationApprovalRequired):
        _publish(store, single["link_id"], key="single-too-early")
    with pytest.raises(PolicyPublicationConflict, match="author"):
        store.approve_artifact(
            TENANT,
            policy_id="single",
            version=1,
            reviewer_id="author-1",
            decision="approve",
            idempotency_key="self-review",
        )
    decision = store.approve_artifact(
        TENANT,
        policy_id="single",
        version=1,
        reviewer_id="reviewer-1",
        decision="approve",
        idempotency_key="single-review",
    )
    assert decision["ready_to_publish"] is True
    assert _publish(store, single["link_id"], key="single-publish")[
        "current_version"
    ] == 1

    _artifact(store, policy_id="four-eyes", approval_mode="four_eyes")
    four = _link(store, policy_id="four-eyes")
    first = store.approve_artifact(
        TENANT,
        policy_id="four-eyes",
        version=1,
        reviewer_id="reviewer-1",
        decision="approve",
        idempotency_key="four-review-1",
    )
    assert first["ready_to_publish"] is False
    with pytest.raises(PolicyPublicationApprovalRequired):
        _publish(store, four["link_id"], key="four-too-early")
    second = store.approve_artifact(
        TENANT,
        policy_id="four-eyes",
        version=1,
        reviewer_id="reviewer-2",
        decision="approve",
        idempotency_key="four-review-2",
    )
    assert second["ready_to_publish"] is True
    assert second["approval_count"] == 2


def test_rejection_permanently_blocks_the_version(store: PolicyPublicationStore):
    _artifact(store, policy_id="rejected", approval_mode="approval")
    link = _link(store, policy_id="rejected")
    result = store.approve_artifact(
        TENANT,
        policy_id="rejected",
        version=1,
        reviewer_id="reviewer-1",
        decision="reject",
        rationale_sha256="a" * 64,
        idempotency_key="reject-version",
    )
    assert result["rejection_count"] == 1
    with pytest.raises(PolicyPublicationApprovalRequired):
        _publish(store, link["link_id"], key="publish-rejected")


def test_exact_pointer_cas_idempotency_and_no_change(store: PolicyPublicationStore):
    _artifact(store)
    link = _link(store)
    first = _publish(store, link["link_id"], key="publish-1")
    assert first["pointer_revision"] == 1
    replay = _publish(store, link["link_id"], key="publish-1")
    assert replay["idempotent_replay"] is True
    assert replay["pointer_revision"] == 1

    no_change = _publish(
        store,
        link["link_id"],
        expected=1,
        key="publish-same-version-new-key",
    )
    assert no_change["no_change"] is True
    assert no_change["pointer_revision"] == 1
    with pytest.raises(PolicyPublicationConflict, match="revision"):
        _publish(
            store,
            link["link_id"],
            expected=0,
            key="stale-publish",
        )


def test_public_retrieval_is_deterministic_and_html_is_escaped(
    store: PolicyPublicationStore, clock: Clock
):
    _artifact(
        store,
        body='<script>alert("x")</script> & operations',
    )
    link = _link(store)
    _publish(store, link["link_id"])

    first = store.retrieve(TENANT, link_id=link["link_id"], output_format="html")
    clock.advance(10)
    second = store.retrieve(TENANT, link_id=link["link_id"], output_format="html")
    assert second == first
    assert "<script>" not in first["content"]
    assert "&lt;script&gt;" in first["content"]
    assert "&amp; operations" in first["content"]

    text = store.retrieve(TENANT, link_id=link["link_id"], output_format="text")
    assert text["content_type"] == "text/plain; charset=utf-8"
    assert text["content"].endswith("\n")
    assert text["etag"] != first["etag"]


def test_private_capability_is_shown_once_and_never_persisted(
    store: PolicyPublicationStore,
):
    _artifact(store)
    link = _link(store, visibility="private")
    capability = link["private_capability"]
    assert capability == "A" * 43
    _publish(store, link["link_id"])

    replay = _link(store, visibility="private")
    assert replay["link_id"] == link["link_id"]
    assert replay["private_capability"] is None
    assert replay["capability_returned"] is False

    with sqlite3.connect(store.path) as connection:
        dump = "\n".join(connection.iterdump())
    assert capability not in dump
    with pytest.raises(PolicyPublicationAccessDenied):
        store.retrieve(
            TENANT,
            link_id=link["link_id"],
            bearer_capability="Z" * 43,
        )
    retrieved = store.retrieve(
        TENANT,
        link_id=link["link_id"],
        bearer_capability=capability,
    )
    assert retrieved["version"] == 1
    events = store.list_access_events(TENANT)
    assert [event["outcome"] for event in events] == ["denied", "granted"]
    assert all("capability" not in repr(event) for event in events)


def test_private_capability_rotation_invalidates_old_authority(
    store: PolicyPublicationStore,
):
    _artifact(store)
    link = _link(store, visibility="private")
    old = link["private_capability"]
    _publish(store, link["link_id"])
    rotated = store.rotate_private_capability(
        TENANT,
        link_id=link["link_id"],
        expected_revision=0,
        actor_id="security-owner",
        idempotency_key="rotate-one",
    )
    assert rotated["private_capability"] == "B" * 43
    assert rotated["capability_generation"] == 2
    replay = store.rotate_private_capability(
        TENANT,
        link_id=link["link_id"],
        expected_revision=0,
        actor_id="security-owner",
        idempotency_key="rotate-one",
    )
    assert replay["private_capability"] is None
    with pytest.raises(PolicyPublicationAccessDenied):
        store.retrieve(
            TENANT, link_id=link["link_id"], bearer_capability=old
        )
    assert store.retrieve(
        TENANT,
        link_id=link["link_id"],
        bearer_capability=rotated["private_capability"],
    )["version"] == 1


def test_immediate_revocation_is_irreversible_and_clears_authority(
    store: PolicyPublicationStore,
):
    _artifact(store)
    link = _link(store, visibility="private")
    _publish(store, link["link_id"])
    revoked = store.revoke_link(
        TENANT,
        link_id=link["link_id"],
        expected_revision=0,
        actor_id="security-owner",
        idempotency_key="revoke-now",
    )
    assert revoked["status"] == "revoked"
    with pytest.raises(PolicyPublicationAccessDenied):
        store.retrieve(
            TENANT,
            link_id=link["link_id"],
            bearer_capability=link["private_capability"],
        )
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT capability_sha256 FROM policy_publication_links"
        ).fetchone()
    assert row[0] is None


def test_scheduled_publication_claim_and_apply(
    store: PolicyPublicationStore, clock: Clock
):
    _artifact(store)
    link = _link(store)
    job = store.schedule_publication(
        TENANT,
        link_id=link["link_id"],
        version=1,
        scheduled_for=clock.value + 60,
        expected_pointer_revision=0,
        scheduled_by="publisher-1",
        idempotency_key="schedule-publish",
    )
    assert job["state"] == "pending"
    assert store.claim_due_jobs(TENANT, worker_id="worker-1") == ()
    with pytest.raises(PolicyPublicationAccessDenied):
        store.retrieve(TENANT, link_id=link["link_id"])

    clock.advance(60)
    claims = store.claim_due_jobs(
        TENANT, worker_id="worker-1", limit=1, lease_seconds=30
    )
    assert len(claims) == 1
    with sqlite3.connect(store.path) as connection:
        dump = "\n".join(connection.iterdump())
    assert claims[0].lease_token not in dump
    applied = store.apply_claim(claims[0])
    assert applied["state"] == "applied"
    assert store.retrieve(TENANT, link_id=link["link_id"])["version"] == 1


def test_expired_scheduler_lease_is_recovered(
    store: PolicyPublicationStore, clock: Clock
):
    _artifact(store)
    link = _link(store)
    store.schedule_publication(
        TENANT,
        link_id=link["link_id"],
        version=1,
        scheduled_for=clock.value + 1,
        expected_pointer_revision=0,
        scheduled_by="publisher-1",
        idempotency_key="recovery-job",
    )
    clock.advance(1)
    first = store.claim_due_jobs(
        TENANT, worker_id="worker-1", lease_seconds=5
    )[0]
    clock.advance(6)
    second = store.claim_due_jobs(
        TENANT, worker_id="worker-2", lease_seconds=30
    )[0]
    assert second.job_id == first.job_id
    assert second.attempt == 2
    with pytest.raises(PolicyPublicationLeaseLost):
        store.apply_claim(first)
    assert store.apply_claim(second)["state"] == "applied"


def test_scheduled_expiry_fails_closed_without_scheduler(
    store: PolicyPublicationStore, clock: Clock
):
    _artifact(store)
    link = _link(store)
    _publish(store, link["link_id"])
    scheduled = store.schedule_expiry(
        TENANT,
        link_id=link["link_id"],
        version=1,
        scheduled_for=clock.value + 10,
        expected_pointer_revision=1,
        scheduled_by="publisher-1",
        idempotency_key="expire-policy",
    )
    assert scheduled["expected_revision"] == 2
    assert store.retrieve(TENANT, link_id=link["link_id"])["version"] == 1
    clock.advance(10)
    with pytest.raises(PolicyPublicationAccessDenied):
        store.retrieve(TENANT, link_id=link["link_id"])
    claim = store.claim_due_jobs(TENANT, worker_id="worker-1")[0]
    assert store.apply_claim(claim)["action"] == "expire"
    assert store.get_link(TENANT, link_id=link["link_id"])["current_version"] is None


def test_scheduled_revocation_fails_closed_without_scheduler(
    store: PolicyPublicationStore, clock: Clock
):
    _artifact(store)
    link = _link(store, visibility="private")
    _publish(store, link["link_id"])
    scheduled = store.schedule_revocation(
        TENANT,
        link_id=link["link_id"],
        scheduled_for=clock.value + 10,
        expected_revision=0,
        scheduled_by="security-owner",
        idempotency_key="scheduled-revoke",
    )
    assert scheduled["expected_revision"] == 1
    with pytest.raises(PolicyPublicationConflict, match="scheduled"):
        store.rotate_private_capability(
            TENANT,
            link_id=link["link_id"],
            expected_revision=1,
            actor_id="security-owner",
            idempotency_key="rotate-after-schedule",
        )
    clock.advance(10)
    with pytest.raises(PolicyPublicationAccessDenied):
        store.retrieve(
            TENANT,
            link_id=link["link_id"],
            bearer_capability=link["private_capability"],
        )
    outcome = store.run_due_jobs(TENANT, worker_id="worker-1")
    assert outcome[0]["state"] == "applied"
    assert store.get_link(TENANT, link_id=link["link_id"])["status"] == "revoked"


def test_scheduler_retries_pending_approval_then_applies(
    store: PolicyPublicationStore, clock: Clock
):
    _artifact(store, approval_mode="approval")
    link = _link(store)
    store.schedule_publication(
        TENANT,
        link_id=link["link_id"],
        version=1,
        scheduled_for=clock.value + 1,
        expected_pointer_revision=0,
        scheduled_by="publisher-1",
        idempotency_key="approval-schedule",
        max_attempts=3,
    )
    clock.advance(1)
    first = store.run_due_jobs(
        TENANT, worker_id="worker-1", approval_retry_seconds=10
    )
    assert first[0]["state"] == "pending"
    assert first[0]["last_error_code"] == "approval_pending"
    store.approve_artifact(
        TENANT,
        policy_id="security-policy",
        version=1,
        reviewer_id="reviewer-1",
        decision="approve",
        idempotency_key="late-approval",
    )
    clock.advance(10)
    second = store.run_due_jobs(TENANT, worker_id="worker-1")
    assert second[0]["state"] == "applied"


def test_claim_and_list_bounds_are_enforced(store: PolicyPublicationStore):
    with pytest.raises(PolicyPublicationValidationError):
        store.claim_due_jobs(TENANT, worker_id="worker-1", limit=101)
    with pytest.raises(PolicyPublicationValidationError):
        store.claim_due_jobs(TENANT, worker_id="worker-1", lease_seconds=3601)
    with pytest.raises(PolicyPublicationValidationError):
        store.list_audit(TENANT, limit=501)


def test_access_retention_checkpoint_preserves_chain(
    store: PolicyPublicationStore, clock: Clock
):
    _artifact(store)
    link = _link(store)
    _publish(store, link["link_id"])
    for _ in range(3):
        store.retrieve(TENANT, link_id=link["link_id"])
        clock.advance(1)
    result = store.purge_access_events(
        TENANT, before=clock.value, limit=2
    )
    assert result["purged"] == 2
    assert len(store.list_access_events(TENANT)) == 1
    verified = store.verify_integrity(TENANT)
    assert verified["status"] == "verified"
    assert verified["access_checkpoint_count"] == 1
    assert verified["retained_access_event_count"] == 1


def test_content_retention_purges_only_unreferenced_versions(
    store: PolicyPublicationStore, clock: Clock
):
    _artifact(store, version=1, body="Version one")
    clock.advance(1)
    _artifact(store, version=2, body="Version two")
    link = _link(store)
    _publish(store, link["link_id"], version=2)
    clock.advance(10)
    result = store.purge_unreferenced_content(
        TENANT, before=clock.value, limit=10
    )
    assert result["purged"] == 1
    assert store.artifact_status(
        TENANT, policy_id="security-policy", version=1
    )["content_available"] is False
    assert store.artifact_status(
        TENANT, policy_id="security-policy", version=2
    )["content_available"] is True
    assert store.retrieve(TENANT, link_id=link["link_id"])["version"] == 2
    assert store.verify_integrity(TENANT)["artifact_count"] == 2


def test_tenant_isolation(store: PolicyPublicationStore):
    _artifact(store)
    link = _link(store)
    _publish(store, link["link_id"])
    with pytest.raises(PolicyPublicationAccessDenied):
        store.retrieve("tenant-b", link_id=link["link_id"])
    assert store.list_access_events(TENANT) == ()
    # An unknown link id is refused without an access event.
    assert store.list_access_events("tenant-b") == ()


def test_integrity_detects_mutable_link_tampering(store: PolicyPublicationStore):
    _artifact(store)
    link = _link(store)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE policy_publication_links SET pointer_revision=99 "
            "WHERE tenant=? AND link_id=?",
            (TENANT, link["link_id"]),
        )
    with pytest.raises(PolicyPublicationIntegrityError, match="link digest"):
        store.verify_integrity(TENANT)


def test_two_publishers_cannot_win_the_same_pointer_revision(
    store: PolicyPublicationStore,
):
    _artifact(store, version=1)
    _artifact(store, version=2)
    link = _link(store)

    def publish(version: int) -> str:
        try:
            store.publish_version(
                TENANT,
                link_id=link["link_id"],
                version=version,
                expected_pointer_revision=0,
                actor_id=f"publisher-{version}",
                idempotency_key=f"concurrent-{version}",
            )
        except PolicyPublicationConflict:
            return "conflict"
        return "published"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(publish, (1, 2)))
    assert outcomes == ["conflict", "published"]
    metadata = store.get_link(TENANT, link_id=link["link_id"])
    assert metadata["pointer_revision"] == 1
    assert metadata["current_version"] in {1, 2}


def test_audit_and_database_never_contain_raw_capabilities(
    store: PolicyPublicationStore,
):
    _artifact(store)
    link = _link(store, visibility="private")
    _publish(store, link["link_id"])
    capability = link["private_capability"]
    store.retrieve(
        TENANT,
        link_id=link["link_id"],
        bearer_capability=capability,
        request_context_sha256=hashlib.sha256(b"request-1").hexdigest(),
    )
    assert capability not in repr(store.list_audit(TENANT))
    assert capability not in repr(store.list_access_events(TENANT))
    with sqlite3.connect(store.path) as connection:
        dump = "\n".join(connection.iterdump())
    assert capability not in dump
    assert store.verify_integrity(TENANT)["status"] == "verified"
