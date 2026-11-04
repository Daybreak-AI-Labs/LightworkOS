from __future__ import annotations

import hashlib
import inspect
import json
import sqlite3
from pathlib import Path

import pytest
from maverick import privacy_notice_governance as notice


class MutableClock:
    def __init__(self, value: float = 2_200_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def authority(tmp_path: Path):
    actor = {"value": "release-author"}
    clock = MutableClock()
    token_counter = {"value": 0}

    def token() -> str:
        token_counter["value"] += 1
        return f"lease-token-{token_counter['value']}"

    store = notice.PrivacyNoticeGovernanceStore(
        tmp_path / "notice-governance.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        signing_key_resolver=lambda _tenant, _ref: b"n" * 32,
        regulatory_reference_resolver=lambda _tenant, doc, source, evidence: (
            doc.startswith("regdoc:")
            and source.startswith("regsource:")
            and len(evidence) == 64
        ),
        clock=clock,
        token_factory=token,
    )
    return store, actor, clock


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def create_policy(
    store: notice.PrivacyNoticeGovernanceStore,
    *,
    tenant: str = "tenant-a",
    ttl: int = 300,
    key: str = "policy",
) -> notice.ApprovalPolicy:
    return store.set_approval_policy(
        tenant,
        "notice-policy",
        required_roles=["privacy", "legal"],
        quorum=2,
        approval_ttl_seconds=ttl,
        expected_revision=0,
        idempotency_key=key,
    )


def create_release(
    store: notice.PrivacyNoticeGovernanceStore,
    clock: MutableClock,
    *,
    tenant: str = "tenant-a",
    notice_id: str = "privacy-main",
    expected_latest_version: int = 0,
    key: str = "release",
    update_proposal_ref: str | None = None,
) -> notice.NoticeRelease:
    suffix = expected_latest_version + 1
    return store.create_release(
        tenant,
        notice_id,
        property_id="property-main",
        jurisdictions=["eu", "us-ca"],
        locales=["en-US", "fr-FR"],
        policy_sha256=digest(f"policy-{suffix}"),
        content_sha256=digest(f"content-{suffix}"),
        configuration_sha256=digest(f"configuration-{suffix}"),
        consent_publication_ref=f"consent-publication:{suffix}",
        approval_policy_id="notice-policy",
        effective_from=clock(),
        effective_until=clock() + 300,
        retained_until=clock() + 400,
        update_proposal_ref=update_proposal_ref,
        expected_latest_version=expected_latest_version,
        idempotency_key=key,
    )


def approve_release(
    store: notice.PrivacyNoticeGovernanceStore,
    actor: dict[str, str],
    release: notice.NoticeRelease,
    *,
    suffix: str,
) -> notice.NoticeRelease:
    actor["value"] = "release-author"
    reviewing = store.submit_for_review(
        release.tenant_id,
        release.notice_id,
        release.version,
        expected_revision=release.state_revision,
        idempotency_key=f"review-{suffix}",
    )
    actor["value"] = f"privacy-approver-{suffix}"
    privacy_approved = store.approve_release(
        release.tenant_id,
        release.notice_id,
        release.version,
        role="privacy",
        expected_release_sha256=release.definition_sha256,
        expected_revision=reviewing.state_revision,
        idempotency_key=f"privacy-{suffix}",
    )
    actor["value"] = f"legal-approver-{suffix}"
    approved = store.approve_release(
        release.tenant_id,
        release.notice_id,
        release.version,
        role="legal",
        expected_release_sha256=release.definition_sha256,
        expected_revision=privacy_approved.state_revision,
        idempotency_key=f"legal-{suffix}",
    )
    assert approved.state == "approved"
    return approved


@pytest.mark.parametrize(("ttl", "elapsed"), [(300, 301), (60, 61)])
def test_expired_publication_prefix_does_not_starve_ready_work_after_restart(authority, ttl, elapsed):
    store, actor, clock = authority
    create_policy(store, ttl=ttl)

    def schedule(name):
        release = create_release(store, clock, notice_id=name, key=name)
        approved = approve_release(store, actor, release, suffix=name)
        actor["value"] = "release-scheduler"
        store.schedule_release(
            "tenant-a", name, release.version, activate_at=clock(),
            expected_release_sha256=release.definition_sha256, max_attempts=3,
            expected_revision=approved.state_revision, idempotency_key=f"schedule-{name}",
        )

    for index in range(10):
        schedule(f"expired-{index}")
    clock.advance(elapsed)
    schedule("ready-eleventh")
    # The public bridge uses limit=1; its bounded first scan retires the old
    # prefix. That progress must survive constructing a fresh store instance.
    assert store.claim_publication_intents("tenant-a", limit=1, lease_seconds=30) == ()
    restarted = notice.PrivacyNoticeGovernanceStore(
        store.path, config_gate=lambda: None, principal_resolver=lambda: "worker",
        signing_key_resolver=lambda *_: b"n" * 32, clock=clock,
    )
    claimed = restarted.claim_publication_intents("tenant-a", limit=1, lease_seconds=30)
    assert [item.notice_id for item in claimed] == ["ready-eleventh"]
    assert restarted.claim_publication_intents("tenant-a", limit=1, lease_seconds=30) == ()


def publish_release(
    store: notice.PrivacyNoticeGovernanceStore,
    actor: dict[str, str],
    clock: MutableClock,
    release: notice.NoticeRelease,
    *,
    suffix: str,
    max_attempts: int = 3,
) -> notice.NoticeRelease:
    approved = approve_release(store, actor, release, suffix=suffix)
    actor["value"] = "release-scheduler"
    scheduled = store.schedule_release(
        release.tenant_id,
        release.notice_id,
        release.version,
        activate_at=clock() + 1,
        expected_release_sha256=release.definition_sha256,
        max_attempts=max_attempts,
        expected_revision=approved.state_revision,
        idempotency_key=f"schedule-{suffix}",
    )
    clock.advance(1)
    intent = store.claim_publication_intents(
        release.tenant_id, limit=1, lease_seconds=30
    )[0]
    assert intent.action == "publish"
    store.ack_publication_intent(
        release.tenant_id,
        intent.intent_id,
        lease_token=intent.lease_token or "",
        acknowledgement_sha256=digest(f"ack-{suffix}"),
        acknowledgement_ref=f"publication-ack:{suffix}",
        expected_revision=intent.revision,
        idempotency_key=f"ack-{suffix}",
    )
    published = store.get_release(
        release.tenant_id, release.notice_id, release.version
    )
    assert scheduled.state == "scheduled"
    assert published.state == "published"
    return published


def test_exact_default_off_gate(monkeypatch, tmp_path: Path) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    for index, configured in enumerate(
        (
            {},
            {"privacy_automation": {"enable": True}},
            {
                "privacy_automation": {
                    "enable": False,
                    "notice_governance": {"enable": True},
                }
            },
            {
                "privacy_automation": {
                    "enable": True,
                    "notice_governance": {"enable": False},
                }
            },
        )
    ):
        monkeypatch.setattr(config, "load_config", lambda value=configured: value)
        assert notice.enabled() is False
        with pytest.raises(notice.PrivacyNoticeConfigError):
            notice.PrivacyNoticeGovernanceStore(
                tmp_path / f"disabled-{index}.sqlite3",
                principal_resolver=lambda: "principal",
            )
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "privacy_automation": {
                "enable": True,
                "notice_governance": {"enable": True},
            }
        },
    )
    assert notice.enabled() is True


def test_actor_spoofing_impossible_and_private_wal_full(tmp_path: Path) -> None:
    for name, method in inspect.getmembers(
        notice.PrivacyNoticeGovernanceStore, predicate=inspect.isfunction
    ):
        if name.startswith("_") or name == "product_boundaries":
            continue
        assert "actor" not in inspect.signature(method).parameters
        assert "actor_ref" not in inspect.signature(method).parameters
    store = notice.PrivacyNoticeGovernanceStore(
        tmp_path / "anonymous.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: None,
        signing_key_resolver=lambda _tenant, _ref: b"n" * 32,
    )
    with store._connect() as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
    with pytest.raises(notice.PrivacyNoticePermissionDenied):
        store.get_approval_policy("tenant-a", "notice-policy")


def test_tenant_canonicalization_isolation_and_scoped_integrity(authority) -> None:
    store, _actor, _clock = authority
    create_policy(store, tenant="Cafe\u0301", key="policy-a")
    create_policy(store, tenant="tenant-b", key="policy-b")
    assert store.get_approval_policy("Caf\u00e9", "notice-policy").tenant_id == "Caf\u00e9"
    with pytest.raises(notice.PrivacyNoticeNotFound):
        store.get_approval_policy("tenant-c", "notice-policy")
    before = store.verify_integrity("Caf\u00e9")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE notice_approval_policies SET payload_json=? WHERE tenant_id=?",
            ('{"tenant_id":"tenant-b"}', "tenant-b"),
        )
    assert store.verify_integrity("Caf\u00e9") == before
    with pytest.raises(notice.PrivacyNoticeIntegrityError):
        store.verify_integrity("tenant-b")


def test_quorum_roles_distinct_humans_and_digest_cas_idempotency(authority) -> None:
    store, actor, clock = authority
    with pytest.raises(notice.PrivacyNoticeValidationError):
        store.set_approval_policy(
            "tenant-a",
            "bad-policy",
            required_roles=["privacy", "legal"],
            quorum=1,
            approval_ttl_seconds=300,
            expected_revision=0,
            idempotency_key="bad-quorum",
        )
    create_policy(store)
    release = create_release(store, clock)
    replay = create_release(store, clock)
    assert replay == release
    with pytest.raises(notice.PrivacyNoticeConflict, match="different canonical"):
        store.create_release(
            "tenant-a",
            "privacy-main",
            property_id="property-main",
            jurisdictions=["eu"],
            locales=["en-US"],
            policy_sha256=digest("different"),
            content_sha256=digest("content-1"),
            configuration_sha256=digest("configuration-1"),
            consent_publication_ref="consent-publication:1",
            approval_policy_id="notice-policy",
            effective_from=clock(),
            effective_until=clock() + 300,
            retained_until=clock() + 400,
            expected_latest_version=0,
            idempotency_key="release",
        )
    reviewing = store.submit_for_review(
        "tenant-a",
        release.notice_id,
        release.version,
        expected_revision=release.state_revision,
        idempotency_key="review",
    )
    with pytest.raises(notice.PrivacyNoticePermissionDenied, match="author"):
        store.approve_release(
            "tenant-a",
            release.notice_id,
            release.version,
            role="privacy",
            expected_release_sha256=release.definition_sha256,
            expected_revision=reviewing.state_revision,
            idempotency_key="self-approval",
        )
    with pytest.raises(notice.PrivacyNoticeConflict, match="draft"):
        store.submit_for_review(
            "tenant-a",
            release.notice_id,
            release.version,
            expected_revision=reviewing.state_revision,
            idempotency_key="review-again",
        )
    actor["value"] = "same-human"
    privacy_approved = store.approve_release(
        "tenant-a",
        release.notice_id,
        release.version,
        role="privacy",
        expected_release_sha256=release.definition_sha256,
        expected_revision=reviewing.state_revision,
        idempotency_key="privacy",
    )
    with pytest.raises(notice.PrivacyNoticePermissionDenied, match="human"):
        store.approve_release(
            "tenant-a",
            release.notice_id,
            release.version,
            role="legal",
            expected_release_sha256=release.definition_sha256,
            expected_revision=privacy_approved.state_revision,
            idempotency_key="inflation",
        )
    actor["value"] = "legal-human"
    with pytest.raises(notice.PrivacyNoticeConflict, match="digest"):
        store.approve_release(
            "tenant-a",
            release.notice_id,
            release.version,
            role="legal",
            expected_release_sha256=digest("wrong-release"),
            expected_revision=privacy_approved.state_revision,
            idempotency_key="wrong-digest",
        )


def test_expired_and_revoked_approvals_invalidate_readiness(authority) -> None:
    store, actor, clock = authority
    create_policy(store, ttl=60)
    release = create_release(store, clock)
    approved = approve_release(store, actor, release, suffix="expiry")
    clock.advance(61)
    with pytest.raises(notice.PrivacyNoticeConflict, match="readiness"):
        store.schedule_release(
            "tenant-a",
            release.notice_id,
            release.version,
            activate_at=clock() + 1,
            expected_release_sha256=release.definition_sha256,
            max_attempts=3,
            expected_revision=approved.state_revision,
            idempotency_key="schedule-expired",
        )

    store2_path = store.path.parent / "revocation.sqlite3"
    actor2 = {"value": "release-author"}
    store2 = notice.PrivacyNoticeGovernanceStore(
        store2_path,
        config_gate=lambda: None,
        principal_resolver=lambda: actor2["value"],
        signing_key_resolver=lambda _tenant, _ref: b"n" * 32,
        clock=clock,
    )
    create_policy(store2, ttl=300)
    release2 = create_release(store2, clock)
    approved2 = approve_release(store2, actor2, release2, suffix="revoke")
    actor2["value"] = "privacy-approver-revoke"
    revoked = store2.revoke_approval(
        "tenant-a",
        release2.notice_id,
        release2.version,
        role="privacy",
        expected_approval_revision=1,
        idempotency_key="revoke",
    )
    assert approved2.state == "approved"
    assert revoked.state == "review"
    with pytest.raises(notice.PrivacyNoticeConflict, match="readiness"):
        store2.schedule_release(
            "tenant-a",
            release2.notice_id,
            release2.version,
            activate_at=clock() + 1,
            expected_release_sha256=release2.definition_sha256,
            max_attempts=3,
            expected_revision=revoked.state_revision,
            idempotency_key="schedule-revoked",
        )

    actor3 = {"value": "release-author"}
    store3 = notice.PrivacyNoticeGovernanceStore(
        store.path.parent / "published-expiry.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor3["value"],
        signing_key_resolver=lambda _tenant, _ref: b"n" * 32,
        clock=clock,
    )
    create_policy(store3, ttl=60)
    published3 = publish_release(
        store3, actor3, clock, create_release(store3, clock), suffix="published-expiry"
    )
    assert store3.current_effective_release(
        "tenant-a", "property-main", "eu", "en-US"
    ) == published3
    clock.advance(61)
    with pytest.raises(notice.PrivacyNoticeNotFound):
        store3.current_effective_release(
            "tenant-a", "property-main", "eu", "en-US"
        )

    actor4 = {"value": "release-author"}
    store4 = notice.PrivacyNoticeGovernanceStore(
        store.path.parent / "published-revocation.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor4["value"],
        signing_key_resolver=lambda _tenant, _ref: b"n" * 32,
        clock=clock,
    )
    create_policy(store4)
    published4 = publish_release(
        store4,
        actor4,
        clock,
        create_release(store4, clock),
        suffix="published-revocation",
    )
    actor4["value"] = "privacy-approver-published-revocation"
    still_published = store4.revoke_approval(
        "tenant-a",
        published4.notice_id,
        published4.version,
        role="privacy",
        expected_approval_revision=1,
        idempotency_key="published-revocation",
    )
    assert still_published.state == "published"
    with pytest.raises(notice.PrivacyNoticeNotFound):
        store4.current_effective_release(
            "tenant-a", "property-main", "eu", "en-US"
        )


def test_publication_outbox_recovery_dead_letter_requeue_ack_and_token_nonexport(
    authority,
) -> None:
    store, actor, clock = authority
    create_policy(store)
    release = create_release(store, clock)
    approved = approve_release(store, actor, release, suffix="outbox")
    actor["value"] = "worker"
    store.schedule_release(
        "tenant-a",
        release.notice_id,
        release.version,
        activate_at=clock() + 1,
        expected_release_sha256=release.definition_sha256,
        max_attempts=2,
        expected_revision=approved.state_revision,
        idempotency_key="schedule",
    )
    clock.advance(1)
    first = store.claim_publication_intents(
        "tenant-a", limit=1, lease_seconds=10
    )[0]
    exported = store.export_notice(
        "tenant-a",
        release.notice_id,
        "export:no-token",
        signing_key_ref="vault:notice-signing-key",
        retained_until=clock() + 100,
        idempotency_key="export-no-token",
    )
    assert first.lease_token not in repr(exported)
    assert "lease_token" not in json.dumps(exported.body)
    clock.advance(11)
    recovered = store.claim_publication_intents(
        "tenant-a", limit=1, lease_seconds=10
    )[0]
    assert recovered.recovery_count == 1
    failed = store.fail_publication_intent(
        "tenant-a",
        recovered.intent_id,
        lease_token=recovered.lease_token or "",
        error_code="adapter_unavailable",
        retry_delay_seconds=0,
        expected_revision=recovered.revision,
        idempotency_key="fail-1",
    )
    assert failed.state == "pending"
    second = store.claim_publication_intents(
        "tenant-a", limit=1, lease_seconds=10
    )[0]
    dead = store.fail_publication_intent(
        "tenant-a",
        second.intent_id,
        lease_token=second.lease_token or "",
        error_code="adapter_unavailable",
        retry_delay_seconds=0,
        expected_revision=second.revision,
        idempotency_key="fail-2",
    )
    assert dead.state == "dead_letter"
    requeued = store.requeue_publication_intent(
        "tenant-a",
        dead.intent_id,
        expected_revision=dead.revision,
        idempotency_key="requeue",
    )
    assert requeued.state == "pending"
    final_claim = store.claim_publication_intents(
        "tenant-a", limit=1, lease_seconds=10
    )[0]
    acked = store.ack_publication_intent(
        "tenant-a",
        final_claim.intent_id,
        lease_token=final_claim.lease_token or "",
        acknowledgement_sha256=digest("publication-ack"),
        acknowledgement_ref="publication-ack:final",
        expected_revision=final_claim.revision,
        idempotency_key="ack-final",
    )
    assert acked.state == "acked"
    assert store.get_release("tenant-a", release.notice_id, 1).state == "published"


def test_default_lease_token_prefix_accepts_urlsafe_leading_underscore(
    monkeypatch, tmp_path: Path
) -> None:
    actor = {"value": "release-author"}
    clock = MutableClock()
    monkeypatch.setattr(
        notice.secrets, "token_urlsafe", lambda _size: "_leading-token"
    )
    store = notice.PrivacyNoticeGovernanceStore(
        tmp_path / "default-lease-token.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        signing_key_resolver=lambda _tenant, _ref: b"n" * 32,
        clock=clock,
    )
    create_policy(store)
    release = create_release(store, clock)
    approved = approve_release(store, actor, release, suffix="default-token")
    actor["value"] = "lease-worker"
    store.schedule_release(
        "tenant-a",
        release.notice_id,
        release.version,
        activate_at=clock() + 1,
        expected_release_sha256=release.definition_sha256,
        max_attempts=3,
        expected_revision=approved.state_revision,
        idempotency_key="schedule-default-token",
    )
    clock.advance(1)
    claimed = store.claim_publication_intents(
        "tenant-a", limit=1, lease_seconds=30
    )
    assert claimed[0].lease_token == "lease:_leading-token"


def test_exact_effective_resolution_rollback_and_independent_authorization(
    authority,
) -> None:
    store, actor, clock = authority
    create_policy(store)
    first = publish_release(
        store,
        actor,
        clock,
        create_release(store, clock, key="release-1"),
        suffix="one",
    )
    actor["value"] = "release-author"
    second_definition = create_release(
        store,
        clock,
        expected_latest_version=1,
        key="release-2",
    )
    second = publish_release(
        store, actor, clock, second_definition, suffix="two"
    )
    assert store.current_effective_release(
        "tenant-a", "property-main", "eu", "en-US"
    ).version == 2
    with pytest.raises(notice.PrivacyNoticeNotFound):
        store.current_effective_release(
            "tenant-a", "property-main", "eu", "de-DE"
        )
    actor["value"] = second.created_by
    with pytest.raises(notice.PrivacyNoticePermissionDenied, match="independently"):
        store.rollback_release(
            "tenant-a",
            second.notice_id,
            second.version,
            target_version=first.version,
            reason_code="superseding_defect",
            max_attempts=3,
            expected_revision=second.state_revision,
            idempotency_key="self-rollback",
        )
    actor["value"] = "independent-release-admin"
    rolled_back = store.rollback_release(
        "tenant-a",
        second.notice_id,
        second.version,
        target_version=first.version,
        reason_code="superseding_defect",
        max_attempts=3,
        expected_revision=second.state_revision,
        idempotency_key="rollback",
    )
    assert rolled_back.state == "rolled_back"
    assert rolled_back.rollback_target_version == 1
    assert store.current_effective_release(
        "tenant-a", "property-main", "eu", "en-US"
    ).version == 1


def test_governed_regulatory_update_requires_resolver_and_human_review(authority) -> None:
    store, actor, clock = authority
    create_policy(store)
    base = create_release(store, clock)
    actor["value"] = "proposal-author"
    proposal = store.create_update_proposal(
        "tenant-a",
        "proposal-2",
        notice_id=base.notice_id,
        base_version=base.version,
        policy_sha256=digest("policy-2"),
        content_sha256=digest("content-2"),
        configuration_sha256=digest("configuration-2"),
        consent_publication_ref="consent-publication:2",
        regulatory_citations=[
            {
                "document_ref": "regdoc:approved-1",
                "source_ref": "regsource:authority-1",
                "evidence_sha256": digest("regulatory-evidence"),
            }
        ],
        reason_codes=["regulatory_change_review"],
        retained_until=clock() + 200,
        idempotency_key="proposal",
    )
    assert proposal.status == "pending_review"
    assert store.get_release("tenant-a", base.notice_id, 1).state == "draft"
    with pytest.raises(notice.PrivacyNoticePermissionDenied, match="distinct"):
        store.review_update_proposal(
            "tenant-a",
            proposal.proposal_id,
            decision="approved",
            expected_revision=proposal.revision,
            idempotency_key="self-review",
        )
    actor["value"] = "proposal-reviewer"
    approved = store.review_update_proposal(
        "tenant-a",
        proposal.proposal_id,
        decision="approved",
        expected_revision=proposal.revision,
        idempotency_key="proposal-review",
    )
    assert approved.status == "approved"
    actor["value"] = "release-author"
    second = create_release(
        store,
        clock,
        expected_latest_version=1,
        key="release-from-proposal",
        update_proposal_ref=proposal.proposal_id,
    )
    assert second.update_proposal_ref == proposal.proposal_id
    assert second.state == "draft"


def test_signed_export_retention_tamper_and_no_raw_content_or_secrets(authority) -> None:
    store, actor, clock = authority
    create_policy(store)
    release = publish_release(
        store,
        actor,
        clock,
        create_release(store, clock),
        suffix="retention",
    )
    exported = store.export_notice(
        "tenant-a",
        release.notice_id,
        "notice-export",
        signing_key_ref="vault:notice-key-v1",
        retained_until=clock() + 100,
        idempotency_key="export",
    )
    assert store.get_export("tenant-a", exported.export_id) == exported
    database_bytes = store.path.read_bytes()
    wal_path = Path(f"{store.path}-wal")
    if wal_path.exists():
        database_bytes += wal_path.read_bytes()
    for forbidden in (
        "<html>raw privacy notice</html>",
        "customer@example.test",
        "literal-provider-secret",
    ):
        assert forbidden.encode() not in database_bytes
    with pytest.raises(notice.PrivacyNoticeValidationError):
        store.create_release(
            "tenant-a",
            "unsafe",
            property_id="property-main",
            jurisdictions=["eu"],
            locales=["en-US"],
            policy_sha256=digest("p"),
            content_sha256=digest("c"),
            configuration_sha256=digest("x"),
            consent_publication_ref="<html>raw privacy notice</html>",
            approval_policy_id="notice-policy",
            effective_from=clock(),
            effective_until=clock() + 100,
            retained_until=clock() + 200,
            expected_latest_version=0,
            idempotency_key="unsafe",
        )
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT payload_json FROM notice_exports WHERE tenant_id=? AND export_id=?",
            ("tenant-a", exported.export_id),
        ).fetchone()
        payload = json.loads(row[0])
        payload["signature_hmac_sha256"] = "0" * 64
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        connection.execute(
            "UPDATE notice_exports SET payload_json=?,integrity_sha256=? "
            "WHERE tenant_id=? AND export_id=?",
            (
                canonical,
                hashlib.sha256(canonical.encode("ascii")).hexdigest(),
                "tenant-a",
                exported.export_id,
            ),
        )
    with pytest.raises(notice.PrivacyNoticeIntegrityError, match="signature"):
        store.get_export("tenant-a", exported.export_id)

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "DELETE FROM notice_exports WHERE tenant_id=?", ("tenant-a",)
        )
    clock.advance(401)
    purged = store.purge_expired(
        "tenant-a", cutoff=clock(), idempotency_key="purge"
    )
    assert purged == {"exports": 0, "proposals": 0, "releases": 1}
    with pytest.raises(notice.PrivacyNoticeNotFound):
        store.get_release("tenant-a", release.notice_id, release.version)
    store.verify_integrity("tenant-a")


def test_honest_boundaries() -> None:
    assert notice.PrivacyNoticeGovernanceStore.product_boundaries() == {
        "provider_neutral": True,
        "network_io": False,
        "provider_writes": False,
        "legal_advice": False,
        "maintained_notice_content": False,
        "sdk_deployment": False,
        "site_mutation": False,
        "accessibility_acceptance": False,
        "legal_acceptance": False,
        "customer_acceptance": False,
        "automatic_legal_applicability_inference": False,
        "automatic_publication": False,
        "raw_html_persisted": False,
        "pii_persisted": False,
        "secret_values_persisted": False,
        "live_acceptance_verified": False,
    }
