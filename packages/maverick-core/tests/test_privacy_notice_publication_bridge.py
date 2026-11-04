from __future__ import annotations

import hashlib
import inspect
import itertools
import json
import sqlite3
from pathlib import Path

import pytest
from maverick.consent_publishing import (
    ConsentPublishingError,
    ConsentPublishingStore,
    PublishingConflict,
    PublishingIdempotencyConflict,
    PublishingValidationError,
)
from maverick.privacy_notice_governance import PrivacyNoticeGovernanceStore
from maverick.privacy_notice_publication_bridge import (
    ConsentPublicationTarget,
    PrivacyNoticePublicationBridge,
)


class MutableClock:
    def __init__(self, value: float = 2_300_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class UncertainOnceConsentStore(ConsentPublishingStore):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.raise_after_publish = True

    def publish(self, *args, **kwargs):
        result = super().publish(*args, **kwargs)
        if self.raise_after_publish:
            self.raise_after_publish = False
            raise TimeoutError("simulated lost local response")
        return result


class UncertainWithdrawOnceConsentStore(ConsentPublishingStore):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.raise_after_withdraw = True

    def withdraw(self, *args, **kwargs):
        result = super().withdraw(*args, **kwargs)
        if self.raise_after_withdraw:
            self.raise_after_withdraw = False
            raise TimeoutError("simulated lost withdrawal response")
        return result


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def make_stores(
    tmp_path: Path,
    *,
    uncertain: bool = False,
    uncertain_withdraw: bool = False,
) -> tuple[PrivacyNoticeGovernanceStore, ConsentPublishingStore, dict[str, str], MutableClock]:
    actor = {"value": "release-author"}
    clock = MutableClock()
    token_ids = itertools.count(1)
    publication_ids = itertools.count(1)
    notice_store = PrivacyNoticeGovernanceStore(
        tmp_path / "notice.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        signing_key_resolver=lambda _tenant, _key_ref: b"n" * 32,
        clock=clock,
        token_factory=lambda: f"lease-token-{next(token_ids)}",
    )
    if uncertain and uncertain_withdraw:
        raise ValueError("only one simulated uncertainty mode can be enabled")
    store_type = (
        UncertainOnceConsentStore
        if uncertain
        else UncertainWithdrawOnceConsentStore
        if uncertain_withdraw
        else ConsentPublishingStore
    )
    consent_store = store_type(
        tmp_path / "consent.sqlite3",
        clock=clock,
        id_factory=lambda prefix: f"{prefix}-{next(publication_ids)}",
    )
    return notice_store, consent_store, actor, clock


def seed_consent(
    store: ConsentPublishingStore,
    *,
    tenant: str = "tenant-a",
    version: int = 1,
) -> dict:
    expected = version - 1
    if version == 1:
        store.upsert_property(
            tenant,
            "property-main",
            kind="web",
            consent_group_id="consumer-global",
            web_domains=["example.com"],
            origin_allowlist=["https://www.example.com"],
            expected_revision=0,
            idempotency_key="property-main",
        )
    store.put_purpose_version(
        tenant,
        "analytics",
        version,
        title_key="purpose.title",
        description_key="purpose.description",
        lawful_basis="consent",
        required=False,
        default_choice="denied",
        expected_current_version=expected,
        idempotency_key=f"purpose-{version}",
    )
    store.put_notice_version(
        tenant,
        "privacy-notice",
        version,
        title_key="notice.title",
        body_key="notice.body",
        document_sha256=digest(f"notice-document-{version}"),
        expected_current_version=expected,
        idempotency_key=f"notice-{version}",
    )
    store.put_translation_version(
        tenant,
        "consumer-copy",
        "en-US",
        version,
        messages={
            "purpose.title": f"Analytics {version}",
            "purpose.description": "Measure service performance",
            "notice.title": "Privacy choices",
            "notice.body": f"Notice version {version}",
            "template.title": "Privacy",
            "template.body": "Control your preferences",
            "action.accept": "Accept",
            "action.reject": "Reject",
        },
        expected_current_version=expected,
        idempotency_key=f"translation-{version}",
    )
    store.put_template_version(
        tenant,
        "standard-banner",
        version,
        surface="banner",
        title_key="template.title",
        body_key="template.body",
        actions={
            "accept_all": "action.accept",
            "reject_all": "action.reject",
        },
        theme_token_id="brand-default",
        expected_current_version=expected,
        idempotency_key=f"template-{version}",
    )
    store.put_rule_group_version(
        tenant,
        "production-rules",
        version,
        rules=[
            {
                "rule_id": "global",
                "priority": 1,
                "jurisdictions": ["us-ca"],
                "locales": ["en-US"],
                "default_locale": "en-US",
                "consent_mode": "opt_in",
                "purposes": [{"id": "analytics", "version": version}],
                "notice": {"id": "privacy-notice", "version": version},
                "template": {"id": "standard-banner", "version": version},
                "translation_catalog_id": "consumer-copy",
                "translation_versions": {"en-US": version},
            }
        ],
        expected_current_version=expected,
        idempotency_key=f"rule-group-{version}",
    )
    return store.preview(tenant, "property-main", "production-rules", version)


def create_notice_release(
    store: PrivacyNoticeGovernanceStore,
    actor: dict[str, str],
    clock: MutableClock,
    preview: dict,
    *,
    version: int,
    configuration_sha256: str | None = None,
    approval_ttl_seconds: int = 10_000,
) -> object:
    tenant = "tenant-a"
    if version == 1:
        store.set_approval_policy(
            tenant,
            "notice-policy",
            required_roles=["privacy", "legal"],
            quorum=2,
            approval_ttl_seconds=approval_ttl_seconds,
            expected_revision=0,
            idempotency_key="notice-policy",
        )
    rule_group_sha = preview["bundle"]["rule_group"]["resource_sha256"]
    actor["value"] = "release-author"
    release = store.create_release(
        tenant,
        "privacy-main",
        property_id="property-main",
        jurisdictions=["us-ca"],
        locales=["en-US"],
        policy_sha256=rule_group_sha,
        content_sha256=digest(f"notice-document-{version}"),
        configuration_sha256=configuration_sha256 or preview["bundle_sha256"],
        consent_publication_ref=f"consent-binding:{version}",
        approval_policy_id="notice-policy",
        effective_from=clock(),
        effective_until=clock() + 5_000,
        retained_until=clock() + 6_000,
        expected_latest_version=version - 1,
        idempotency_key=f"release-{version}",
    )
    reviewing = store.submit_for_review(
        tenant,
        release.notice_id,
        release.version,
        expected_revision=release.state_revision,
        idempotency_key=f"review-{version}",
    )
    actor["value"] = f"privacy-approver-{version}"
    privacy_approved = store.approve_release(
        tenant,
        release.notice_id,
        release.version,
        role="privacy",
        expected_release_sha256=release.definition_sha256,
        expected_revision=reviewing.state_revision,
        idempotency_key=f"privacy-approval-{version}",
    )
    actor["value"] = f"legal-approver-{version}"
    approved = store.approve_release(
        tenant,
        release.notice_id,
        release.version,
        role="legal",
        expected_release_sha256=release.definition_sha256,
        expected_revision=privacy_approved.state_revision,
        idempotency_key=f"legal-approval-{version}",
    )
    actor["value"] = "release-scheduler"
    store.schedule_release(
        tenant,
        release.notice_id,
        release.version,
        activate_at=clock() + 1,
        expected_release_sha256=release.definition_sha256,
        max_attempts=3,
        expected_revision=approved.state_revision,
        idempotency_key=f"schedule-{version}",
    )
    clock.advance(1)
    return release


class TargetAuthority:
    def __init__(self, consent_store: ConsentPublishingStore) -> None:
        self.consent_store = consent_store
        self.expected_revisions: dict[str, int] = {}
        self.publication_ids: dict[str, str] = {}
        self.tamper_ref = False

    def __call__(self, intent, release, rollback_release):
        selected = rollback_release or release
        history = self.consent_store.publication_history(
            selected.tenant_id,
            selected.property_id,
            limit=500,
        )["items"]
        current_revision = history[0]["publication_revision"] if history else 0
        expected_revision = self.expected_revisions.setdefault(
            intent.intent_id,
            current_revision,
        )
        return ConsentPublicationTarget(
            tenant_id=selected.tenant_id,
            intent_id=intent.intent_id,
            action=intent.action,
            intent_release_sha256=release.definition_sha256,
            notice_id=selected.notice_id,
            selected_release_version=selected.version,
            selected_release_sha256=selected.definition_sha256,
            consent_publication_ref=(
                "wrong-binding" if self.tamper_ref else selected.consent_publication_ref
            ),
            property_id=selected.property_id,
            rule_group_id="production-rules",
            rule_group_version=selected.version,
            notice_resource_id="privacy-notice",
            notice_resource_version=selected.version,
            expected_property_revision=1,
            expected_publication_revision=expected_revision,
            target_publication_id=(
                self.publication_ids.get(selected.consent_publication_ref)
                if intent.action == "rollback"
                else None
            ),
        )


def make_bridge(
    notice_store: PrivacyNoticeGovernanceStore,
    consent_store: ConsentPublishingStore,
    target_authority: TargetAuthority,
) -> PrivacyNoticePublicationBridge:
    return PrivacyNoticePublicationBridge(
        notice_store=notice_store,
        consent_store=consent_store,
        tenant_resolver=lambda: "tenant-a",
        target_resolver=target_authority,
        lease_seconds=60,
        retry_delay_seconds=0,
    )


def test_publish_certifies_exact_digests_mutates_and_acknowledges(tmp_path: Path) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path)
    preview = seed_consent(consent_store)
    release = create_notice_release(
        notice_store,
        actor,
        clock,
        preview,
        version=1,
    )
    authority = TargetAuthority(consent_store)
    actor["value"] = "publication-worker"
    result = make_bridge(notice_store, consent_store, authority).process_next()

    assert result.status == "applied"
    assert result.action == "publish"
    assert result.release_sha256 == release.definition_sha256
    assert result.acknowledgement_sha256 == digest(
        json.dumps(
            result.evidence,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    assert "lease_token" not in str(result.evidence).lower()
    history = consent_store.publication_history("tenant-a", "property-main")
    assert len(history["items"]) == 1
    assert history["items"][0]["publication_id"] == result.publication_id
    published = notice_store.get_release("tenant-a", "privacy-main", 1)
    assert published.state == "published"
    assert PrivacyNoticePublicationBridge.product_boundaries()["network_io"] is False


def test_exact_current_bundle_is_accepted_as_no_change(tmp_path: Path) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path)
    preview = seed_consent(consent_store)
    existing = consent_store.publish(
        "tenant-a",
        "property-main",
        "production-rules",
        1,
        expected_property_revision=1,
        expected_publication_revision=0,
        idempotency_key="existing-publication",
    )
    create_notice_release(notice_store, actor, clock, preview, version=1)
    actor["value"] = "publication-worker"
    result = make_bridge(
        notice_store,
        consent_store,
        TargetAuthority(consent_store),
    ).process_next()

    assert result.status == "no_change"
    assert result.publication_id == existing["publication_id"]
    assert len(consent_store.publication_history("tenant-a", "property-main")["items"]) == 1
    assert notice_store.get_release("tenant-a", "privacy-main", 1).state == "published"


def test_digest_and_server_binding_mismatches_fail_before_mutation(tmp_path: Path) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path)
    preview = seed_consent(consent_store)
    create_notice_release(
        notice_store,
        actor,
        clock,
        preview,
        version=1,
        configuration_sha256=digest("wrong-configuration"),
    )
    actor["value"] = "publication-worker"
    mismatch = make_bridge(
        notice_store,
        consent_store,
        TargetAuthority(consent_store),
    ).process_next()
    assert mismatch.status == "failed"
    assert mismatch.error_code == "digest_mismatch"
    assert consent_store.publication_history("tenant-a", "property-main")["items"] == []

    # The ready intent can be retried, but a stale server-side binding also
    # fails closed and still performs no consent mutation.
    authority = TargetAuthority(consent_store)
    authority.tamper_ref = True
    stale = make_bridge(notice_store, consent_store, authority).process_next()
    assert stale.status == "failed"
    assert stale.error_code == "stale_binding"
    assert consent_store.publication_history("tenant-a", "property-main")["items"] == []


def test_revoked_approval_makes_claim_idle_and_prevents_write(tmp_path: Path) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path)
    preview = seed_consent(consent_store)
    create_notice_release(notice_store, actor, clock, preview, version=1)
    actor["value"] = "privacy-approver-1"
    notice_store.revoke_approval(
        "tenant-a",
        "privacy-main",
        1,
        role="privacy",
        expected_approval_revision=1,
        idempotency_key="revoke-before-worker",
    )
    actor["value"] = "publication-worker"

    result = make_bridge(
        notice_store,
        consent_store,
        TargetAuthority(consent_store),
    ).process_next()
    assert result.status == "idle"
    assert consent_store.publication_history("tenant-a", "property-main")["items"] == []


def test_expired_approval_makes_claim_idle_while_release_window_remains_open(
    tmp_path: Path,
) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path)
    preview = seed_consent(consent_store)
    create_notice_release(
        notice_store,
        actor,
        clock,
        preview,
        version=1,
        approval_ttl_seconds=60,
    )
    clock.advance(61)
    actor["value"] = "publication-worker"

    result = make_bridge(
        notice_store,
        consent_store,
        TargetAuthority(consent_store),
    ).process_next()
    assert result.status == "idle"
    release = notice_store.get_release("tenant-a", "privacy-main", 1)
    assert release.effective_from <= clock() < release.effective_until
    assert consent_store.publication_history("tenant-a", "property-main")["items"] == []


def test_uncertain_local_response_recovers_with_same_idempotency_binding(
    tmp_path: Path,
) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path, uncertain=True)
    preview = seed_consent(consent_store)
    create_notice_release(notice_store, actor, clock, preview, version=1)
    authority = TargetAuthority(consent_store)
    bridge = make_bridge(notice_store, consent_store, authority)
    actor["value"] = "publication-worker"

    uncertain = bridge.process_next()
    assert uncertain.status == "ambiguous"
    assert uncertain.error_code == "mutation_outcome_unknown"
    first = consent_store.publication_history("tenant-a", "property-main")["items"]
    assert len(first) == 1
    assert notice_store.get_release("tenant-a", "privacy-main", 1).state == "scheduled"

    clock.advance(61)
    recovered = bridge.process_next()
    assert recovered.status == "recovered"
    second = consent_store.publication_history("tenant-a", "property-main")["items"]
    assert second == first
    assert notice_store.get_release("tenant-a", "privacy-main", 1).state == "published"


def test_ack_rechecks_revocation_after_write_and_returns_ambiguous(
    tmp_path: Path,
) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path)
    preview = seed_consent(consent_store)
    create_notice_release(notice_store, actor, clock, preview, version=1)
    original_ack = notice_store.ack_publication_intent

    def revoke_then_ack(*args, **kwargs):
        actor["value"] = "privacy-approver-1"
        notice_store.revoke_approval(
            "tenant-a",
            "privacy-main",
            1,
            role="privacy",
            expected_approval_revision=1,
            idempotency_key="revoke-during-ack",
        )
        actor["value"] = "publication-worker"
        return original_ack(*args, **kwargs)

    notice_store.ack_publication_intent = revoke_then_ack  # type: ignore[method-assign]
    actor["value"] = "publication-worker"
    result = make_bridge(
        notice_store,
        consent_store,
        TargetAuthority(consent_store),
    ).process_next()

    assert result.status == "ambiguous"
    assert result.error_code == "acknowledgement_ambiguous"
    assert len(consent_store.publication_history("tenant-a", "property-main")["items"]) == 1
    assert notice_store.get_release("tenant-a", "privacy-main", 1).state == "review"


def test_rollback_revalidates_target_and_uses_exact_prior_publication(
    tmp_path: Path,
) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path)
    authority = TargetAuthority(consent_store)
    bridge = make_bridge(notice_store, consent_store, authority)

    preview1 = seed_consent(consent_store, version=1)
    create_notice_release(notice_store, actor, clock, preview1, version=1)
    actor["value"] = "publication-worker"
    first = bridge.process_next()
    authority.publication_ids["consent-binding:1"] = first.publication_id or ""

    preview2 = seed_consent(consent_store, version=2)
    create_notice_release(notice_store, actor, clock, preview2, version=2)
    actor["value"] = "publication-worker"
    second = bridge.process_next()
    assert second.publication_revision == 2

    current = notice_store.get_release("tenant-a", "privacy-main", 2)
    actor["value"] = "independent-rollback-operator"
    notice_store.rollback_release(
        "tenant-a",
        "privacy-main",
        2,
        target_version=1,
        reason_code="approved-rollback",
        max_attempts=3,
        expected_revision=current.state_revision,
        idempotency_key="rollback-release-2",
    )
    actor["value"] = "publication-worker"
    rolled_back = bridge.process_next()

    assert rolled_back.status == "applied"
    assert rolled_back.action == "rollback"
    assert rolled_back.publication_revision == 3
    head = consent_store.publication_history("tenant-a", "property-main")["items"][0]
    assert head["action"] == "rollback"
    assert head["source_publication_id"] == first.publication_id
    assert head["bundle_sha256"] == preview1["bundle_sha256"]


def test_withdraw_tombstones_active_bundle_and_acknowledges_notice_intent(
    tmp_path: Path,
) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path)
    preview = seed_consent(consent_store)
    create_notice_release(notice_store, actor, clock, preview, version=1)
    actor["value"] = "publication-worker"
    bridge = make_bridge(notice_store, consent_store, TargetAuthority(consent_store))
    published = bridge.process_next()
    before = consent_store.publication_history("tenant-a", "property-main")["items"]

    current = notice_store.get_release("tenant-a", "privacy-main", 1)
    actor["value"] = "independent-withdraw-operator"
    notice_store.withdraw_release(
        "tenant-a",
        "privacy-main",
        1,
        reason_code="emergency-withdrawal",
        max_attempts=3,
        expected_revision=current.state_revision,
        idempotency_key="withdraw-release-1",
    )
    actor["value"] = "publication-worker"
    withdrawn = bridge.process_next()

    assert published.status == "applied"
    assert withdrawn.status == "applied"
    assert withdrawn.error_code is None
    after = consent_store.publication_history("tenant-a", "property-main")["items"]
    assert len(after) == len(before) + 1
    assert after[0]["action"] == "withdraw"
    assert after[0]["source_publication_id"] == before[0]["publication_id"]
    denied = consent_store.resolve_public_configuration(
        "tenant-a",
        "property-main",
        server_origin="https://www.example.com",
        requested_locale="en-US",
    )
    assert denied["allowed"] is False
    assert denied["reason"] == "withdrawn"
    assert notice_store.get_release("tenant-a", "privacy-main", 1).state == "withdrawn"


def test_preapplied_exact_withdrawal_is_accepted_as_no_change(tmp_path: Path) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path)
    preview = seed_consent(consent_store)
    create_notice_release(notice_store, actor, clock, preview, version=1)
    authority = TargetAuthority(consent_store)
    bridge = make_bridge(notice_store, consent_store, authority)
    actor["value"] = "publication-worker"
    published = bridge.process_next()

    current = notice_store.get_release("tenant-a", "privacy-main", 1)
    actor["value"] = "independent-withdraw-operator"
    notice_store.withdraw_release(
        "tenant-a",
        "privacy-main",
        1,
        reason_code="preapplied-withdrawal",
        max_attempts=3,
        expected_revision=current.state_revision,
        idempotency_key="notice-preapplied-withdrawal",
    )
    consent_store.withdraw(
        "tenant-a",
        "property-main",
        expected_property_revision=1,
        expected_publication_revision=1,
        idempotency_key="preapply-consent-withdrawal",
    )
    actor["value"] = "publication-worker"
    no_change = bridge.process_next()

    assert published.status == "applied"
    assert no_change.status == "no_change"
    history = consent_store.publication_history("tenant-a", "property-main")["items"]
    assert [item["action"] for item in history] == ["withdraw", "publish"]


def test_withdraw_refuses_to_tombstone_a_different_current_bundle(tmp_path: Path) -> None:
    notice_store, consent_store, actor, clock = make_stores(tmp_path)
    preview1 = seed_consent(consent_store, version=1)
    create_notice_release(notice_store, actor, clock, preview1, version=1)
    authority = TargetAuthority(consent_store)
    bridge = make_bridge(notice_store, consent_store, authority)
    actor["value"] = "publication-worker"
    assert bridge.process_next().status == "applied"

    seed_consent(consent_store, version=2)
    unrelated = consent_store.publish(
        "tenant-a",
        "property-main",
        "production-rules",
        2,
        expected_property_revision=1,
        expected_publication_revision=1,
        idempotency_key="unrelated-current-bundle",
    )
    current = notice_store.get_release("tenant-a", "privacy-main", 1)
    actor["value"] = "independent-withdraw-operator"
    notice_store.withdraw_release(
        "tenant-a",
        "privacy-main",
        1,
        reason_code="stale-release-withdrawal",
        max_attempts=3,
        expected_revision=current.state_revision,
        idempotency_key="notice-stale-release-withdrawal",
    )
    actor["value"] = "publication-worker"
    rejected = bridge.process_next()

    assert rejected.status == "failed"
    assert rejected.error_code == "digest_mismatch"
    head = consent_store.publication_history("tenant-a", "property-main")["items"][0]
    assert head == unrelated


def test_uncertain_withdrawal_recovers_without_a_second_tombstone(tmp_path: Path) -> None:
    notice_store, consent_store, actor, clock = make_stores(
        tmp_path,
        uncertain_withdraw=True,
    )
    preview = seed_consent(consent_store)
    create_notice_release(notice_store, actor, clock, preview, version=1)
    authority = TargetAuthority(consent_store)
    bridge = make_bridge(notice_store, consent_store, authority)
    actor["value"] = "publication-worker"
    assert bridge.process_next().status == "applied"

    current = notice_store.get_release("tenant-a", "privacy-main", 1)
    actor["value"] = "independent-withdraw-operator"
    notice_store.withdraw_release(
        "tenant-a",
        "privacy-main",
        1,
        reason_code="uncertain-withdrawal",
        max_attempts=3,
        expected_revision=current.state_revision,
        idempotency_key="notice-uncertain-withdrawal",
    )
    actor["value"] = "publication-worker"
    uncertain = bridge.process_next()
    assert uncertain.status == "ambiguous"
    assert uncertain.error_code == "mutation_outcome_unknown"
    first_history = consent_store.publication_history(
        "tenant-a",
        "property-main",
    )["items"]
    assert [item["action"] for item in first_history] == ["withdraw", "publish"]

    clock.advance(61)
    recovered = bridge.process_next()
    assert recovered.status == "recovered"
    assert consent_store.publication_history("tenant-a", "property-main")["items"] == first_history


def test_consent_withdraw_has_exact_cas_replay_and_no_change_semantics(
    tmp_path: Path,
) -> None:
    _notice_store, consent_store, _actor, _clock = make_stores(tmp_path)
    seed_consent(consent_store)
    published = consent_store.publish(
        "tenant-a",
        "property-main",
        "production-rules",
        1,
        expected_property_revision=1,
        expected_publication_revision=0,
        idempotency_key="publish-before-withdraw",
    )
    withdrawn = consent_store.withdraw(
        "tenant-a",
        "property-main",
        expected_property_revision=1,
        expected_publication_revision=1,
        idempotency_key="withdraw-once",
    )
    assert withdrawn["action"] == "withdraw"
    assert withdrawn["publication_revision"] == 2
    assert withdrawn["source_publication_id"] == published["publication_id"]

    replay = consent_store.withdraw(
        "tenant-a",
        "property-main",
        expected_property_revision=1,
        expected_publication_revision=1,
        idempotency_key="withdraw-once",
    )
    assert replay == withdrawn
    with pytest.raises(PublishingIdempotencyConflict):
        consent_store.withdraw(
            "tenant-a",
            "property-main",
            expected_property_revision=1,
            expected_publication_revision=2,
            idempotency_key="withdraw-once",
        )
    no_change = consent_store.withdraw(
        "tenant-a",
        "property-main",
        expected_property_revision=1,
        expected_publication_revision=2,
        idempotency_key="withdraw-no-change",
    )
    assert no_change == withdrawn
    with pytest.raises(PublishingConflict):
        consent_store.withdraw(
            "tenant-a",
            "property-main",
            expected_property_revision=1,
            expected_publication_revision=1,
            idempotency_key="withdraw-stale-cas",
        )
    history = consent_store.publication_history("tenant-a", "property-main")["items"]
    assert [item["action"] for item in history] == ["withdraw", "publish"]


def test_withdrawal_public_denial_rollback_restore_and_tombstone_target_rejection(
    tmp_path: Path,
) -> None:
    _notice_store, consent_store, _actor, _clock = make_stores(tmp_path)
    seed_consent(consent_store)
    published = consent_store.publish(
        "tenant-a",
        "property-main",
        "production-rules",
        1,
        expected_property_revision=1,
        expected_publication_revision=0,
        idempotency_key="publish-for-restore",
    )
    withdrawn = consent_store.withdraw(
        "tenant-a",
        "property-main",
        expected_property_revision=1,
        expected_publication_revision=1,
        idempotency_key="withdraw-for-restore",
    )
    denied = consent_store.resolve_public_configuration(
        "tenant-a",
        "property-main",
        server_origin="https://www.example.com",
        requested_locale="en-US",
    )
    assert denied["allowed"] is False
    assert denied["reason"] == "withdrawn"

    with pytest.raises(PublishingValidationError, match="tombstone"):
        consent_store.rollback(
            "tenant-a",
            "property-main",
            withdrawn["publication_id"],
            expected_property_revision=1,
            expected_publication_revision=2,
            idempotency_key="reject-tombstone-target",
        )
    restored = consent_store.rollback(
        "tenant-a",
        "property-main",
        published["publication_id"],
        expected_property_revision=1,
        expected_publication_revision=2,
        idempotency_key="restore-active-publication",
    )
    assert restored["action"] == "rollback"
    assert restored["publication_revision"] == 3
    allowed = consent_store.resolve_public_configuration(
        "tenant-a",
        "property-main",
        server_origin="https://www.example.com",
        jurisdiction="us-ca",
        requested_locale="en-US",
    )
    assert allowed["allowed"] is True
    assert allowed["publication"]["publication_id"] == restored["publication_id"]


def test_withdrawal_history_certifies_tombstone_digest(tmp_path: Path) -> None:
    _notice_store, consent_store, _actor, _clock = make_stores(tmp_path)
    seed_consent(consent_store)
    consent_store.publish(
        "tenant-a",
        "property-main",
        "production-rules",
        1,
        expected_property_revision=1,
        expected_publication_revision=0,
        idempotency_key="publish-for-integrity",
    )
    withdrawn = consent_store.withdraw(
        "tenant-a",
        "property-main",
        expected_property_revision=1,
        expected_publication_revision=1,
        idempotency_key="withdraw-for-integrity",
    )
    with sqlite3.connect(consent_store.path) as connection:
        connection.execute("DROP TRIGGER consent_publications_no_update")
        connection.execute(
            "UPDATE consent_publications SET bundle_json=? WHERE publication_id=?",
            ('{"schema":"tampered"}', withdrawn["publication_id"]),
        )
    with pytest.raises(ConsentPublishingError, match="bundle"):
        consent_store.publication_history("tenant-a", "property-main")


def test_v1_publication_store_migrates_without_changing_existing_history(
    tmp_path: Path,
) -> None:
    _notice_store, consent_store, _actor, clock = make_stores(tmp_path)
    seed_consent(consent_store)
    published = consent_store.publish(
        "tenant-a",
        "property-main",
        "production-rules",
        1,
        expected_property_revision=1,
        expected_publication_revision=0,
        idempotency_key="publish-before-v1-migration",
    )
    with sqlite3.connect(consent_store.path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("DROP TRIGGER consent_publications_no_update")
        connection.execute("DROP TRIGGER consent_publications_no_delete")
        connection.execute("DROP INDEX consent_publications_property")
        connection.execute("ALTER TABLE consent_publications RENAME TO consent_publications_v2")
        connection.execute(
            """
            CREATE TABLE consent_publications (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant TEXT NOT NULL,
                publication_id TEXT NOT NULL,
                property_id TEXT NOT NULL,
                publication_revision INTEGER NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('publish', 'rollback')),
                source_publication_id TEXT,
                property_revision INTEGER NOT NULL,
                bundle_json TEXT NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                publication_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE (tenant, publication_id),
                UNIQUE (tenant, property_id, publication_revision),
                FOREIGN KEY (tenant, property_id)
                    REFERENCES publishing_properties(tenant, property_id)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO consent_publications
            SELECT * FROM consent_publications_v2
            """
        )
        connection.execute("DROP TABLE consent_publications_v2")
        connection.execute(
            "CREATE INDEX consent_publications_property ON consent_publications("
            "tenant,property_id,publication_revision DESC)"
        )
        connection.execute("UPDATE publishing_meta SET value='1' WHERE key='schema_version'")
    migrated = ConsentPublishingStore(
        consent_store.path,
        clock=clock,
        id_factory=lambda prefix: f"{prefix}-after-migration",
    )
    assert migrated.publication_history("tenant-a", "property-main")["items"] == [published]
    withdrawn = migrated.withdraw(
        "tenant-a",
        "property-main",
        expected_property_revision=1,
        expected_publication_revision=1,
        idempotency_key="withdraw-after-v1-migration",
    )
    assert withdrawn["action"] == "withdraw"
    with sqlite3.connect(consent_store.path) as connection:
        version = connection.execute(
            "SELECT value FROM publishing_meta WHERE key='schema_version'"
        ).fetchone()
        schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='consent_publications'"
        ).fetchone()
    assert version == ("2",)
    assert schema is not None and "withdraw" in schema[0]


def test_worker_surface_accepts_no_request_selected_authority() -> None:
    parameters = inspect.signature(PrivacyNoticePublicationBridge.process_next).parameters
    assert set(parameters) == {"self"}
    target_fields = set(ConsentPublicationTarget.__dataclass_fields__)
    assert not {"actor", "actor_ref", "content", "credential", "key_ref"}.intersection(
        target_fields
    )
    withdraw_parameters = inspect.signature(ConsentPublishingStore.withdraw).parameters
    assert set(withdraw_parameters) == {
        "self",
        "tenant_id",
        "property_id",
        "expected_property_revision",
        "expected_publication_revision",
        "idempotency_key",
        # A guard callback and the digest that binds the withdrawal receipt to
        # its reviewed requester; neither selects content, target or credential.
        "before_write",
        "receipt_owner",
    }
