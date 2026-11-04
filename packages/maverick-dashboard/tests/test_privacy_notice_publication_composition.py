from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest
from maverick.privacy_notice_governance import NoticeRelease, PublicationIntent
from maverick_dashboard import privacy_notice_publication_composition as composition


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config(*, ref: str = "consent-binding:1"):
    return {
        "consent_preferences": {"enable": True, "publishing": {"enable": True}},
        "privacy_automation": {
            "enable": True,
            "notice_governance": {
                "enable": True,
                "publication_runtime": {
                    "enable": True,
                    "scheduler_enable": True,
                    "active_tenants": ["tenant-a"],
                    "poll_seconds": 30,
                    "retry_max_seconds": 300,
                    "tenant_limit": 10,
                    "lease_seconds": 60,
                    "retry_delay_seconds": 20,
                    "bindings": {
                        "primary": {
                            "tenant_id": "tenant-a",
                            "notice_id": "privacy-main",
                            "consent_publication_ref": ref,
                            "property_id": "property-main",
                            "rule_group_id": "production-rules",
                            "rule_group_version": 7,
                            "notice_resource_id": "privacy-notice",
                            "notice_resource_version": 4,
                        }
                    },
                },
            },
        },
    }


def _release() -> NoticeRelease:
    return NoticeRelease(
        tenant_id="tenant-a",
        notice_id="privacy-main",
        version=9,
        property_id="property-main",
        jurisdictions=("us-ca",),
        locales=("en-US",),
        policy_sha256=_digest("rule-group"),
        content_sha256=_digest("notice-document"),
        configuration_sha256=_digest("bundle"),
        consent_publication_ref="consent-binding:1",
        approval_policy_id="notice-policy",
        approval_policy_sha256=_digest("approval-policy"),
        required_roles=("privacy", "legal"),
        quorum=2,
        approval_ttl_seconds=300,
        effective_from=2_300_000_000.0,
        effective_until=2_300_001_000.0,
        retained_until=2_300_002_000.0,
        update_proposal_ref=None,
        definition_sha256=_digest("release-definition"),
        state="scheduled",
        activate_at=2_300_000_001.0,
        created_by="author",
        approved_digest_sha256=_digest("approvals"),
        rollback_target_version=None,
        state_revision=5,
        created_at=2_300_000_000.0,
        updated_at=2_300_000_001.0,
        integrity_sha256=_digest("release-integrity"),
    )


def _intent(action: str = "publish") -> PublicationIntent:
    release = _release()
    return PublicationIntent(
        tenant_id="tenant-a",
        intent_id="intent-1",
        notice_id=release.notice_id,
        release_version=release.version,
        action=action,
        target_version=None,
        release_sha256=release.definition_sha256,
        consent_publication_ref=release.consent_publication_ref,
        state="leased",
        attempts=0,
        max_attempts=3,
        recovery_count=0,
        next_attempt_at=2_300_000_001.0,
        lease_owner="worker",
        lease_token="lease-1",
        lease_until=2_300_000_060.0,
        last_error_code=None,
        acknowledgement_sha256=None,
        acknowledgement_ref=None,
        revision=2,
        created_at=2_300_000_000.0,
        updated_at=2_300_000_001.0,
        integrity_sha256=_digest("intent"),
    )


def _preview(release: NoticeRelease):
    return {
        "schema": "lightwork.consent-preview.v1",
        "bundle": {
            "schema": "lightwork.consent-preview.v1",
            "property": {"property_id": "property-main", "revision": 3},
            "rule_group": {
                "resource_kind": "rule_group",
                "resource_id": "production-rules",
                "version": 7,
                "resource_sha256": release.policy_sha256,
            },
            "resources": [
                {
                    "resource_kind": "notice",
                    "resource_id": "privacy-notice",
                    "locale": "",
                    "version": 4,
                    "payload": {"document_sha256": release.content_sha256},
                }
            ],
        },
        "bundle_sha256": release.configuration_sha256,
    }


def test_settings_are_closed_exact_and_require_consent_authority() -> None:
    settings = composition.settings_from_config(_config())
    assert settings.enabled is True
    assert settings.scheduler_enabled is True
    assert settings.active_tenants == ("tenant-a",)
    assert settings.bindings[0].rule_group_version == 7
    assert len(settings.bindings[0].authority_sha256) == 64

    duplicate = _config()
    duplicate["privacy_automation"]["notice_governance"]["publication_runtime"][
        "bindings"
    ]["second"] = dict(
        duplicate["privacy_automation"]["notice_governance"]["publication_runtime"][
            "bindings"
        ]["primary"]
    )
    with pytest.raises(
        composition.PrivacyNoticePublicationCompositionError,
        match="references must be unique",
    ):
        composition.settings_from_config(duplicate)

    missing_consent = _config()
    missing_consent["consent_preferences"]["publishing"]["enable"] = False
    with pytest.raises(
        composition.PrivacyNoticePublicationCompositionError,
        match="requires notice governance and consent publishing",
    ):
        composition.settings_from_config(missing_consent)


def test_resolver_rereads_authority_and_derives_exact_cas_target() -> None:
    release = _release()
    preview = _preview(release)
    notice = SimpleNamespace(get_release=lambda *_args: release)

    class Consent:
        def __init__(self) -> None:
            self.previews = 0

        def preview(self, *_args):
            self.previews += 1
            return preview

        def publication_history(self, *_args, **_kwargs):
            return {
                "items": [
                    {
                        "publication_id": "publication-4",
                        "publication_revision": 4,
                        "property_id": "property-main",
                        "property_revision": 3,
                        "action": "publish",
                        "bundle_sha256": _digest("other"),
                    }
                ],
                "truncated": False,
            }

    consent = Consent()
    resolver = composition.ExactPublicationTargetResolver(
        tenant_id="tenant-a",
        settings=composition.settings_from_config(_config()),
        notice_store=notice,
        consent_store=consent,
    )
    target = resolver(_intent(), release, None)
    assert target.expected_property_revision == 3
    assert target.expected_publication_revision == 4
    assert target.rule_group_version == 7
    assert target.notice_resource_version == 4
    assert consent.previews == 2


def test_release_rotation_and_binding_rekey_fail_before_consent_preview() -> None:
    release = _release()
    rotated = replace(release, definition_sha256=_digest("rotated"))

    class Consent:
        previews = 0

        def preview(self, *_args):
            self.previews += 1
            return _preview(release)

    consent = Consent()
    resolver = composition.ExactPublicationTargetResolver(
        tenant_id="tenant-a",
        settings=composition.settings_from_config(_config()),
        notice_store=SimpleNamespace(get_release=lambda *_args: rotated),
        consent_store=consent,
    )
    with pytest.raises(
        composition.PrivacyNoticePublicationCompositionError,
        match="release authority changed",
    ):
        resolver(_intent(), release, None)
    assert consent.previews == 0

    rekeyed = composition.ExactPublicationTargetResolver(
        tenant_id="tenant-a",
        settings=composition.settings_from_config(_config(ref="consent-binding:2")),
        notice_store=SimpleNamespace(get_release=lambda *_args: release),
        consent_store=consent,
    )
    with pytest.raises(
        composition.PrivacyNoticePublicationCompositionError,
        match="binding is unavailable",
    ):
        rekeyed(_intent(), release, None)
    assert consent.previews == 0


def test_rollback_chooses_oldest_exact_verified_bundle_digest() -> None:
    release = _release()
    preview = _preview(release)
    history = {
        "items": [
            {
                "publication_id": "publication-8",
                "publication_revision": 8,
                "property_id": "property-main",
                "property_revision": 3,
                "action": "rollback",
                "bundle_sha256": release.configuration_sha256,
            },
            {
                "publication_id": "publication-2",
                "publication_revision": 2,
                "property_id": "property-main",
                "property_revision": 3,
                "action": "publish",
                "bundle_sha256": release.configuration_sha256,
            },
        ],
        "truncated": False,
    }
    consent = SimpleNamespace(
        preview=lambda *_args: preview,
        publication_history=lambda *_args, **_kwargs: history,
    )
    resolver = composition.ExactPublicationTargetResolver(
        tenant_id="tenant-a",
        settings=composition.settings_from_config(_config()),
        notice_store=SimpleNamespace(get_release=lambda *_args: release),
        consent_store=consent,
    )
    target = resolver(_intent("rollback"), release, release)
    assert target.target_publication_id == "publication-2"
    assert target.expected_publication_revision == 8


def test_readiness_is_configuration_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        composition,
        "settings_for_tenant",
        lambda _tenant: composition.settings_from_config(_config()),
    )
    ready = composition.readiness(SimpleNamespace(state=SimpleNamespace()), "tenant-a")
    assert ready["configuration_preflight_ready"] is True
    assert ready["executable_ready"] is False
    assert ready["status_opened_tenant_store"] is False
    assert ready["provider_network_io"] is False
    assert ready["site_mutation"] is False
