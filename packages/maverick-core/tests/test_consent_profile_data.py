from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import sqlite3
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from maverick.consent_profile_data import (
    ConsentProfileDataConfigError,
    ConsentProfileDataConflict,
    ConsentProfileDataIntegrityError,
    ConsentProfileDataNotFound,
    ConsentProfileDataPermissionDenied,
    ConsentProfileDataStore,
    ConsentProfileDataValidationError,
    PromptContext,
    PublicProfileAuthority,
    product_boundaries,
    profile_data_enabled,
    require_profile_data_enabled,
)

DAY = 24 * 60 * 60
ENABLED = {
    "consent_preferences": {
        "enable": True,
        "profile_data": {"enable": True},
    }
}


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def environment(
    tmp_path: Path,
) -> tuple[ConsentProfileDataStore, dict[str, str], Clock, Path]:
    actor = {"value": "admin-owner"}
    clock = Clock()
    path = tmp_path / "consent-profile-data.sqlite3"
    store = ConsentProfileDataStore(
        path,
        config_gate=lambda: require_profile_data_enabled(ENABLED),
        principal_resolver=lambda: actor["value"],
        clock=clock,
    )
    return store, actor, clock, path


def _definitions() -> list[dict[str, Any]]:
    return [
        {
            "preference_id": "required-bool",
            "definition_version": 1,
            "label_ref": "label.required-bool",
            "value_type": "boolean",
            "options": [],
            "required": True,
            "expires_after_seconds": 120,
            "retention_seconds": DAY,
        },
        {
            "preference_id": "locale",
            "definition_version": 2,
            "label_ref": "label.locale",
            "value_type": "single_select",
            "options": [
                {"value_id": "us", "label_ref": "option.locale.us"},
                {"value_id": "eu", "label_ref": "option.locale.eu"},
            ],
            "required": False,
            "expires_after_seconds": None,
            "retention_seconds": DAY,
        },
        {
            "preference_id": "channels",
            "definition_version": 1,
            "label_ref": "label.channels",
            "value_type": "multi_select",
            "options": [
                {"value_id": "email", "label_ref": "option.channel.email"},
                {"value_id": "sms", "label_ref": "option.channel.sms"},
            ],
            "required": False,
            "expires_after_seconds": None,
            "retention_seconds": DAY,
        },
    ]


def _publish_catalog(
    store: ConsentProfileDataStore,
    actor: dict[str, str],
    *,
    tenant: str = "tenant-a",
    catalog_id: str = "profile-catalog",
) -> None:
    actor["value"] = "catalog-author"
    created = store.create_catalog_version(
        tenant,
        catalog_id,
        property_id="property-web",
        publication_sha256=_digest("publication"),
        bundle_sha256=_digest("bundle"),
        configuration_sha256=_digest("configuration"),
        policy_id="profile-policy",
        policy_version=3,
        policy_sha256=_digest("policy"),
        definitions=_definitions(),
        retention_seconds=DAY,
        expected_latest_version=0,
        idempotency_key="catalog-create-0001",
    )
    assert created.state == "pending_approval"
    actor["value"] = "catalog-reviewer"
    published = store.approve_catalog_version(
        tenant,
        catalog_id,
        1,
        expected_revision=1,
        idempotency_key="catalog-approve-001",
    )
    assert published.state == "published"


def _authority(
    *,
    tenant: str = "tenant-a",
    profile: str = "profile-001",
    catalog_id: str = "profile-catalog",
    capability_label: str = "profile-capability",
) -> PublicProfileAuthority:
    return PublicProfileAuthority(
        tenant_id=tenant,
        profile_id=profile,
        property_id="property-web",
        catalog_id=catalog_id,
        catalog_version=1,
        publication_sha256=_digest("publication"),
        bundle_sha256=_digest("bundle"),
        configuration_sha256=_digest("configuration"),
        policy_id="profile-policy",
        policy_version=3,
        policy_sha256=_digest("policy"),
        profile_capability_sha256=_digest(capability_label),
    )


def _stages() -> list[dict[str, Any]]:
    return [
        {
            "stage_id": "foundation",
            "priority": 20,
            "prompt_label_ref": "prompt.foundation",
            # Optional is deliberately first: assignment must still put required first.
            "preference_ids": ["locale", "required-bool"],
            "condition": None,
        },
        {
            "stage_id": "purpose-stage",
            "priority": 10,
            "prompt_label_ref": "prompt.channels",
            "preference_ids": ["channels"],
            "condition": {
                "source": "purpose",
                "key": "analytics",
                "operator": "equals",
                "value": "grant",
            },
        },
    ]


def _activate_journey(
    store: ConsentProfileDataStore,
    actor: dict[str, str],
    *,
    tenant: str = "tenant-a",
    journey_id: str = "progressive-profile",
    max_prompts: int = 2,
    cooldown_seconds: int = 60,
    frequency_cap: int = 3,
    frequency_window_seconds: int = 600,
) -> None:
    actor["value"] = "journey-author"
    draft = store.create_journey_version(
        tenant,
        journey_id,
        catalog_id="profile-catalog",
        catalog_version=1,
        stages=_stages(),
        max_prompts=max_prompts,
        cooldown_seconds=cooldown_seconds,
        frequency_cap=frequency_cap,
        frequency_window_seconds=frequency_window_seconds,
        retention_seconds=DAY,
        expected_latest_version=0,
        idempotency_key=f"{journey_id}-create-001",
    )
    assert draft.state == "draft"
    actor["value"] = "journey-reviewer"
    approved = store.approve_journey_version(
        tenant,
        journey_id,
        1,
        expected_revision=1,
        idempotency_key=f"{journey_id}-approve-01",
    )
    actor["value"] = "release-manager"
    active = store.activate_journey(
        tenant,
        journey_id,
        1,
        expected_revision=approved.revision,
        idempotency_key=f"{journey_id}-activate-1",
    )
    assert active.state == "active"


def test_exact_default_off_gate_and_honest_product_boundaries(tmp_path: Path) -> None:
    assert profile_data_enabled(ENABLED)
    assert not profile_data_enabled({})
    assert not profile_data_enabled(
        {"consent_preferences": {"enable": 1, "profile_data": {"enable": True}}}
    )
    assert not profile_data_enabled(
        {"consent_preferences": {"enable": True, "profile_data": {"enable": "true"}}}
    )
    with pytest.raises(ConsentProfileDataConfigError):
        ConsentProfileDataStore(
            tmp_path / "disabled.sqlite3",
            config_gate=lambda: require_profile_data_enabled(
                {"consent_preferences": {"enable": True}}
            ),
        )
    boundaries = product_boundaries()
    assert boundaries["provider_neutral"] is True
    assert boundaries["network_io"] is False
    assert boundaries["live_traffic_operated"] is False
    assert boundaries["accessibility_acceptance_verified"] is False
    assert boundaries["customer_acceptance_verified"] is False


def test_unicode_tenant_canonicalization_isolation_and_strict_ids(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, _, _ = environment
    decomposed = "Te\u0301nant-東京"
    canonical = unicodedata.normalize("NFC", decomposed)
    _publish_catalog(store, actor, tenant=decomposed)
    catalog = store.get_catalog_version(canonical, "profile-catalog", 1)
    assert catalog.tenant_id == canonical
    with pytest.raises(ConsentProfileDataNotFound):
        store.get_catalog_version("tenant-other", "profile-catalog", 1)
    with pytest.raises(ConsentProfileDataValidationError):
        store.get_catalog_version(canonical, "../profile-catalog", 1)


def test_public_authority_exact_type_and_all_binding_fields_are_enforced(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, _, _ = environment
    _publish_catalog(store, actor)
    authority = _authority()

    with pytest.raises(ConsentProfileDataPermissionDenied):
        store.set_public_value(  # type: ignore[arg-type]
            dataclasses.asdict(authority),
            "required-bool",
            True,
            expected_revision=0,
            idempotency_key="mapping-forgery-1",
        )

    class ForgedAuthority(PublicProfileAuthority):
        pass

    forged = ForgedAuthority(**dataclasses.asdict(authority))
    with pytest.raises(ConsentProfileDataPermissionDenied):
        store.set_public_value(
            forged,
            "required-bool",
            True,
            expected_revision=0,
            idempotency_key="subclass-forgery",
        )

    for changed in (
        dataclasses.replace(authority, property_id="property-other"),
        dataclasses.replace(authority, configuration_sha256=_digest("configuration-other")),
        dataclasses.replace(authority, catalog_id="other-catalog"),
    ):
        with pytest.raises((ConsentProfileDataNotFound, ConsentProfileDataPermissionDenied)):
            store.set_public_value(
                changed,
                "required-bool",
                True,
                expected_revision=0,
                idempotency_key="binding-forgery-" + changed.property_id,
            )

    stored = store.set_public_value(
        authority,
        "required-bool",
        True,
        expected_revision=0,
        idempotency_key="binding-valid-001",
    )
    assert stored.binding_sha256
    changed_capability = dataclasses.replace(
        authority,
        profile_capability_sha256=_digest("rotated-or-forged-capability"),
    )
    with pytest.raises(ConsentProfileDataPermissionDenied):
        store.get_current_value(changed_capability, "required-bool")
    with pytest.raises(ConsentProfileDataPermissionDenied):
        store.set_public_value(
            changed_capability,
            "required-bool",
            False,
            expected_revision=1,
            idempotency_key="capability-forgery-1",
        )
    assert "tenant_id" not in inspect.signature(store.set_public_value).parameters
    assert "actor" not in inspect.signature(store.set_public_value).parameters


def test_only_closed_published_values_and_no_raw_secrets_or_pii_are_stored(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, _, path = environment
    _publish_catalog(store, actor)
    authority = _authority(capability_label="raw-profile-capability-secret")
    invalid = (
        ("required-bool", "true"),
        ("locale", "unknown-option"),
        ("channels", ["email", "email"]),
        ("channels", {"email": True}),
        ("locale", "person@example.test"),
    )
    for index, (preference, value) in enumerate(invalid):
        with pytest.raises(ConsentProfileDataValidationError):
            store.set_public_value(
                authority,
                preference,
                value,
                expected_revision=0,
                idempotency_key=f"invalid-value-{index}",
            )
    selected = store.set_public_value(
        authority,
        "channels",
        ["sms", "email"],
        expected_revision=0,
        idempotency_key="valid-multiselect",
    )
    assert selected.value == ["email", "sms"]
    database = b"".join(
        candidate.read_bytes()
        for candidate in (path, path.with_name(path.name + "-wal"))
        if candidate.exists()
    )
    assert b"raw-profile-capability-secret" not in database
    assert _digest("raw-profile-capability-secret").encode() not in database
    assert b"person@example.test" not in database
    assert selected.binding_sha256 == _digest_for_json(dataclasses.asdict(authority))


def test_receipts_snapshot_history_export_cas_idempotency_unset_and_revoke(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, _, _ = environment
    _publish_catalog(store, actor)
    authority = _authority()
    first = store.set_public_value(
        authority,
        "required-bool",
        True,
        expected_revision=0,
        idempotency_key="value-set-first",
    )
    replay = store.set_public_value(
        authority,
        "required-bool",
        True,
        expected_revision=0,
        idempotency_key="value-set-first",
    )
    assert replay == first
    with pytest.raises(ConsentProfileDataConflict):
        store.set_public_value(
            authority,
            "required-bool",
            False,
            expected_revision=1,
            idempotency_key="value-set-first",
        )
    with pytest.raises(ConsentProfileDataConflict):
        store.set_public_value(
            authority,
            "required-bool",
            False,
            expected_revision=0,
            idempotency_key="value-stale-cas",
        )
    second = store.set_public_value(
        authority,
        "required-bool",
        False,
        expected_revision=1,
        idempotency_key="value-set-second",
    )
    unset = store.unset_public_value(
        authority,
        "required-bool",
        expected_revision=second.revision,
        idempotency_key="value-unset-001",
    )
    assert unset.status == "unset"
    reset = store.set_public_value(
        authority,
        "required-bool",
        True,
        expected_revision=unset.revision,
        idempotency_key="value-reset-001",
    )
    revoked = store.revoke_public_value(
        authority,
        "required-bool",
        expected_revision=reset.revision,
        idempotency_key="value-revoke-01",
    )
    assert revoked.status == "revoked"
    assert store.get_current_value(authority, "required-bool") == revoked
    history = store.value_history(authority, "required-bool")
    assert [item.action for item in history] == [
        "set",
        "set",
        "unset",
        "set",
        "revoked",
    ]
    assert [item.sequence for item in history] == list(range(1, 6))
    assert history[0].previous_receipt_sha256 == "0" * 64
    assert history[1].previous_receipt_sha256 == history[0].integrity_sha256
    view = store.consumer_view(authority)
    assert view.active_values == {}
    assert view.current_records == (revoked,)
    exported = store.export_profile(authority)
    assert exported.schema == "lightwork.consent-profile-data-export.v1"
    assert exported.body["profile_id"] == authority.profile_id
    assert len(exported.body["history"]) == 5  # type: ignore[arg-type]
    assert exported.export_sha256 == _digest_for_json(exported.body)


def _digest_for_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def test_expiry_retention_prefix_checkpoint_and_final_purge_integrity(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, clock, path = environment
    _publish_catalog(store, actor)
    authority = _authority()
    store.set_public_value(
        authority,
        "required-bool",
        True,
        expected_revision=0,
        idempotency_key="expiry-value-one",
    )
    clock.advance(121)
    assert "required-bool" not in store.consumer_view(authority).active_values
    store.set_public_value(
        authority,
        "required-bool",
        False,
        expected_revision=1,
        idempotency_key="expiry-value-two",
    )
    first_cutoff = clock.value - 121 + DAY + 1
    actor["value"] = "retention-operator"
    prefix = store.purge_expired(
        "tenant-a",
        before=first_cutoff,
        idempotency_key="purge-prefix-001",
    )
    assert prefix["value_receipts"] == 1
    assert len(store.value_history(authority)) == 1
    store.verify_integrity("tenant-a")
    clock.value = first_cutoff + DAY + 1
    final = store.purge_expired(
        "tenant-a",
        before=clock.value,
        idempotency_key="purge-final-0001",
    )
    assert final["profile_values"] == 1
    assert final["value_receipts"] == 1
    store.verify_integrity("tenant-a")
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM profile_values").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM value_receipts").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM receipt_checkpoints").fetchone()[0] == 0


def test_catalog_and_journey_require_four_eyes_and_conditions_are_closed(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, _, _ = environment
    actor["value"] = "same-human"
    store.create_catalog_version(
        "tenant-a",
        "profile-catalog",
        property_id="property-web",
        publication_sha256=_digest("publication"),
        bundle_sha256=_digest("bundle"),
        configuration_sha256=_digest("configuration"),
        policy_id="profile-policy",
        policy_version=3,
        policy_sha256=_digest("policy"),
        definitions=_definitions(),
        retention_seconds=DAY,
        expected_latest_version=0,
        idempotency_key="four-eyes-catalog",
    )
    with pytest.raises(ConsentProfileDataPermissionDenied):
        store.approve_catalog_version(
            "tenant-a",
            "profile-catalog",
            1,
            expected_revision=1,
            idempotency_key="self-approve-cat",
        )
    actor["value"] = "catalog-reviewer"
    store.approve_catalog_version(
        "tenant-a",
        "profile-catalog",
        1,
        expected_revision=1,
        idempotency_key="review-approve-cat",
    )
    actor["value"] = "journey-human"
    store.create_journey_version(
        "tenant-a",
        "progressive-profile",
        catalog_id="profile-catalog",
        catalog_version=1,
        stages=_stages(),
        max_prompts=2,
        cooldown_seconds=60,
        frequency_cap=3,
        frequency_window_seconds=600,
        retention_seconds=DAY,
        expected_latest_version=0,
        idempotency_key="four-eyes-journey",
    )
    with pytest.raises(ConsentProfileDataPermissionDenied):
        store.approve_journey_version(
            "tenant-a",
            "progressive-profile",
            1,
            expected_revision=1,
            idempotency_key="self-approve-jour",
        )
    malicious = _stages()
    malicious[1]["condition"] = {
        "source": "purpose",
        "key": "analytics",
        "operator": "equals",
        "value": "grant",
        "expression": "__import__('os').system('whoami')",
    }
    with pytest.raises(ConsentProfileDataValidationError, match="closed"):
        store.create_journey_version(
            "tenant-a",
            "raw-code-journey",
            catalog_id="profile-catalog",
            catalog_version=1,
            stages=malicious,
            max_prompts=2,
            cooldown_seconds=60,
            frequency_cap=3,
            frequency_window_seconds=600,
            retention_seconds=DAY,
            expected_latest_version=0,
            idempotency_key="reject-raw-code-1",
        )


def test_prompt_assignment_is_deterministic_required_first_and_safely_targeted(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, _, _ = environment
    _publish_catalog(store, actor)
    _activate_journey(store, actor)
    authority = _authority()
    with pytest.raises(ConsentProfileDataValidationError):
        PromptContext(
            ("analytics", "grant"),
        )  # type: ignore[arg-type]
    context = PromptContext((("analytics", "grant"),))
    assignment = store.assign_prompt(
        authority,
        context,
        "progressive-profile",
        idempotency_key="assign-profile-001",
    )
    replay = store.assign_prompt(
        authority,
        context,
        "progressive-profile",
        idempotency_key="assign-profile-001",
    )
    assert replay == assignment
    assert assignment.eligible
    assert assignment.reason == "assigned"
    assert [item.preference_id for item in assignment.prompts] == [
        "required-bool",
        "channels",
    ]
    assert assignment.prompts[0].required is True
    assert assignment.prompts[0].label_ref == "label.required-bool"
    assert assignment.prompts[0].options == ()
    assert assignment.prompts[1].options == (
        {"value_id": "email", "label_ref": "option.channel.email"},
        {"value_id": "sms", "label_ref": "option.channel.sms"},
    )
    assert all(not hasattr(item, "value") for item in assignment.prompts)
    with pytest.raises(ConsentProfileDataConflict):
        store.assign_prompt(
            authority,
            PromptContext((("analytics", "deny"),)),
            "progressive-profile",
            idempotency_key="assign-profile-001",
        )


def test_prompt_cooldown_frequency_cap_completion_and_privacy_bounded_events(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, clock, _ = environment
    _publish_catalog(store, actor)
    _activate_journey(
        store,
        actor,
        max_prompts=1,
        cooldown_seconds=60,
        frequency_cap=1,
        frequency_window_seconds=120,
    )
    authority = _authority()
    context = PromptContext((("analytics", "deny"),))
    assignment = store.assign_prompt(
        authority,
        context,
        "progressive-profile",
        idempotency_key="assign-cap-start",
    )
    assert [item.preference_id for item in assignment.prompts] == ["required-bool"]
    with pytest.raises(ConsentProfileDataConflict, match="requires every prompted"):
        store.record_prompt_interaction(
            authority,
            assignment,
            "completed",
            idempotency_key="complete-too-soon",
        )
    dismissed = store.record_prompt_interaction(
        authority,
        assignment,
        "dismissed",
        idempotency_key="dismiss-prompt-01",
    )
    assert dismissed["event_type"] == "dismissed"
    immediate = store.assign_prompt(
        authority,
        context,
        "progressive-profile",
        idempotency_key="assign-cap-cooldown",
    )
    # Frequency cap is stricter and fail-closes even while cooldown also applies.
    assert not immediate.eligible and immediate.reason == "frequency_cap"
    clock.advance(61)
    capped = store.assign_prompt(
        authority,
        context,
        "progressive-profile",
        idempotency_key="assign-cap-window",
    )
    assert not capped.eligible and capped.reason == "frequency_cap"
    clock.advance(60)
    available = store.assign_prompt(
        authority,
        context,
        "progressive-profile",
        idempotency_key="assign-cap-again",
    )
    assert available.eligible
    value = store.set_public_value(
        authority,
        "required-bool",
        True,
        expected_revision=0,
        idempotency_key="value-for-complete",
    )
    assert value.status == "active"
    completed = store.record_prompt_interaction(
        authority,
        available,
        "completed",
        idempotency_key="complete-after-value",
    )
    assert completed["event_type"] == "completed"
    assert "value" not in completed
    assert "purpose_signals" not in completed
    assert (
        store.record_prompt_interaction(
            authority,
            available,
            "completed",
            idempotency_key="complete-after-value",
        )
        == completed
    )
    with pytest.raises(ConsentProfileDataConflict, match="terminal interaction"):
        store.record_prompt_interaction(
            authority,
            available,
            "dismissed",
            idempotency_key="duplicate-terminal",
        )
    store.verify_integrity("tenant-a")


def test_prompt_cooldown_blocks_reprompt_until_elapsed(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, clock, _ = environment
    _publish_catalog(store, actor)
    _activate_journey(
        store,
        actor,
        max_prompts=3,
        cooldown_seconds=60,
        frequency_cap=10,
        frequency_window_seconds=600,
    )
    authority = _authority()
    context = PromptContext((("analytics", "grant"),))
    first = store.assign_prompt(
        authority,
        context,
        "progressive-profile",
        idempotency_key="cooldown-first-001",
    )
    assert len(first.prompts) == 3
    blocked = store.assign_prompt(
        authority,
        context,
        "progressive-profile",
        idempotency_key="cooldown-blocked-1",
    )
    assert not blocked.eligible and blocked.reason == "cooldown"
    clock.advance(61)
    elapsed = store.assign_prompt(
        authority,
        context,
        "progressive-profile",
        idempotency_key="cooldown-elapsed-1",
    )
    assert elapsed.eligible and elapsed.reason == "assigned"


def test_completed_values_are_not_reprompted_and_preference_conditions_use_only_stored_values(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, clock, _ = environment
    _publish_catalog(store, actor)
    stages = [
        {
            "stage_id": "locale-first",
            "priority": 1,
            "prompt_label_ref": "prompt.locale",
            "preference_ids": ["locale"],
            "condition": None,
        },
        {
            "stage_id": "stored-value-target",
            "priority": 2,
            "prompt_label_ref": "prompt.channels",
            "preference_ids": ["channels"],
            "condition": {
                "source": "preference",
                "key": "locale",
                "operator": "equals",
                "value": "us",
            },
        },
    ]
    actor["value"] = "journey-author"
    store.create_journey_version(
        "tenant-a",
        "stored-target",
        catalog_id="profile-catalog",
        catalog_version=1,
        stages=stages,
        max_prompts=2,
        cooldown_seconds=60,
        frequency_cap=10,
        frequency_window_seconds=600,
        retention_seconds=DAY,
        expected_latest_version=0,
        idempotency_key="stored-target-create",
    )
    actor["value"] = "journey-reviewer"
    store.approve_journey_version(
        "tenant-a",
        "stored-target",
        1,
        expected_revision=1,
        idempotency_key="stored-target-review",
    )
    actor["value"] = "release-manager"
    store.activate_journey(
        "tenant-a",
        "stored-target",
        1,
        expected_revision=2,
        idempotency_key="stored-target-active",
    )
    authority = _authority()
    first = store.assign_prompt(
        authority,
        PromptContext(),
        "stored-target",
        idempotency_key="stored-target-first",
    )
    assert [item.preference_id for item in first.prompts] == ["locale"]
    store.set_public_value(
        authority,
        "locale",
        "us",
        expected_revision=0,
        idempotency_key="set-locale-us-01",
    )
    clock.advance(61)
    second = store.assign_prompt(
        authority,
        PromptContext(),
        "stored-target",
        idempotency_key="stored-target-second",
    )
    assert [item.preference_id for item in second.prompts] == ["channels"]


def test_pause_kill_and_rollback_all_fail_safe_to_no_prompt(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, _, _ = environment
    _publish_catalog(store, actor)
    _activate_journey(store, actor)
    authority = _authority()
    actor["value"] = "release-manager"
    paused = store.pause_journey(
        "tenant-a",
        "progressive-profile",
        1,
        expected_revision=3,
        idempotency_key="journey-pause-001",
    )
    no_prompt = store.assign_prompt(
        authority,
        PromptContext(),
        "progressive-profile",
        idempotency_key="paused-no-prompt",
    )
    assert paused.state == "paused"
    assert not no_prompt.eligible and no_prompt.reason == "not_active"
    active = store.activate_journey(
        "tenant-a",
        "progressive-profile",
        1,
        expected_revision=paused.revision,
        idempotency_key="journey-reactivate",
    )
    rolled_back = store.rollback_journey(
        "tenant-a",
        "progressive-profile",
        1,
        expected_revision=active.revision,
        idempotency_key="journey-rollback-1",
    )
    assert rolled_back.state == "rolled_back"
    assert (
        store.assign_prompt(
            authority,
            PromptContext(),
            "progressive-profile",
            idempotency_key="rollback-no-prompt",
        ).reason
        == "not_active"
    )

    _activate_journey(store, actor, journey_id="killable-journey")
    killed = store.kill_journey(
        "tenant-a",
        "killable-journey",
        1,
        expected_revision=3,
        idempotency_key="journey-kill-0001",
    )
    assert killed.state == "killed"
    assert (
        store.assign_prompt(
            authority,
            PromptContext(),
            "killable-journey",
            idempotency_key="killed-no-prompt",
        ).reason
        == "not_active"
    )


def test_concurrent_value_cas_allows_exactly_one_winner(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, _, _ = environment
    _publish_catalog(store, actor)
    authority = _authority()

    def write(value: bool, key: str) -> str:
        try:
            store.set_public_value(
                authority,
                "required-bool",
                value,
                expected_revision=0,
                idempotency_key=key,
            )
            return "stored"
        except ConsentProfileDataConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda item: write(*item),
                ((True, "concurrent-value-a"), (False, "concurrent-value-b")),
            )
        )
    assert sorted(results) == ["conflict", "stored"]
    assert store.get_current_value(authority, "required-bool").revision == 1
    store.verify_integrity("tenant-a")


def test_integrity_is_tenant_scoped_and_tenant_b_tamper_does_not_affect_tenant_a(
    environment: tuple[ConsentProfileDataStore, dict[str, str], Clock, Path],
) -> None:
    store, actor, _, path = environment
    _publish_catalog(store, actor, tenant="tenant-a")
    _publish_catalog(store, actor, tenant="tenant-b")
    authority_a = _authority(tenant="tenant-a", profile="profile-a")
    authority_b = _authority(tenant="tenant-b", profile="profile-b")
    store.set_public_value(
        authority_a,
        "required-bool",
        True,
        expected_revision=0,
        idempotency_key="tenant-a-value-01",
    )
    store.set_public_value(
        authority_b,
        "required-bool",
        False,
        expected_revision=0,
        idempotency_key="tenant-b-value-01",
    )
    before = store.verify_integrity("tenant-a")
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE profile_values SET profile_id=? WHERE tenant_id=?",
            ("relocated-profile", "tenant-b"),
        )
        connection.commit()
    after = store.verify_integrity("tenant-a")
    assert after.verified_records == before.verified_records
    assert after.audit_events == before.audit_events
    with pytest.raises(ConsentProfileDataIntegrityError):
        store.verify_integrity("tenant-b")
