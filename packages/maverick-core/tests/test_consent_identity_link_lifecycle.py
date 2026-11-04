from __future__ import annotations

import hashlib
import sqlite3

import pytest
from maverick.consent_preferences import (
    ConsentConflict,
    ConsentNotFound,
    ConsentPreferencesError,
    ConsentPreferenceStore,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def test_unlink_account_transition_history_and_integrity_are_exact(tmp_path) -> None:
    now = 1_800_000_000.0
    store = ConsentPreferenceStore(tmp_path / "consent.sqlite3", clock=lambda: now)
    for profile_id, kind in (
        ("known-a", "known"),
        ("known-b", "known"),
        ("anonymous", "anonymous"),
    ):
        store.create_profile(
            "tenant-a",
            profile_id,
            kind,
            digest(f"subject:{profile_id}"),
            f"create-{profile_id}",
        )
    first = store.link_profiles(
        "tenant-a",
        "known-a",
        "anonymous",
        expected_known_revision=0,
        expected_anonymous_revision=0,
        idempotency_key="initial-link",
    )
    assert first["transition_type"] == "linked"
    assert first["receipt_histories_merged"] is False

    unlinked = store.unlink_profile(
        "tenant-a",
        "anonymous",
        expected_anonymous_revision=1,
        expected_known_revision=1,
        expected_link_revision=1,
        idempotency_key="unlink-1",
        identity_evidence_sha256=digest("verified-identity"),
        audit_evidence_sha256=digest("independent-audit"),
        actor_sha256=digest("consumer-device"),
        reason_sha256=digest("account-change"),
        retention_until=now + 86_400,
    )
    assert unlinked["link_revision"] == 2
    assert store.unlink_profile(
        "tenant-a",
        "anonymous",
        expected_anonymous_revision=1,
        expected_known_revision=1,
        expected_link_revision=1,
        idempotency_key="unlink-1",
        identity_evidence_sha256=digest("verified-identity"),
        audit_evidence_sha256=digest("independent-audit"),
        actor_sha256=digest("consumer-device"),
        reason_sha256=digest("account-change"),
        retention_until=now + 86_400,
    ) == unlinked
    authority = store.get_profile_authority("tenant-a", "anonymous")
    assert authority["link_status"] == "unlinked"
    assert authority["linked_known_profile_id"] is None
    assert authority["last_known_profile_id"] == "known-a"
    with pytest.raises(ConsentConflict, match="fresh verified identity"):
        store.link_profiles(
            "tenant-a",
            "known-b",
            "anonymous",
            expected_known_revision=0,
            expected_anonymous_revision=2,
            idempotency_key="unsafe-manual-relink",
        )

    transitioned = store.link_profiles(
        "tenant-a",
        "known-b",
        "anonymous",
        expected_known_revision=0,
        expected_anonymous_revision=2,
        expected_link_revision=2,
        idempotency_key="verified-account-transition",
        identity_evidence_sha256=digest("fresh-verified-identity"),
        audit_evidence_sha256=digest("fresh-independent-audit"),
        actor_sha256=digest("consumer-device-2"),
        retention_until=now + 172_800,
    )
    assert transitioned["transition_type"] == "account_transition"
    assert transitioned["receipt_histories_merged"] is False
    history = store.get_profile_link_history("tenant-a", "anonymous")
    assert [event["action"] for event in reversed(history["events"])] == [
        "linked",
        "unlinked",
        "account_transition",
    ]
    assert store.verify_profile_link_integrity("tenant-a") == {
        "authorities_verified": 1,
        "events_verified": 3,
        "truncated": False,
    }
    with pytest.raises(ConsentNotFound):
        store.get_profile_link_history("tenant-b", "anonymous")

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE consent_profile_link_current SET revision=99 "
            "WHERE tenant='tenant-a' AND anonymous_profile_id='anonymous'"
        )
    with pytest.raises(ConsentPreferencesError, match="integrity"):
        store.get_profile_authority("tenant-a", "anonymous")
